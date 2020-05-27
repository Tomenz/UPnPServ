// SockTest.cpp : Definiert den Einstiegspunkt f¸r die Konsolenanwendung.
//

#include "socketlib/SocketLib.h"
#include "tinyxml2/tinyxml2.h"

#include <iostream>
#include <sstream>
#include <fstream>
#include <map>
#include <list>
#include <codecvt>
#include <regex>
#include <iomanip>
#include <random>
#include <condition_variable>
#include <atomic>

#if defined(_WIN32) || defined(_WIN64)
#include <Ws2tcpip.h>
#include <conio.h>
#include <io.h>
#include <fcntl.h>
#endif

#ifdef _DEBUG
#ifdef _WIN64
#pragma comment(lib, "x64/Debug/socketlib64d")
#elif _WIN32
#pragma comment(lib, "Debug/socketlib32d")
#endif
#else
#ifdef _WIN64
#pragma comment(lib, "x64/Release/socketlib64")
#elif _WIN32
#pragma comment(lib, "Release/socketlib32")
#endif
#endif

#pragma comment(lib, "libcrypto.lib")
#pragma comment(lib, "libssl.lib")

using namespace std::placeholders;
using namespace tinyxml2;

// http://www.upnp-hacks.org/links.html

#define HTTPServSocket(UPnParameter) get<3>(UPnParameter)
#define HTTPServPort(UPnParameter) get<4>(UPnParameter)

static const string strMSearch("M-SEARCH * HTTP/1.1\r\n" \
                               "HOST: %{HOSTADDR}\r\n" \
                               "ST: %{SSDP}\r\n" \
                               "MAN: \"ssdp:discover\"\r\n" \
                               "MX: 3\r\n" \
                               /*"USER-AGENT: Microsoft-Windows-NT/5.1 UPnP/1.1 socks-utility/1.0\r\n" \*/
                               "\r\n");
static const string strNotify("NOTIFY * HTTP/1.1\r\n" \
                              "HOST: %{HOSTADDR}\r\n" \
                              "CACHE-CONTROL: max-age=1800\r\n" \
                              "LOCATION: http://%{ADDRESS}:%{PORT}/rootdesc.xml\r\n" \
                              "SERVER: Microsoft-Windows-NT/5.1 UPnP/1.0 socks-utility/1.0\r\n" \
                              "NT: upnp:rootdevice\r\n" \
                              "NTS: ssdp:%{SSDP}\r\n" \
                              "USN: uuid:Upnp-BasicDevice-1_0-71.9999::upnp:rootdevice\r\n" \
                              "\r\n");
static const string strRespons("HTTP/1.1 200 OK\r\n" \
                              "CACHE-CONTROL: max-age=1800\r\n" \
                              "DATE: %{DATE}\r\n" \
                              "EXT:\r\n" \
                              "LOCATION: http://%{ADDRESS}:%{PORT}/rootdesc.xml\r\n" \
                              "SERVER: Microsoft-Windows-NT/5.1 UPnP/1.0 socks-utility/1.0\r\n" \
                              "ST: upnp:rootdevice\r\n" \
                              "USN: uuid:Upnp-BasicDevice-1_0-71.9999::upnp:rootdevice\r\n" \
                              "\r\n");

static mutex mxcout;

class RandIntervalTimer
{
public:

    RandIntervalTimer()
    {
    }

    virtual ~RandIntervalTimer()
    {
        Stop();
    }

    template<typename fn, typename... Args>
    void Start(fn f, Args... args)
    {
        m_thWaitThread = thread([&](fn&& f1, Args&&... args1)
        {
            atomic_init(&m_bStop, false);
            function<typename result_of<fn(Args...)>::type()> task(bind(forward<fn>(f1), forward<Args>(args1)...));
            uniform_int_distribution<int> dist(10000, 100000);

            unique_lock<mutex> lock(mut);

            do
            {
                random_device rd;
                mt19937 mt(rd());
                int tMilliSeconds = dist(mt);

                // { const auto tNow = chrono::system_clock::to_time_t(chrono::system_clock::now());  wstringstream ss; ss << put_time(::localtime(&tNow)), L"%a, %d %b %Y %H:%M:%S") << L" - Timer starts mit: " << tMilliSeconds << L" Millisekunden\r\n";  OutputDebugString(ss.str().c_str()); }
                m_cv.wait_for(lock, chrono::milliseconds(tMilliSeconds));
                if (m_bStop == false)
                {
                    task();
                    // OutputDebugString(L"Timer Callback aufgerufen\r\n");
                }
            } while (m_bStop == false);
        }, forward<fn>(f), forward<Args>(args)...);
    }

    void Stop()
    {
        mut.lock();
        m_bStop = true;
        m_cv.notify_all();
        mut.unlock();

        if (m_thWaitThread.joinable() == true)
            m_thWaitThread.join();
    }

private:
    thread m_thWaitThread;
    atomic<bool> m_bStop;
    mutex mut;
    condition_variable m_cv;
};

class UpnPServer
{
    typedef tuple<int, string, uint32_t, TcpServer*, uint16_t, UdpSocket*, uint16_t> UPnParameter;  // AddrFamiely, IP-Addr, Interface-Index, TCP-Server, TCP-Server Port, UDP-Socket, UDP-Socket Port

    typedef struct
    {
        string strSCPDURL;
        string strXml;
        tinyxml2::XMLDocument docXml;
    }SERVICEINFO;
    typedef struct
    {
        string strXml;
        tinyxml2::XMLDocument docXml;
        list<SERVICEINFO> vServices;
    }DEVICEINFO;

public:
	UpnPServer()
    {
    }

    ~UpnPServer()
    {
    }

    void Start()
    {
        BaseSocket::EnumIpAddresses([&](int adrFamily, const string& strIpAddr, int nInterfaceIndex, void*) -> int
        {
            lock_guard<mutex> lock(mxcout);
            cout << strIpAddr << endl; cout.flush();//OutputDebugStringA(strIpAddr.c_str()); OutputDebugStringA("\r\n");

            pair<map<UdpSocket*, UPnParameter>::iterator, bool>paRet = m_maSockets.emplace(new UdpSocket(), make_tuple(adrFamily, strIpAddr, nInterfaceIndex, new TcpServer(), 0, new UdpSocket(), 0));
            if (paRet.second == true)
            {
                paRet.first->first->BindErrorFunction(static_cast<function<void(BaseSocket*)>>(bind(&UpnPServer::OnSocketError, this, _1)));
                paRet.first->first->BindCloseFunction(static_cast<function<void(BaseSocket*)>>(bind(&UpnPServer::OnSocketCloseing, this, _1)));
                paRet.first->first->BindFuncBytesReceived(static_cast<function<void(UdpSocket*)>>(bind(&UpnPServer::UpnPDatenEmpfangen, this, _1)));

                HTTPServSocket(paRet.first->second)->BindErrorFunction(static_cast<function<void(BaseSocket*)>>(bind(&UpnPServer::OnSocketError, this, _1)));
                HTTPServSocket(paRet.first->second)->BindNewConnection(function<void(const vector<TcpSocket*>&)>(bind(&UpnPServer::OnNewConnection, this, _1)));

                get<5>(paRet.first->second)->BindErrorFunction(static_cast<function<void(BaseSocket*)>>(bind(&UpnPServer::OnSocketError, this, _1)));
                get<5>(paRet.first->second)->BindCloseFunction(static_cast<function<void(BaseSocket*)>>(bind(&UpnPServer::OnSocketCloseing, this, _1)));
                get<5>(paRet.first->second)->BindFuncBytesReceived(static_cast<function<void(UdpSocket*)>>(bind(&UpnPServer::UpdDatenEmpfangen, this, _1)));

                if (get<0>(paRet.first->second) == AF_INET)
                {
                    // Start the Http Server on that address
                    HTTPServSocket(paRet.first->second)->Start(strIpAddr.c_str(), 0);
                    HTTPServPort(paRet.first->second) = HTTPServSocket(paRet.first->second)->GetServerPort();
                    cout << "HTTP Server on: " << strIpAddr << ":" << HTTPServPort(paRet.first->second) << endl; cout.flush();

                    if (paRet.first->first->Create(strIpAddr.c_str(), 1900, "0.0.0.0") == false)
                        cout << "Error creating Socket: " << strIpAddr << endl;
                    if (paRet.first->first->AddToMulticastGroup("239.255.255.250", strIpAddr.c_str(), nInterfaceIndex) == false)
                        cout << "Error joining Multicastgroup: " << strIpAddr << endl;

                    get<5>(paRet.first->second)->Create(strIpAddr.c_str(), 0);
                    get<6>(paRet.first->second) = get<5>(paRet.first->second)->GetSocketPort();

                    string strSend = regex_replace(strMSearch, regex("\\%\\{HOSTADDR\\}"), "239.255.255.250:1900");
                    strSend = regex_replace(strSend, regex("\\%\\{SSDP\\}"), "ssdp:all");
                    get<5>(paRet.first->second)->Write(strSend.c_str(), strSend.size(), "239.255.255.250:1900");

                    SendNotifyAdvertise(paRet.first->second, "239.255.255.250:1900", "alive");
                }
                else if (get<0>(paRet.first->second) == AF_INET6)
                {
                    // Start the Http Server on that address
                    HTTPServSocket(paRet.first->second)->Start(strIpAddr.c_str(), 0);
                    HTTPServPort(paRet.first->second) = HTTPServSocket(paRet.first->second)->GetServerPort();
                    cout << "HTTP Server on: " << strIpAddr << ":" << HTTPServPort(paRet.first->second) << endl; cout.flush();

                    if (paRet.first->first->Create(strIpAddr.c_str(), 1900, "::") == false)
                        cout << "Error creating Socket: " << strIpAddr << endl;
                    if (paRet.first->first->AddToMulticastGroup("FF02::C", strIpAddr.c_str(), nInterfaceIndex) == false)
                        cout << "Error joining Multicastgroup: " << strIpAddr << endl;

                    get<5>(paRet.first->second)->Create(strIpAddr.c_str(), 0);
                    get<6>(paRet.first->second) = get<5>(paRet.first->second)->GetSocketPort();

                    string strSend = regex_replace(strMSearch, regex("\\%\\{HOSTADDR\\}"), "[FF02::C]:1900");
                    strSend = regex_replace(strSend, regex("\\%\\{SSDP\\}"), "ssdp:all");
                    get<5>(paRet.first->second)->Write(strSend.c_str(), strSend.size(), "[FF02::C]:1900");

                    SendNotifyAdvertise(paRet.first->second, "[FF02::C]:1900", "alive");
                }
            }

            return 0;
        }, 0);

        m_timMSearch.Start([&]()
        {
            static bool bToggle = false;
            for (auto& itSocket : m_maSockets)
            {
                bToggle = !bToggle;
                string strSend;
                if (get<0>(itSocket.second) == AF_INET)
                {
                    strSend = regex_replace(strMSearch, regex("\\%\\{HOSTADDR\\}"), "239.255.255.250:1900");
                    strSend = regex_replace(strSend, regex("\\%\\{SSDP\\}"), bToggle == true ? "upnp:rootdevice" : "ssdp:all");
                    get<5>(itSocket.second)->Write(strSend.c_str(), strSend.size(), "239.255.255.250:1900");
                }
                else
                {
                    strSend = regex_replace(strMSearch, regex("\\%\\{HOSTADDR\\}"), "[FF02::C]:1900");
                    strSend = regex_replace(strSend, regex("\\%\\{SSDP\\}"), bToggle == true ? "upnp:rootdevice" : "ssdp:all");
                    get<5>(itSocket.second)->Write(strSend.c_str(), strSend.size(), "[FF02::C]:1900");
                }
            }
        });

        m_timNotify.Start([&]()
        {
            for (auto& itSocket : m_maSockets)
            {
                if (get<0>(itSocket.second) == AF_INET)
                    SendNotifyAdvertise(itSocket.second, "239.255.255.250:1900", "alive");
                else
                    SendNotifyAdvertise(itSocket.second, "[FF02::C]:1900", "alive");
            }
        });
    }

    void Stop()
    {
        m_timMSearch.Stop();
        m_timNotify.Stop();

        for (auto& itSocket : m_maSockets)
        {
            if (get<0>(itSocket.second) == AF_INET)
                SendNotifyAdvertise(itSocket.second, "239.255.255.250:1900", "byebye");
            else
                SendNotifyAdvertise(itSocket.second, "[FF02::C]:1900", "byebye");
        }

        this_thread::sleep_for(chrono::milliseconds(300));

        for (auto itItem : m_maSockets)
        {
            if (get<0>(itItem.second) == AF_INET)
            {
                if (itItem.first->RemoveFromMulticastGroup("239.255.255.250", get<1>(itItem.second).c_str(), get<2>(itItem.second)) == false)
                    cout << "Error leaving Multicastgroup: " << get<1>(itItem.second) << endl;
            }
            else if (get<0>(itItem.second) == AF_INET6)
            {
                if (itItem.first->RemoveFromMulticastGroup("FF02::C", get<1>(itItem.second).c_str(), get<2>(itItem.second)) == false)
                    cout << "Error leaving Multicastgroup: " << get<1>(itItem.second) << endl;
            }

            // UPnP, UDP Socket schlieﬂen
            itItem.first->Close();
            // HTTP, TCP Socket schlieﬂen
            get<3>(itItem.second)->Close();
            // UDP Socket schlieﬂen
            get<5>(itItem.second)->Close();
        }

        m_mtxConnections.lock();
        for (auto item : m_maServerConn)
            item.first->Close();
        m_mtxConnections.unlock();

        m_mtxClientConn.lock();
        for (auto item : m_maClientConn)
            item.first->Close();
        m_mtxClientConn.unlock();

        while (m_maSockets.size())
        {
            // UPnP, UDP Socket schlieﬂen
            delete m_maSockets.begin()->first;

            // HTTP, TCP Socket schlieﬂen
            delete get<3>(m_maSockets.begin()->second);

            // UDP Socket schlieﬂen
            delete get<5>(m_maSockets.begin()->second);

            m_maSockets.erase(m_maSockets.begin());
        }

        while (m_maServerConn.size() != 0)
            this_thread::sleep_for(chrono::milliseconds(100));

        while (m_maClientConn.size() != 0)
            this_thread::sleep_for(chrono::milliseconds(100));
    }

    void OnSocketError(BaseSocket* pBaseSocket)
    {
        m_mtxConnections.lock();
        auto itFound = m_maServerConn.find(reinterpret_cast<TcpSocket*>(pBaseSocket));
        m_mtxConnections.unlock();

        if (itFound != end(m_maServerConn))
        {
            OutputDebugString(wstring(wstring(L"Error beim Accept: ") + to_wstring(pBaseSocket->GetErrorNo()) + L"\r\n").c_str());
        }
        else
        {
            m_mtxClientConn.lock();
            auto itFound = m_maClientConn.find(reinterpret_cast<TcpSocket*>(pBaseSocket));
            m_mtxClientConn.unlock();

            if (itFound != end(m_maClientConn))
                OutputDebugString(wstring(wstring(L"Error in Verbindung zu: ") + wstring(get<1>(itFound->second).begin(), get<1>(itFound->second).end()) + L", mit ErrorNr: " + to_wstring(pBaseSocket->GetErrorNo()) + L"\r\n").c_str());
            else
                OutputDebugString(wstring(wstring(L"Socket Error: ") + to_wstring(pBaseSocket->GetErrorNo()) + L"\r\n").c_str());
        }

        pBaseSocket->Close();
    }

    void OnSocketCloseing(BaseSocket* pBaseSocket)
    {
        cout << "Socket closing" << endl;

        m_mtxConnections.lock();
        if (m_maServerConn.find(reinterpret_cast<TcpSocket*>(pBaseSocket)) != end(m_maServerConn))
            m_maServerConn.erase(reinterpret_cast<TcpSocket*>(pBaseSocket));
        m_mtxConnections.unlock();

        bool bTcpSocket = false;
        m_mtxClientConn.lock();
        if (m_maClientConn.find(reinterpret_cast<TcpSocket*>(pBaseSocket)) != end(m_maClientConn))
        {
            m_maClientConn.erase(reinterpret_cast<TcpSocket*>(pBaseSocket));
            bTcpSocket = true;
            //delete pBaseSocket;
        }
        m_mtxClientConn.unlock();

        if (bTcpSocket == true)
            pBaseSocket->SelfDestroy();
    }

    void UpnPDatenEmpfangen(UdpSocket* pUdpSocket)
    {
        uint32_t nAvalible = pUdpSocket->GetBytesAvailible();

        shared_ptr<char> spBuffer(new char[nAvalible + 1]);

        string strFrom;
        uint32_t nRead = pUdpSocket->Read(spBuffer.get(), nAvalible, strFrom);

        if (nRead > 0)
        {
            auto itSocket = m_maSockets.find(pUdpSocket);
            if (itSocket == end(m_maSockets))
                return; // should never happened

            size_t nPos = strFrom.rfind(":");
            if (nPos == string::npos)
                return; // If this happens, than something really got wrong, our strFrom should always have a port divided by columns

            uint16_t sPort = stoi(strFrom.substr(nPos + 1));
            strFrom.erase(nPos);
            if (nPos = strFrom.find("["), nPos != string::npos) strFrom.erase(nPos, 1);
            if (nPos = strFrom.rfind("]"), nPos != string::npos) strFrom.erase(nPos, 1);

            // is the message from our own socket ?
            if (strFrom == get<1>(itSocket->second) && sPort == get<6>(itSocket->second))
                return;

            // if more than 1 IP is assigned to a network interface, we still become a message from the other IP on that interface
            auto itFound = find_if(begin(m_maSockets), end(m_maSockets), [&](const auto& itSearch) { return get<1>(itSearch.second) == strFrom && get<6>(itSearch.second) == sPort ? true : false; });
            if (itFound != end(m_maSockets))
                return;
#ifdef _DEBUG
            stringstream ss;

            static const string strEndOfHeader("\r\n\r\n");
            auto szEnd = search(&spBuffer.get()[0], &spBuffer.get()[nRead], &strEndOfHeader[0], &strEndOfHeader[strEndOfHeader.size()]);
            if (szEnd == &spBuffer.get()[nRead])    // if not found, returns the pointer to the end of the buffer
                ss << "! - ";

            ss << (get<0>(itSocket->second) == AF_INET6 ? "[" : "") << strFrom << (get<0>(itSocket->second) == AF_INET6 ? "]:" : ":") << sPort << " an Interface: " << get<1>(itSocket->second) << endl;
            ss << string(spBuffer.get(), nRead) << endl;
            lock_guard<mutex> lock(mxcout);
            cout << ss.str(); cout.flush();
#endif
            map<string, string> HeaderList = ParseHttpHeader(string(spBuffer.get(), nRead));
            if (HeaderList.empty() == false)
            {
                auto itHeader = HeaderList.find(":method");
                if (itHeader != end(HeaderList) && itHeader->second.compare("M-SEARCH") == 0)
                {
                    auto itST = HeaderList.find("st");
                    if (itST != end(HeaderList) && (itST->second == "ssdp:all" || itST->second == "upnp:rootdevice"))
                    {
                        string strSend = regex_replace(strRespons, regex("\\%\\{ADDRESS\\}"), (get<0>(itSocket->second) == AF_INET6 ? "[" : "") + get<1>(itSocket->second) + (get<0>(itSocket->second) == AF_INET6 ? "]" : ""));
                        strSend = regex_replace(strSend, regex("\\%\\{PORT\\}"), to_string(HTTPServPort(itSocket->second)));
                        strSend = regex_replace(strSend, regex("\\%\\{DATE\\}"), GetGmtDateString());
                        get<5>(itSocket->second)->Write(&strSend[0], strSend.size(), (get<0>(itSocket->second) == AF_INET6 ? "[" : "") + strFrom + (get<0>(itSocket->second) == AF_INET6 ? "]:" : ":") + to_string(sPort));
                    }
                }
                else if (itHeader != end(HeaderList) && itHeader->second.compare("NOTIFY") == 0)
                {
                    auto itLocation = HeaderList.find("location");
                    auto itNts = HeaderList.find("nts");
                    if (itNts != end(HeaderList) && itLocation != end(HeaderList))
                    {
                        auto tpLocation = ParseLocationHeader(itLocation->second);

                        transform(begin(itNts->second), end(itNts->second), begin(itNts->second), ::tolower);
                        if (itNts->second == "ssdp:alive" || itNts->second == "ssdp:update")
                        {
                            if (get<1>(tpLocation).size() == 0) // no path supplied in the location url
                            {
                                OutputDebugString(wstring(L"Error: location header invalid: " + wstring(itLocation->second.begin(), itLocation->second.end()) + L"\r\n").c_str());
                                return;
                            }

                            bool bBereitsInListe = false;
                            m_mtxDevices.lock();
                            if (m_maDevices.find(get<0>(tpLocation)) != end(m_maDevices))
                                bBereitsInListe = true;
                            m_mtxDevices.unlock();

                            FetchHttp(true, get<0>(tpLocation), get<1>(tpLocation), get<2>(tpLocation));
                        }
                        else if (itNts->second == "ssdp:byebye")
                        {
                            OutputDebugString(wstring(L"Device von " + wstring(begin(get<0>(tpLocation)), end(get<0>(tpLocation))) + L" meldet sich ab\r\n").c_str());
                        }
                        else
                            OutputDebugString(L"Error: NTS Header in Notify with unknown verb\r\n");
                    }
                    else
                        OutputDebugString(L"Error: no NTS or Location Header in Notify message\r\n");
                }
                else
                    OutputDebugString(L"Error: unexpected method\r\n");
            }
            else
                OutputDebugString(L"Error: parsing http header\r\n");
        }
    }

    // In this function we receive the answer from out M-Search question
    void UpdDatenEmpfangen(UdpSocket* pUdpSocket)
    {
        uint32_t nAvalible = pUdpSocket->GetBytesAvailible();

        shared_ptr<char> spBuffer(new char[nAvalible + 1]);

        string strFrom;
        uint32_t nRead = pUdpSocket->Read(spBuffer.get(), nAvalible, strFrom);

        if (nRead > 0)
        {
           // auto item = find_if(begin(m_maSockets), end(m_maSockets), [&](const auto& iter) { return get<5>(iter.second) == pUdpSocket ? true : false; });
#ifdef _DEBUG
            stringstream ss;
            ss << strFrom << endl;
            ss << string(spBuffer.get(), nRead) << endl;
            mxcout.lock();
            cout << ss.str(); cout.flush();
            mxcout.unlock();
#endif
            map<string, string> HeaderList = ParseHttpHeader(string(spBuffer.get(), nRead));
            if (HeaderList.empty() == false)
            {
                auto itHeader = HeaderList.find(":method");
                auto itPath = HeaderList.find(":path");
                if (itHeader != end(HeaderList) && itHeader->second.compare("HTTP/1.1") == 0 && itPath != end(HeaderList) && itPath->second.compare("200") == 0)
                {
                    auto itLocation = HeaderList.find("location");
                    if (itLocation != end(HeaderList))
                    {
                        // http://[fe80::c891:7b5b:ccb9:98c2]:2869/upnphost/udhisapi.dll?content=uuid:dcd07b65-61c7-4850-b552-ffa7fca788fc
                        auto tpLocation = ParseLocationHeader(itLocation->second);
                        if (get<1>(tpLocation).size() == 0)
                        {
                            OutputDebugString(wstring(L"Error: location header invalid: " + wstring(itLocation->second.begin(), itLocation->second.end()) + L"\r\n").c_str());
                            return;
                        }

                        FetchHttp(true, get<0>(tpLocation), get<1>(tpLocation), get<2>(tpLocation));
                    }
                    else
                        OutputDebugString(L"Error: no location header in m-search response\r\n");
                }
                else
                    OutputDebugString(L"Error: unexpected method\r\n");

            }
            else
                OutputDebugString(L"Error: parsing http header\r\n");
        }
    }

    void OnNewConnection(const vector<TcpSocket*>& vNewConnections)
    {
        for (auto pSocket : vNewConnections)
        {
            if (pSocket != nullptr)
            {
                pSocket->BindFuncBytesReceived(static_cast<function<void(TcpSocket*)>>(bind(&UpnPServer::OnDataRecieved, this, _1)));
                pSocket->BindErrorFunction(static_cast<function<void(BaseSocket*)>>(bind(&UpnPServer::OnSocketError, this, _1)));
                pSocket->BindCloseFunction(static_cast<function<void(BaseSocket*)>>(bind(&UpnPServer::OnSocketCloseing, this, _1)));
                m_mtxConnections.lock();
                m_maServerConn.emplace(pSocket, make_tuple(string(), map<string, string>()));
                pSocket->StartReceiving();
                m_mtxConnections.unlock();
            }
        }
    }

    void OnDataRecieved(TcpSocket* pTcpSocket)
    {
        uint32_t nAvalible = pTcpSocket->GetBytesAvailible();

        if (nAvalible == 0)
        {
            pTcpSocket->Close();
            return;
        }

        shared_ptr<char> spBuffer(new char[nAvalible]);

        uint32_t nRead = pTcpSocket->Read(spBuffer.get(), nAvalible);

        if (nRead > 0)
        {
            m_mtxConnections.lock();
            auto item = m_maServerConn.find(pTcpSocket);
            if (item != end(m_maServerConn))
            {
                get<0>(item->second).append(spBuffer.get(), nRead);

                if (get<1>(item->second).empty() == true)
                {
                    map<string, string> HeaderList = ParseHttpHeader(get<0>(item->second));
                    if (HeaderList.empty() == false)
                        get<1>(item->second) = HeaderList;
                    else
                        OutputDebugString(L"Error: parsing http header\r\n");
                }

                if (get<1>(item->second).empty() == false)  // Header empfangen
                {
                    size_t nContentLength = 0;
                    auto itLength = get<1>(item->second).find("content-length");
                    if (itLength != end(get<1>(item->second)))
                        nContentLength = stoi(itLength->second);

                    if (nContentLength == 0 || nContentLength == get<0>(item->second).size())
                    {
                        ifstream src(string("." + get<1>(item->second).find(":path")->second).c_str(), ios::binary);
                        if (src.is_open() == true)
                        {
                            string strBuffer;
                            {
                                stringstream ssIn;
                                copy(istreambuf_iterator<char>(src), istreambuf_iterator<char>(), ostreambuf_iterator<char>(ssIn));
                                strBuffer = ssIn.str();
                            }
                            src.close();

                            string strFileTyp;
                            size_t nPos = get<1>(item->second).find(":path")->second.rfind(".");
                            if (nPos != string::npos)
                                strFileTyp = get<1>(item->second).find(":path")->second.substr(nPos + 1);

                            if (strFileTyp == "xml")
                            {
                                auto itSocket = find_if(begin(m_maSockets), end(m_maSockets), [&](const auto& iter) { return HTTPServSocket(iter.second) == pTcpSocket->GetServerSocketRef() ? true : false; });
                                if (itSocket != end(m_maSockets))
                                {
                                    strBuffer = regex_replace(strBuffer, regex("\\%\\{ADDRESS\\}"), (get<0>(itSocket->second) == AF_INET6 ? "[" : "") + get<1>(itSocket->second) + (get<0>(itSocket->second) == AF_INET6 ? "]" : ""));
                                    strBuffer = regex_replace(strBuffer, regex("\\%\\{PORT\\}"), to_string(HTTPServPort(itSocket->second)));
                                }
                            }

                            // MimeType
                            static const map<const char*, const char*> MimeListe = { { "xml", "text/xml" },{ "gif", "image/gif" },{ "jpeg", "image/jpeg" },{ "jpg", "image/jpeg" },{ "png", "image/png" } };

                            auto it = find_if(begin(MimeListe), end(MimeListe), [strFileTyp](const auto& item) { return strFileTyp == item.first; });
                            if (it != end(MimeListe))
                                strFileTyp = it->second;
                            else
                                strFileTyp = "application/octet-stream";

                            string strHeader("HTTP/1.1 200 OK\r\nServer: socks-utility/1.0\r\nDate: " + GetGmtDateString() + "\r\nConnection: close\r\nContent-Length: " + to_string(strBuffer.size()) + "\r\nContent-Type: " + strFileTyp +  "\r\n\r\n");
                            pTcpSocket->Write(&strHeader[0], strHeader.size());
                            pTcpSocket->Write(&strBuffer[0], strBuffer.size());
                        }
                        else
                            pTcpSocket->Write("HTTP/1.1 404 NotFound\r\nConnection: close\r\n\r\n", 44);

                        m_maServerConn.erase(pTcpSocket);
                        pTcpSocket->Close();
                    }
                }
            }
            m_mtxConnections.unlock();
        }
    }

    void OnConnEstablished(TcpSocket* pSocket)
    {
        m_mtxClientConn.lock();
        auto itSocket = m_maClientConn.find(pSocket);
        if (itSocket == end(m_maClientConn))
        {
            m_mtxClientConn.unlock();
            return;
        }

        string strRequest((get<5>(itSocket->second).size() > 0 ? "POST " : "GET ") + get<0>(itSocket->second) + " HTTP/1.1\r\nHost: " + get<1>(itSocket->second) + "\r\nConnection: close\r\n");
        if (get<5>(itSocket->second).size() > 0)
        {
            for (auto itHeader : get<6>(itSocket->second))
                strRequest += itHeader.first + ": " + itHeader.second + "\r\n";
            strRequest += "Content-Length: " + to_string(get<5>(itSocket->second).size()) + "\r\nContent-Type: text/xml; charset=\"utf-8\"\r\n\r\n";
            strRequest += get<5>(itSocket->second);
        }
        else
            strRequest += "\r\n";

        pSocket->Write(&strRequest[0], strRequest.size());

        get<5>(itSocket->second).clear();   // Content to send in request
        get<6>(itSocket->second).clear();   // Additional Headers in request

        m_mtxClientConn.unlock();
    }

    void OnClientReceived(TcpSocket* pSocket)
    {
        function<void(const string&, string&, SERVICEINFO*)> fnAddDevice = [&](const string& strHost, string& strRecBuffer, SERVICEINFO* pServiceItem)
        {
            m_mtxDevices.lock();

            if (pServiceItem == nullptr)
            {
                m_maDevices[strHost].strXml = strRecBuffer;
                m_maDevices[strHost].docXml.Parse(strRecBuffer.c_str());
                if (m_maDevices[strHost].docXml.ErrorID() == 0)
                {
                    XMLElement* ServListElement = m_maDevices[strHost].docXml.FirstChildElement("root")->FirstChildElement("device")->FirstChildElement("serviceList");
                    if (ServListElement != nullptr)
                    {
                        for (XMLNode* ele = ServListElement->FirstChildElement("service"); ele; ele = ele->NextSibling())
                        {
                            string strScpUrl(ele->FirstChildElement("SCPDURL")->GetText());
                            if (strScpUrl[0] != '/')
                                strScpUrl.insert(0, "/");

                            if (find_if(begin(m_maDevices[strHost].vServices), end(m_maDevices[strHost].vServices), [&](const auto& itServic) { return itServic.strSCPDURL == strScpUrl ? true : false; }) == end(m_maDevices[strHost].vServices))
                            {
                                m_maDevices[strHost].vServices.emplace_back();
                                m_maDevices[strHost].vServices.back().strSCPDURL = strScpUrl;
                                //OutputDebugString(wstring(wstring(m_maDevices[strHost].vServices.back().strSCPDURL.begin(), m_maDevices[strHost].vServices.back().strSCPDURL.end()) + L"\r\n").c_str());

                                string strNewHost(strHost);
                                XMLElement* BaseUrlElement = m_maDevices[strHost].docXml.FirstChildElement("root")->FirstChildElement("URLBase");
                                if (BaseUrlElement != nullptr)
                                    strNewHost = BaseUrlElement->GetText();

                                size_t nPos = strNewHost.find("://");
                                if (nPos != string::npos)
                                    strNewHost.erase(0, nPos + 3);
                                nPos = strNewHost.find("/");
                                if (nPos != string::npos)
                                    strNewHost.erase(nPos);

                                FetchHttp(false, strNewHost, m_maDevices[strHost].vServices.back().strSCPDURL, false, &m_maDevices[strHost].vServices.back());
                            }
                        }

                    }
                }
                else
                    OutputDebugString(L"Error: parsing XML document\r\n");
            }
            else if (pServiceItem == reinterpret_cast<SERVICEINFO*>(-1) || pServiceItem == reinterpret_cast<SERVICEINFO*>(-2))
            {
                tinyxml2::XMLDocument xml;
                xml.Parse(strRecBuffer.c_str());
                if (xml.ErrorID() == 0)
                {

                }
            }
            else
            {
                pServiceItem->strXml = strRecBuffer;
                pServiceItem->docXml.Parse(strRecBuffer.c_str());
                if (pServiceItem->docXml.ErrorID() == 0)
                {
                    if (strHost == "192.168.16.185:2869")
                    {
                        // Variable abfragen
                        XMLElement* VariableListe = pServiceItem->docXml.FirstChildElement("scpd")->FirstChildElement("serviceStateTable");
                        if (VariableListe != nullptr)
                        {
                            for (XMLNode* ele = VariableListe->FirstChildElement("stateVariable"); ele; ele = ele->NextSibling())
                            {
                                if (ele->FirstChildElement("name")->GetText() == string("SearchCapabilities"))
                                {
                                    tinyxml2::XMLDocument xml;
                                    xml.InsertFirstChild(xml.NewDeclaration());   // <?xml version="1.0" encoding="UTF-8"?>

                                    XMLElement* Envelop = xml.NewElement("SOAP-ENV:Envelope");
                                    Envelop->SetAttribute("xmlns:SOAP-ENV", "http://schemas.xmlsoap.org/soap/envelope/");
                                    Envelop->SetAttribute("SOAP-ENV:encodingStyle", "http://schemas.xmlsoap.org/soap/encoding/");
                                    xml.InsertEndChild(Envelop);

                                    XMLElement* Body = xml.NewElement("SOAP-ENV:Body");
                                    Envelop->InsertFirstChild(Body);

                                    XMLElement* Query = xml.NewElement("m:QueryStateVariable");
                                    Query->SetAttribute("xmlns:m", "urn:schemas-upnp-org:control-1-0"/*"urn:schemas-upnp-org:service-1-0"*/);
                                    Body->InsertFirstChild(Query);

                                    XMLElement* Name = xml.NewElement("m:varName");
                                    Name->InsertFirstChild(xml.NewText("SearchCapabilities"));
                                    Query->InsertFirstChild(Name);

                                    XMLPrinter printer;
                                    xml.Print(&printer);
                                    string xmlStr(printer.CStr(), printer.CStrSize());

                                    if (xmlStr.size() > 100)
                                    {
                                        XMLElement* ServListElement = m_maDevices[strHost].docXml.FirstChildElement("root")->FirstChildElement("device")->FirstChildElement("serviceList");
                                        if (ServListElement != nullptr)
                                        {
                                            for (XMLNode* ele = ServListElement->FirstChildElement("service"); ele; ele = ele->NextSibling())
                                            {
                                                if (ele->FirstChildElement("serviceType")->GetText() == string("urn:schemas-upnp-org:service:ContentDirectory:1"))
                                                {
                                                    string strUrlPath = ele->FirstChildElement("controlURL")->GetText();
                                                    FetchHttp(false, strHost, strUrlPath, false, reinterpret_cast<SERVICEINFO*>(-1), xmlStr, { make_pair("SOAPAction", "\"urn:schemas-upnp-org:control-1-0#QueryStateVariable\"") });
                                                    break;
                                                }
                                            }
                                        }
                                    }
                                    break;
                                }
                            }
                        }

                    }

                    if (strHost == "192.66.65.100:2869")
                    {
                        // Funktion aufrufen
                        XMLElement* ActionListe = pServiceItem->docXml.FirstChildElement("scpd")->FirstChildElement("actionList");
                        if (ActionListe != nullptr)
                        {
                            for (XMLNode* ele = ActionListe->FirstChildElement("action"); ele; ele = ele->NextSibling())
                            {
                                if (ele->FirstChildElement("name")->GetText() == string("GetProtocolInfo"))
                                {
                                    tinyxml2::XMLDocument xml2;
                                    xml2.InsertFirstChild(xml2.NewDeclaration());   // <?xml version="1.0" encoding="UTF-8"?>

                                    XMLElement* Envelop2 = xml2.NewElement("SOAP-ENV:Envelope");
                                    Envelop2->SetAttribute("xmlns:SOAP-ENV", "http://schemas.xmlsoap.org/soap/envelope/");
                                    Envelop2->SetAttribute("SOAP-ENV:encodingStyle", "http://schemas.xmlsoap.org/soap/encoding/");
                                    xml2.InsertEndChild(Envelop2);

                                    XMLElement* Body2 = xml2.NewElement("SOAP-ENV:Body");
                                    Envelop2->InsertFirstChild(Body2);

                                    XMLElement* Query2 = xml2.NewElement("m:GetProtocolInfo");
                                    Query2->SetAttribute("xmlns:m", "urn:schemas-upnp-org:service:ConnectionManager:1");
                                    Body2->InsertFirstChild(Query2);

                                    XMLPrinter printer2;
                                    xml2.Print(&printer2);
                                    string xmlStr2(printer2.CStr(), printer2.CStrSize());

                                    if (xmlStr2.size() > 100)
                                    {
                                        XMLElement* ServListElement = m_maDevices[strHost].docXml.FirstChildElement("root")->FirstChildElement("device")->FirstChildElement("serviceList");
                                        if (ServListElement != nullptr)
                                        {
                                            for (XMLNode* ele = ServListElement->FirstChildElement("service"); ele; ele = ele->NextSibling())
                                            {
                                                if (ele->FirstChildElement("serviceType")->GetText() == string("urn:schemas-upnp-org:service:ConnectionManager:1"))
                                                {
                                                    string strUrlPath = ele->FirstChildElement("controlURL")->GetText();
                                                    FetchHttp(false, strHost, strUrlPath, false, reinterpret_cast<SERVICEINFO*>(-2), xmlStr2, { make_pair("SOAPAction", "\"urn:schemas-upnp-org:service:ConnectionManager:1#GetProtocolInfo\"") });
                                                    break;
                                                }
                                            }
                                        }
                                    }
                                    break;
                                }
                            }
                        }
                    }
                }
                else
                    OutputDebugString(L"Error: parsing XML document\r\n");
            }

            m_mtxDevices.unlock();
        };

        uint32_t nAvalible = pSocket->GetBytesAvailible();

        if (nAvalible == 0) // Connection terminated
        {
            m_mtxClientConn.lock();
            auto itSocket = m_maClientConn.find(pSocket);
            //m_mtxClientConn.unlock();
            if (itSocket == m_maClientConn.end())
            {
                m_mtxClientConn.unlock();
                pSocket->Close();
                return;
            }

            map<string, string>& HeaderList = get<6>(itSocket->second);
            auto itStatus = HeaderList.find(":path");   // :path is the second item in the first line. In this case of a response it is the status code
            if (itStatus != end(HeaderList) && stoi(itStatus->second) == 200)
            {
                if (get<5>(itSocket->second).size() > 0)    // we have some kind of a body recieved
                {
                    auto itContType = HeaderList.find("content-type");
                    if (itContType == end(HeaderList) || itContType->second.find("text/xml") != string::npos)
                        fnAddDevice(get<1>(itSocket->second), get<5>(itSocket->second), get<3>(itSocket->second));
                    else
                        OutputDebugString(wstring(L"Error: Content-Type invalid: " + wstring(itContType->second.begin(), itContType->second.end()) + L"\r\n").c_str());
                }
            }
            else if (itStatus != end(HeaderList))
                OutputDebugString(wstring(L"Error: HTTP Statuscode: " + to_wstring(stoi(itStatus->second)) + L" bei Verbindung zu: : " + wstring((get<4>(itSocket->second) & 2) == 2 ? L"https://" : L"http://") + wstring(begin(get<1>(itSocket->second)), end(get<1>(itSocket->second))) + wstring(begin(get<0>(itSocket->second)), end(get<0>(itSocket->second))) + L"\r\n").c_str());
            else
                OutputDebugString(wstring(L"Error: HTTP ohne Daten bei Verbindung zu: : " + wstring((get<4>(itSocket->second) & 2) == 2 ? L"https://" : L"http://") + wstring(begin(get<1>(itSocket->second)), end(get<1>(itSocket->second))) + wstring(begin(get<0>(itSocket->second)), end(get<0>(itSocket->second))) + L"\r\n").c_str());

            m_mtxClientConn.unlock();
            pSocket->Close();
            return;
        }

        shared_ptr<char> spBuffer(new char[nAvalible]);

        uint32_t nRead = pSocket->Read(spBuffer.get(), nAvalible);

        if (nRead > 0)
        {
            static regex rx("^([0-9a-fA-F]+)[\\r]?\\n");

            m_mtxClientConn.lock();
            auto itSocket = m_maClientConn.find(pSocket);
            //m_mtxClientConn.unlock();
            if (itSocket == m_maClientConn.end())
            {
                m_mtxClientConn.unlock();
                pSocket->Close();
                return;
            }

            get<5>(itSocket->second).append(spBuffer.get(), nRead);

            // Did we get a Http Header
            map<string, string>& HeaderList = get<6>(itSocket->second);
            if (HeaderList.size() == 0)  // no http header received
                HeaderList = ParseHttpHeader(get<5>(itSocket->second));

            if (HeaderList.size() > 0)
            {
                // do we have Chunked transfer-encoding?
                auto itTransCode = HeaderList.find("transfer-encoding");
                if (itTransCode != end(HeaderList) && itTransCode->second == "chunked")
                {
                    if (get<2>(itSocket->second) == 0)
                    {
                        match_results<const char*> mr;
                        if (regex_search(get<5>(itSocket->second).c_str(), mr, rx, regex_constants::format_first_only) == true && mr[0].matched == true && mr[1].matched == true)
                        {
                            get<2>(itSocket->second) = strtol(mr[1].str().c_str(), 0, 16);
                            get<5>(itSocket->second).erase(0, mr.length());
                            if (get<2>(itSocket->second) > 0)
                                get<4>(itSocket->second) |= 1;  // We need a chunk size from 0 to end chunked transfer encoding
                        }
                    }

                    while (get<2>(itSocket->second) > 0 && get<5>(itSocket->second).size() >= get<2>(itSocket->second))    // we have more or equal bytes in our receive buffer, than the chunk size
                    {
                        match_results<const char*> mr;
                        if (regex_search(get<5>(itSocket->second).substr(get<2>(itSocket->second)).c_str(), mr, rx, regex_constants::format_first_only) == true && mr[0].matched == true && mr[1].matched == true)
                        {   // we found the next chunk header
                            uint32_t nOldSize = get<2>(itSocket->second);
                            get<2>(itSocket->second) = strtol(mr[1].str().c_str(), 0, 16);
                            get<5>(itSocket->second).erase(nOldSize, mr.length());
                            if (get<2>(itSocket->second) == 0)
                                get<4>(itSocket->second) &= ~1;  // We need a chunk size from 0 to end chunked transfer encoding
                            get<2>(itSocket->second) += nOldSize;
                        }
                        else
                            break;  // We did not find the next chunk header, there must come more bytes from the server
                    }
                }

                auto itLength = HeaderList.find("content-length");
                if ((itLength != end(HeaderList) && (stoi(itLength->second) <= get<5>(itSocket->second).size() || stoi(itLength->second) == 0))
                || (get<2>(itSocket->second) > 0 && get<5>(itSocket->second).size() >= get<2>(itSocket->second) && (get<4>(itSocket->second) & 1) == 0))
                {
                    auto itStatus = HeaderList.find(":path");   // :path is the second item in the first headerline. In this case of a respons it is the status code
                    if (itStatus != end(HeaderList) && stoi(itStatus->second) == 200)
                    {
                        auto itContType = HeaderList.find("content-type");
                        if (itContType == end(HeaderList) || itContType->second.find("text/xml") != string::npos)
                            fnAddDevice(get<1>(itSocket->second), get<5>(itSocket->second), get<3>(itSocket->second));
                        else
                            OutputDebugString(wstring(L"Error: Content-Type invalid: " + wstring(itContType->second.begin(), itContType->second.end()) + L"\r\n").c_str());
                        get<5>(itSocket->second).clear();

                        m_mtxClientConn.unlock();
                        pSocket->Close();
                        return;
                    }

                    else if (itStatus != end(HeaderList) && stoi(itStatus->second) >= 300 && stoi(itStatus->second) <= 399)
                    {
                        auto itLocation = HeaderList.find("location");
                        if (itLocation != end(HeaderList))
                        {
                            auto tpLocation = ParseLocationHeader(itLocation->second);
                            if (get<1>(tpLocation).size() > 0)
                                FetchHttp(false, get<0>(tpLocation), get<1>(tpLocation), get<2>(tpLocation));
                            else
                                OutputDebugString(wstring(L"Error: location header invalid: " + wstring(itLocation->second.begin(), itLocation->second.end()) + L"\r\n").c_str());
                        }

                        get<5>(itSocket->second).clear();

                        m_mtxClientConn.unlock();
                        pSocket->Close();
                        return;
                    }
                    else
                    {
                        if (itStatus != end(HeaderList))
                            OutputDebugString(wstring(L"Error: HTTP Statuscode: " + to_wstring(stoi(itStatus->second)) + L" bei Verbindung zu: : " + wstring((get<4>(itSocket->second) & 2) == 2 ? L"https://" : L"http://")  + wstring(begin(get<1>(itSocket->second)), end(get<1>(itSocket->second))) + wstring(begin(get<0>(itSocket->second)), end(get<0>(itSocket->second))) + L"\r\n").c_str());
                        else
                            OutputDebugString(wstring(L"Error: HTTP ohne Daten bei Verbindung zu: : " + wstring((get<4>(itSocket->second) & 2) == 2 ? L"https://" : L"http://") + wstring(begin(get<1>(itSocket->second)), end(get<1>(itSocket->second))) + wstring(begin(get<0>(itSocket->second)), end(get<0>(itSocket->second))) + L"\r\n").c_str());

                        get<5>(itSocket->second).clear();

                        m_mtxClientConn.unlock();
                        pSocket->Close();
                        return;
                    }
                }
            }
            m_mtxClientConn.unlock();
        }
    }

    void SendNotifyAdvertise(const UPnParameter& tpParam, const char* szHostAddr, const char* szSSDP)
    {
        string strSend;
        strSend = regex_replace(strNotify, regex("\\%\\{HOSTADDR\\}"), szHostAddr);
        strSend = regex_replace(strSend, regex("\\%\\{ADDRESS\\}"), (get<0>(tpParam) == AF_INET6 ? "[" : "") + get<1>(tpParam) + (get<0>(tpParam) == AF_INET6 ? "]" : ""));
        strSend = regex_replace(strSend, regex("\\%\\{PORT\\}"), to_string(HTTPServPort(tpParam)));
        strSend = regex_replace(strSend, regex("\\%\\{SSDP\\}"), szSSDP);
        get<5>(tpParam)->Write(strSend.c_str(), strSend.size(), szHostAddr);
    }

    void FetchHttp(bool bLock, string strHost, const string& strPath, bool bUseSsl, SERVICEINFO* pServInfo = nullptr, const string& strBody = string(), const map<string, string>& mHeader = {})
    {
        if (bLock == true)
            m_mtxClientConn.lock();

        auto itRet = m_maClientConn.emplace(bUseSsl == true ? new SslTcpSocket() : new TcpSocket(), make_tuple(strPath, strHost, 0, pServInfo, bUseSsl == true ? 2 : 0, strBody, mHeader));
        if (itRet.second == true)
        {
            itRet.first->first->BindCloseFunction(static_cast<function<void(BaseSocket*)>>(bind(&UpnPServer::OnSocketCloseing, this, _1)));
            itRet.first->first->BindErrorFunction(static_cast<function<void(BaseSocket*)>>(bind(&UpnPServer::OnSocketError, this, _1)));
            itRet.first->first->BindFuncConEstablished(static_cast<function<void(TcpSocket*)>>(bind(&UpnPServer::OnConnEstablished, this, _1)));
            itRet.first->first->BindFuncBytesReceived(static_cast<function<void(TcpSocket*)>>(bind(&UpnPServer::OnClientReceived, this, _1)));

            size_t nPos = strHost.rfind(":");
            uint16_t sPort = bUseSsl == true ? 443 : 80;
            if (nPos != string::npos)
            {
                sPort = stoi(strHost.substr(nPos + 1));
                strHost.erase(nPos);
            }

            if (itRet.first->first->Connect(&strHost[0], sPort) == false)
                m_maClientConn.erase(itRet.first->first);
        }

        if (bLock == true)
            m_mtxClientConn.unlock();
    }

    tuple<string, string, bool> ParseLocationHeader(string strLocation)
    {
        transform(begin(strLocation), end(strLocation), begin(strLocation), ::tolower);

        bool bUseHttps = false;
        string strPath;

        size_t nPos = strLocation.find("://");
        if (nPos != string::npos)
        {
            if (strLocation.substr(0, nPos) == "https")
                bUseHttps = true;
            strLocation.erase(0, nPos + 3);
        }
        nPos = strLocation.find("/");
        if (nPos != string::npos)
        {
            strPath = strLocation.substr(nPos);
            strLocation.erase(nPos);
        }

        return make_tuple(strLocation, strPath, bUseHttps);
    }

    map<string, string> ParseHttpHeader(string& strReceived)
    {
        map<string, string> HeaderList;

        size_t nPosEndOfHeader = strReceived.find("\r\n\r\n");
        if (nPosEndOfHeader != string::npos)
        {
            const static regex crlfSeperator("\r\n");
            sregex_token_iterator line(begin(strReceived), begin(strReceived) + nPosEndOfHeader, crlfSeperator, -1);
            while (line != sregex_token_iterator())
            {
                if (HeaderList.size() == 0)    // 1 Zeile
                {
                    const string& strLine = line->str();
                    const static regex SpaceSeperator(" ");
                    sregex_token_iterator token(begin(strLine), end(strLine), SpaceSeperator, -1);
                    if (token != sregex_token_iterator())
                    {
                        auto itLastItem = HeaderList.emplace(":method", token++->str());
                        if (itLastItem.second == true)
                            transform(begin(itLastItem.first->second), end(itLastItem.first->second), begin(itLastItem.first->second), toupper);
                    }
                    if (token != sregex_token_iterator())
                        HeaderList.emplace(":path", token++->str());
                    if (token != sregex_token_iterator())
                        HeaderList.emplace(":version", token++->str());
                }
                else
                {
                    size_t nPos1 = line->str().find(':');
                    if (nPos1 != string::npos)
                    {
                        string strTmp = line->str().substr(0, nPos1);
                        transform(begin(strTmp), begin(strTmp) + nPos1, begin(strTmp), ::tolower);

                        auto parResult = HeaderList.emplace(strTmp, line->str().substr(nPos1 + 1));
                        if (parResult.second == true)
                        {
                            parResult.first->second.erase(parResult.first->second.find_last_not_of(" \r\n\t") + 1);
                            parResult.first->second.erase(0, parResult.first->second.find_first_not_of(" \t"));
                        }
                    }
                }
                ++line;
            }

            strReceived.erase(0, nPosEndOfHeader + 4);
        }
        return HeaderList;
    }

    string GetGmtDateString()
    {
        static locale s_cLocal(locale("C"));

        auto in_time_t = chrono::system_clock::to_time_t(chrono::system_clock::now());

        stringstream ss;
        ss.imbue(s_cLocal);
        ss << put_time(::gmtime(&in_time_t), "%a, %d %b %Y %H:%M:%S GMT");
        return ss.str();
    }

private:
    map<UdpSocket*, UPnParameter>    m_maSockets;                       // Multicast Socket, siehe oben
    map<TcpSocket*, tuple<string, map<string, string>>>   m_maServerConn;                    // TCP-Client-Socket, Empfangs-Puffer, Headerlist
    mutex                            m_mtxConnections;
    map<TcpSocket*, tuple<string, string, uint32_t, SERVICEINFO*, uint32_t, string, map<string, string>>>   m_maClientConn;  // Socket, RequestItem, Hostname, Next chunk size, Pointer to Service, iStatusFlag, Content-Body, (Additional) Headerlist
    mutex                            m_mtxClientConn;

    map<string, DEVICEINFO>          m_maDevices;                       // IP Adresse:Port, XML-Dokument
    mutex                            m_mtxDevices;

    RandIntervalTimer                m_timMSearch;
    RandIntervalTimer                m_timNotify;
};


int main(int argc, const char* argv[])
{
#if defined(_WIN32) || defined(_WIN64)
    // Detect Memory Leaks
    _CrtSetDbgFlag(_CRTDBG_ALLOC_MEM_DF | _CRTDBG_LEAK_CHECK_DF | _CrtSetDbgFlag(_CRTDBG_REPORT_FLAG));

    //_setmode(_fileno(stdout), _O_U8TEXT);
#endif

    //locale::global(std::locale(""));

	UpnPServer UpnPSrv;
	UpnPSrv.Start();

#if defined(_WIN32) || defined(_WIN64)
    //while (::_kbhit() == 0)
    //    this_thread::sleep_for(chrono::milliseconds(1));
    _getch();
#else
    getchar();
#endif

	UpnPSrv.Stop();

    return 0;
}

