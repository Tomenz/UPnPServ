
#include <iostream>
#include <map>
#include <mutex>

#if defined(_WIN32) || defined(_WIN64)
#include <Ws2tcpip.h>
#include <conio.h>
#include <io.h>
#include <fcntl.h>
#endif

#include "socketlib/SocketLib.h"
#include "tinyxml2/tinyxml2.h"

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

static mutex mxcout;

class SsdpServer
{
    typedef tuple<int, string, uint32_t> UPnParameter;  // AddrFamiely, IP-Addr, Interface-Index, TCP-Server, TCP-Server Port, UDP-Socket, UDP-Socket Port

public:
    SsdpServer() {}
    ~SsdpServer() {}

    void Start()
    {
        BaseSocket::EnumIpAddresses([&](int adrFamily, const string& strIpAddr, int nInterfaceIndex, void*) -> int
        {
            lock_guard<mutex> lock(mxcout);
            cout << strIpAddr << endl; cout.flush();//OutputDebugStringA(strIpAddr.c_str()); OutputDebugStringA("\r\n");

            pair<map<UdpSocket*, UPnParameter>::iterator, bool>paRet = m_maSockets.emplace(new UdpSocket(), make_tuple(adrFamily, strIpAddr, nInterfaceIndex));
            if (paRet.second == true)
            {
                paRet.first->first->BindErrorFunction(static_cast<function<void(BaseSocket*)>>(bind(&SsdpServer::OnSocketError, this, _1)));
                paRet.first->first->BindCloseFunction(static_cast<function<void(BaseSocket*)>>(bind(&SsdpServer::OnSocketCloseing, this, _1)));
                paRet.first->first->BindFuncBytesReceived(static_cast<function<void(UdpSocket*)>>(bind(&SsdpServer::UpnPDatenEmpfangen, this, _1)));
                if (get<0>(paRet.first->second) == AF_INET)
                {
                    if (paRet.first->first->Create(strIpAddr.c_str(), 1900, "0.0.0.0") == false)
                        cout << "Error creating Socket: " << strIpAddr << endl;
                    if (paRet.first->first->AddToMulticastGroup("239.255.255.250", strIpAddr.c_str(), nInterfaceIndex) == false)
                        cout << "Error joining Multicastgroup: " << strIpAddr << endl;
                }
                else if (get<0>(paRet.first->second) == AF_INET6)
                {
                    if (paRet.first->first->Create(strIpAddr.c_str(), 1900, "::") == false)
                        cout << "Error creating Socket: " << strIpAddr << endl;
                    if (paRet.first->first->AddToMulticastGroup("FF02::C", strIpAddr.c_str(), nInterfaceIndex) == false)
                        cout << "Error joining Multicastgroup: " << strIpAddr << endl;
                }
            }

            return 0;
        }, 0);

    }

    void Stop()
    {
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

            // UPnP, UDP Socket schließen
            itItem.first->Close();
        }

        while (m_maSockets.size())
        {
            // UPnP, UDP Socket schließen
            delete m_maSockets.begin()->first;

            m_maSockets.erase(m_maSockets.begin());
        }
    }

    void OnSocketError(BaseSocket* pBaseSocket)
    {
        pBaseSocket->Close();
    }

    void OnSocketCloseing(BaseSocket* pBaseSocket)
    {
        cout << "Socket closing" << endl;
    }

    void UpnPDatenEmpfangen(UdpSocket* pUdpSocket)
    {
        size_t nAvalible = pUdpSocket->GetBytesAvailable();

        shared_ptr<char> spBuffer(new char[nAvalible + 1]);

        string strFrom;
        size_t nRead = pUdpSocket->Read(spBuffer.get(), nAvalible, strFrom);

        if (nRead > 0)
        {
            auto itSocket = m_maSockets.find(pUdpSocket);
            if (itSocket == end(m_maSockets))
                return; // should never happened

            size_t nPos = strFrom.rfind(":");
            if (nPos == string::npos)
                return; // If this happens, than something really got wrong, our strFrom should always have a port divided by columns

        }
    }


private:
    map<UdpSocket*, UPnParameter>    m_maSockets;                       // Multicast Socket, siehe oben
    mutex                            m_mtxConnections;

};


int main(int argc, const char* argv[])
{
#if defined(_WIN32) || defined(_WIN64)
    // Detect Memory Leaks
    _CrtSetDbgFlag(_CRTDBG_ALLOC_MEM_DF | _CRTDBG_LEAK_CHECK_DF | _CrtSetDbgFlag(_CRTDBG_REPORT_FLAG));

    //_setmode(_fileno(stdout), _O_U8TEXT);
#endif

    //locale::global(std::locale(""));

    SsdpServer ssdp;
    ssdp.Start();

#if defined(_WIN32) || defined(_WIN64)
    //while (::_kbhit() == 0)
    //    this_thread::sleep_for(chrono::milliseconds(1));
    _getch();
#else
    getchar();
#endif

    ssdp.Stop();

    return 0;
}
