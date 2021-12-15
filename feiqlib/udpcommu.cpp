#include "udpcommu.h"
#include <arpa/inet.h>
#include <array>
#include <errno.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <sys/types.h>
#include <thread>
#include <unistd.h>

#define setFailedMsgAndReturnFalse(msg) \
    {                                   \
        mErrMsg = msg;                  \
        return false;                   \
    }

#define setErrnoMsgAndReturnFalse() \
    {                               \
        mErrMsg = strerror(errno);  \
        return false;               \
    }

#define setErrnoMsg() mErrMsg = strerror(errno);

UdpCommu::UdpCommu() {}

bool UdpCommu::bindTo(int port)
{
    if (mSocket != -1)
        setFailedMsgAndReturnFalse("已经初始化");

    //创建socket
    mSocket = socket(PF_INET, SOCK_DGRAM, 0);
    if (mSocket == -1)
        setErrnoMsgAndReturnFalse();

    auto ret = -1;
    //允许广播
    auto broadcast = 1;
    ret = setsockopt(mSocket, SOL_SOCKET, SO_BROADCAST, &broadcast, sizeof(int));
    if (ret == -1)
        setErrnoMsgAndReturnFalse();

    //地址复用
    auto reuse = 1;
    ret = setsockopt(mSocket, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(int));
    if (ret == -1)
        setErrnoMsgAndReturnFalse();

    //绑定
    sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(port);

    ret = ::bind(mSocket, (sockaddr *)&addr, sizeof(addr));
    if (ret == -1)
        setErrnoMsgAndReturnFalse();

    return true;
}

int UdpCommu::sentTo(const string &ip, int port, const void *data, int size)
{
    sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr(ip.c_str());
    addr.sin_port = htons(port);

    auto ret = ::sendto(mSocket, data, size, 0, (sockaddr *)&addr, sizeof(addr));
    if (ret == -1)
        setErrnoMsg();

    return ret;
}

bool UdpCommu::startAsyncRecv(UdpRecvHandler handler)
{
    if (handler == nullptr)
        setFailedMsgAndReturnFalse("handler不能为空")

            if (mSocket == -1)
                setFailedMsgAndReturnFalse("请先初始化socket");

    mRecvHandler = handler;
    if (!mAsyncMode)
    {
        mAsyncMode = true;
        std::thread t(&UdpCommu::recvThread, this);
        t.detach();
    }

    return true;
}

void UdpCommu::close()
{
    if (mSocket == -1)
        return;

    ::close(mSocket);
    mSocket = -1;
    mAsyncMode = false;
}

string get_mac_addr()
{
    const int MAC_SIZE = 18;
    struct ifreq ifr;
    int sd;
    const char eth_inf[] = "eth0";
    char mac[MAC_SIZE] = "";

    bzero(&ifr, sizeof(struct ifreq));
    if ((sd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        printf("get %s mac address socket creat error\n", eth_inf);
        return "";
    }

    strncpy(ifr.ifr_name, eth_inf, sizeof(ifr.ifr_name) - 1);

    if (ioctl(sd, SIOCGIFHWADDR, &ifr) < 0)
    {
        printf("get %s mac address error\n", eth_inf);
        close(sd);
        return "";
    }

    snprintf(mac, MAC_SIZE, "%02x:%02x:%02x:%02x:%02x:%02x",
             (unsigned char)ifr.ifr_hwaddr.sa_data[0],
             (unsigned char)ifr.ifr_hwaddr.sa_data[1],
             (unsigned char)ifr.ifr_hwaddr.sa_data[2],
             (unsigned char)ifr.ifr_hwaddr.sa_data[3],
             (unsigned char)ifr.ifr_hwaddr.sa_data[4],
             (unsigned char)ifr.ifr_hwaddr.sa_data[5]);

    close(sd);
    return mac;
}

string UdpCommu::getBoundMac()
{
    return get_mac_addr();
}

string UdpCommu::getErrMsg()
{
    return mErrMsg;
}

void UdpCommu::recvThread()
{
    timeval timeo = {3, 0};
    auto ret = setsockopt(mSocket, SOL_SOCKET, SO_RCVTIMEO, &timeo, sizeof(timeval));
    if (ret != 0)
    {
        printf("faield to set recv timeo\n");
        mAsyncMode = false;
        return;
    }

    std::array<char, MAX_RCV_SIZE> buf;
    sockaddr_in addr;
    socklen_t len = sizeof(addr);

    while (mSocket != -1)
    {
        buf.fill(0);
        memset(&addr, 0, len);

        auto size = recvfrom(mSocket, buf.data(), MAX_RCV_SIZE, 0, (sockaddr *)&addr, &len);
        if (size < 0)
        {
            if (errno == EAGAIN || errno == ETIMEDOUT)
                continue;

            printf("error occur:%s\n", strerror(errno));
            break;
        }

        auto ip = inet_ntoa(addr.sin_addr);
        vector<char> data(std::begin(buf), std::begin(buf) + size);
        mRecvHandler(ip, data);
    }

    printf("end recv thread\n");
    mAsyncMode = false;
}
