#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>
#pragma comment(lib, "ws2_32.lib")
#define CONNECT_TIMEOUT 3000

int main(int argc, char* argv[]) {
    if (argc != 5) {
        printf("Usage: %s -a [IPv4 Address] -p [Port]\n", argv[0]);
        return 1;
    }

    char* targetIP = NULL;
    int targetPort = 0;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-a") == 0 && i + 1 < argc) {
            targetIP = argv[i + 1];
        }
        else if (strcmp(argv[i], "-p") == 0 && i + 1 < argc) {
            targetPort = atoi(argv[i + 1]);
        }
    }

    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);
    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    int timeout = CONNECT_TIMEOUT;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (char*)&timeout, sizeof(timeout));
    struct sockaddr_in targetAddr;
    targetAddr.sin_family = AF_INET;
    targetAddr.sin_addr.s_addr = inet_addr(targetIP);
    targetAddr.sin_port = htons(targetPort);

    int result = connect(sock, (struct sockaddr*)&targetAddr, sizeof(targetAddr));
    if (result == SOCKET_ERROR) {
        printf("Port %d on %s is closed.\n", targetPort, targetIP);
    }
    else {
        printf("Port %d on %s is open.\n", targetPort, targetIP);
        closesocket(sock);
    }

    WSACleanup();
    return 0;
}