#include <stdio.h>
#include <string.h>
#include <pcap.h>
#include <WinSock2.h>
#include <Windows.h>
#include "func.h"

#define THE_DEV "\\Device\\NPF_{640B66A2-8911-45EE-A955-DA940E350F34}"

pcap_if_t* thedev;
HANDLE print_mutex;
HANDLE exit_event = NULL;
HANDLE threads[PROTOCOL_MAXN];
pcap_t* adapter_handles[4];

BOOL WINAPI ConsoleHandler(DWORD dwCtrlType)
{
    switch (dwCtrlType)
    {
    case CTRL_C_EVENT:
        SetEvent(exit_event);
        return TRUE;
    default:
        return FALSE;
    }
}

int main() {
    pcap_if_t* alldevs;
    char errbuf[PCAP_ERRBUF_SIZE];

    exit_event = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (!exit_event) {
        fprintf(stderr, "Error: CreateEvent failed\n");
        return -1;
    }

    if (!SetConsoleCtrlHandler(ConsoleHandler, TRUE)) {
        fprintf(stderr, "Error: SetConsoleCtrlHandler failed\n");
        return -1;
    }

    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
        return -1;
    }

    for (pcap_if_t* d = alldevs; d; d = d->next) {
        ifprint(d);
        if (strcmp(d->name, THE_DEV) == 0) {
            thedev = d;
        }
    }
    if (!thedev) {
        fprintf(stderr, "Specified device not found\n");
        return -1;
    }

    print_mutex = CreateMutex(NULL, FALSE, NULL);
    if (!print_mutex) {
        fprintf(stderr, "Error: CreateMutex failed\n");
        return -1;
    }

    threads[PROTOCOL_ARP] = CreateThread(NULL, 0, sniff_arp, NULL, 0, NULL);
    threads[PROTOCOL_ICMP] = CreateThread(NULL, 0, sniff_icmp, NULL, 0, NULL);
    threads[PROTOCOL_UDP] = CreateThread(NULL, 0, sniff_udp, NULL, 0, NULL);
    threads[PROTOCOL_TCP] = CreateThread(NULL, 0, sniff_tcp, NULL, 0, NULL);
    for (int i = 0; i < PROTOCOL_MAXN; i++) {
        if (!threads[i]) {
            fprintf(stderr, "Error creating thread\n");
            pcap_freealldevs(alldevs);
            return -1;
        }
    }

    printf("Network packet sniffing started!\n");

    WaitForSingleObject(exit_event, INFINITE);

    for (int i = 0; i < PROTOCOL_MAXN; i++) {
        pcap_breakloop(adapter_handles[i]);
    }

    WaitForMultipleObjects(PROTOCOL_MAXN, threads, TRUE, INFINITE);

    pcap_freealldevs(alldevs);
    for (int i = 0; i < PROTOCOL_MAXN; i++) {
        CloseHandle(threads[i]);
    }

    printf("Network packet sniffing stopped!\n");

    CloseHandle(print_mutex);
    CloseHandle(exit_event);

    return 0;
}
