#include <pcap.h>
#include <Windows.h>
#include "func.h"

static void handle_arp(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data) {
    if (header->caplen < 42) {
        printf("Invalid ARP packet length\n");
        return;
    }

    // 获取ARP报文的各个字段
    const u_char* arp_hdr = pkt_data + 14; // 跳过以太网头部
    int arp_op = arp_hdr[6] * 256 + arp_hdr[7]; // 操作码

    // 获取锁
    WaitForSingleObject(print_mutex, INFINITE);

    // 格式化打印ARP报文的相关信息
    printf("[ARP Packet]:\n");
    printf("\tOperation: %s\n", arp_op == 1 ? "ARP Request" : (arp_op == 2 ? "ARP Reply" : "Unknown"));

    // 打印源和目的MAC地址
    printf("\tSender MAC Address: ");
    for (int i = 0; i < 6; i++) {
        printf("%02X", arp_hdr[8 + i]);
        if (i < 5) printf(":");
    }
    printf("\n");

    printf("\tSender IP Address: ");
    for (int i = 0; i < 4; i++) {
        printf("%d", arp_hdr[14 + i]);
        if (i < 3) printf(".");
    }
    printf("\n");

    printf("\tTarget MAC Address: ");
    for (int i = 0; i < 6; i++) {
        printf("%02X", arp_hdr[18 + i]);
        if (i < 5) printf(":");
    }
    printf("\n");

    printf("\tTarget IP Address: ");
    for (int i = 0; i < 4; i++) {
        printf("%d", arp_hdr[24 + i]);
        if (i < 3) printf(".");
    }
    printf("\n\n");

    // 释放锁
    ReleaseMutex(print_mutex);
}

DWORD WINAPI sniff_arp(LPVOID lpParam) {
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;

    pcap_t* adapter_handle = pcap_open_live(thedev->name, MAX_PACKET_SIZE, 1, 1000, errbuf);
    if (adapter_handle == NULL) {
        fprintf(stderr, "Error in pcap_open_live: %s\n", errbuf);
        return -1;
    }
    adapter_handles[PROTOCOL_ARP] = adapter_handle;
    if (pcap_compile(adapter_handle, &fp, "arp", 0, 0) == -1) {
        fprintf(stderr, "Error compiling filter: %s\n", errbuf);
        pcap_close(adapter_handle);
        return -1;
    }
    if (pcap_setfilter(adapter_handle, &fp) == -1) {
        fprintf(stderr, "Error setting filter: %s\n", errbuf);
        pcap_close(adapter_handle);
        return -1;
    }

    pcap_loop(adapter_handle, 0, handle_arp, NULL);
    pcap_close(adapter_handle);
    return 0;
}