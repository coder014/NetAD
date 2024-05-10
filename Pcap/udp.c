#include <pcap.h>
#include <Windows.h>
#include "func.h"

static void handle_udp(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data) {
    // 检查报文长度是否符合UDP报文的最小长度
    if (header->caplen < 42) {
        printf("Invalid UDP packet length\n");
        return;
    }

    // 获取UDP报文的各个字段
    const u_char* udp_hdr = pkt_data + 14 + 20; // 跳过以太网头部和IP头部
    int udp_src_port = udp_hdr[0] * 256 + udp_hdr[1]; // 源端口号
    int udp_dst_port = udp_hdr[2] * 256 + udp_hdr[3]; // 目的端口号
    int udp_length = udp_hdr[4] * 256 + udp_hdr[5]; // UDP长度

    // 源和目的IP地址
    char src_ip[INET6_ADDRSTRLEN];
    char dst_ip[INET6_ADDRSTRLEN];
    if (pkt_data[12] == 0x08 && pkt_data[13] == 0x00) { // IPv4
        inet_ntop(AF_INET, pkt_data + 26, src_ip, INET6_ADDRSTRLEN);
        inet_ntop(AF_INET, pkt_data + 30, dst_ip, INET6_ADDRSTRLEN);
    }
    else if (pkt_data[12] == 0x86 && pkt_data[13] == 0xdd) { // IPv6
        inet_ntop(AF_INET6, pkt_data + 22, src_ip, INET6_ADDRSTRLEN);
        inet_ntop(AF_INET6, pkt_data + 38, dst_ip, INET6_ADDRSTRLEN);
    }
    else {
        printf("Unknown IP version\n");
        return;
    }

    // 源和目的端口号
    int src_port = ntohs(udp_src_port);
    int dst_port = ntohs(udp_dst_port);

    // 获取UDP数据载荷
    const u_char* udp_payload = udp_hdr + 8;

    // 获取锁
    WaitForSingleObject(print_mutex, INFINITE);

    // 格式化打印UDP报文的相关信息
    printf("[UDP Packet]:\n");
    printf("\tSource IP Address: %s\n", src_ip);
    printf("\tSource Port: %d\n", src_port);
    printf("\tDestination IP Address: %s\n", dst_ip);
    printf("\tDestination Port: %d\n", dst_port);
    printf("\tUDP Length: %d bytes\n", udp_length);

    // 打印UDP数据载荷（16进制与ASCII编码）
    printf("\tUDP Payload (Hex): ");
    for (int i = 0; i < udp_length - 8; i++) {
        printf("%02X ", udp_payload[i]);
    }
    printf("\n");

    printf("\tUDP Payload (ASCII): ");
    for (int i = 0; i < udp_length - 8; i++) {
        if (udp_payload[i] >= 32 && udp_payload[i] <= 126) {
            printf("%c", udp_payload[i]);
        }
        else {
            printf(".");
        }
    }
    printf("\n\n");

    // 释放锁
    ReleaseMutex(print_mutex);
}

DWORD WINAPI sniff_udp(LPVOID lpParam) {
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;

    pcap_t* adapter_handle = pcap_open_live(thedev->name, MAX_PACKET_SIZE, 1, 1000, errbuf);
    if (adapter_handle == NULL) {
        fprintf(stderr, "Error in pcap_open_live: %s\n", errbuf);
        return -1;
    }
    adapter_handles[PROTOCOL_UDP] = adapter_handle;
    if (pcap_compile(adapter_handle, &fp, "udp", 0, 0) == -1) {
        fprintf(stderr, "Error compiling filter: %s\n", errbuf);
        pcap_close(adapter_handle);
        return -1;
    }
    if (pcap_setfilter(adapter_handle, &fp) == -1) {
        fprintf(stderr, "Error setting filter: %s\n", errbuf);
        pcap_close(adapter_handle);
        return -1;
    }

    pcap_loop(adapter_handle, 0, handle_udp, NULL);
    pcap_close(adapter_handle);
    return 0;
}