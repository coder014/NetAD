#include <pcap.h>
#include <Windows.h>
#include "func.h"

const char* tcp_flag_strs[] = {
    "FIN",
    "SYN",
    "RST",
    "PSH",
    "ACK",
    "URG",
    "ECE",
    "CWR"
};

static void handle_tcp(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data) {
    // 检查报文长度是否符合TCP报文的最小长度
    if (header->caplen < 54) {
        printf("Invalid TCP packet length\n");
        return;
    }

    // 获取TCP报文的各个字段
    const u_char* tcp_hdr = pkt_data + 14 + 20; // 跳过以太网头部和IP头部
    int tcp_src_port = tcp_hdr[0] * 256 + tcp_hdr[1]; // 源端口号
    int tcp_dst_port = tcp_hdr[2] * 256 + tcp_hdr[3]; // 目的端口号
    int tcp_seq = (tcp_hdr[4] << 24) + (tcp_hdr[5] << 16) + (tcp_hdr[6] << 8) + tcp_hdr[7]; // 序列号
    int tcp_ack = (tcp_hdr[8] << 24) + (tcp_hdr[9] << 16) + (tcp_hdr[10] << 8) + tcp_hdr[11]; // 确认号
    int tcp_offset = (tcp_hdr[12] >> 4) * 4; // 数据偏移
    int tcp_flags = tcp_hdr[13]; // TCP标志位

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
    int src_port = ntohs(tcp_src_port);
    int dst_port = ntohs(tcp_dst_port);

    // 获取TCP数据载荷
    const u_char* tcp_payload = pkt_data + 14 + 20 + tcp_offset;

    // 获取锁
    WaitForSingleObject(print_mutex, INFINITE);

    // 格式化打印TCP报文的相关信息
    printf("[TCP Packet]:\n");
    printf("\tSource IP Address: %s\n", src_ip);
    printf("\tSource Port: %d\n", src_port);
    printf("\tDestination IP Address: %s\n", dst_ip);
    printf("\tDestination Port: %d\n", dst_port);
    printf("\tSequence Number: %d\n", tcp_seq);
    printf("\tACK Number: %d\n", tcp_ack);
    printf("\tData Offset: %d bytes\n", tcp_offset);
    printf("\tFlags: ");
    for (int i = 0; i < 8; i++) {
        if (tcp_flags & (1 << i)) {
            printf("%s ", tcp_flag_strs[i]);
        }
    }
    printf("\n");

    // 如果存在TCP数据载荷，则以16进制与ASCII编码字符形式打印
    if (header->caplen > (UINT32)(14 + 20 + tcp_offset)) {
        printf("\tTCP Payload (Hex): ");
        for (int i = 0; i < (int)(header->caplen - (14 + 20 + tcp_offset)); i++) {
            printf("%02X ", tcp_payload[i]);
        }
        printf("\n");

        printf("\tTCP Payload (ASCII): ");
        for (int i = 0; i < (int)(header->caplen - (14 + 20 + tcp_offset)); i++) {
            if (tcp_payload[i] >= 32 && tcp_payload[i] <= 126) {
                printf("%c", tcp_payload[i]);
            }
            else {
                printf(".");
            }
        }
        printf("\n");
    }
    printf("\n");

    // 释放锁
    ReleaseMutex(print_mutex);
}

DWORD WINAPI sniff_tcp(LPVOID lpParam) {
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;

    pcap_t* adapter_handle = pcap_open_live(thedev->name, MAX_PACKET_SIZE, 1, 1000, errbuf);
    if (adapter_handle == NULL) {
        fprintf(stderr, "Error in pcap_open_live: %s\n", errbuf);
        return -1;
    }
    adapter_handles[PROTOCOL_TCP] = adapter_handle;
    if (pcap_compile(adapter_handle, &fp, "tcp", 0, 0) == -1) {
        fprintf(stderr, "Error compiling filter: %s\n", errbuf);
        pcap_close(adapter_handle);
        return -1;
    }
    if (pcap_setfilter(adapter_handle, &fp) == -1) {
        fprintf(stderr, "Error setting filter: %s\n", errbuf);
        pcap_close(adapter_handle);
        return -1;
    }

    pcap_loop(adapter_handle, 0, handle_tcp, NULL);
    pcap_close(adapter_handle);
    return 0;
}