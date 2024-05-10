#include <pcap.h>
#include <Windows.h>
#include "func.h"

const char* icmp_types[] = {
    "Echo Reply",
    "Unknown",
    "Unknown",
    "Destination Unreachable",
    "Source Quench",
    "Redirect",
    "Unknown",
    "Unknown",
    "Echo Request",
    "Router Advertisement",
    "Router Selection",
    "Time Exceeded",
    "Parameter Problem",
    "Timestamp Request",
    "Timestamp Reply",
    "Information Request",
    "Information Reply",
    "Address Mask Request",
    "Address Mask Reply",
    "Unknown"
};

static void handle_icmp(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data) {
    // ��鱨�ĳ����Ƿ����ICMP���ĵ���С����
    if (header->caplen < 34) {
        printf("Invalid ICMP packet length\n");
        return;
    }

    // ��ȡICMP���ĵĸ����ֶ�
    const u_char* icmp_hdr = pkt_data + 14 + 20; // ������̫��ͷ����IPͷ��
    int icmp_type = icmp_hdr[0]; // ICMP����
    int icmp_code = icmp_hdr[1]; // ICMP����
    int icmp_id = icmp_hdr[4] * 256 + icmp_hdr[5]; // ICMP��ʶ��
    int icmp_seq = icmp_hdr[6] * 256 + icmp_hdr[7]; // ICMP���к�

    // Դ��Ŀ��IP��ַ
    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, pkt_data + 26, src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, pkt_data + 30, dst_ip, INET_ADDRSTRLEN);

    // Դ��Ŀ��MAC��ַ
    char src_mac[32];
    char dst_mac[32];
    sprintf(src_mac, "%02X:%02X:%02X:%02X:%02X:%02X", pkt_data[6], pkt_data[7], pkt_data[8], pkt_data[9], pkt_data[10], pkt_data[11]);
    sprintf(dst_mac, "%02X:%02X:%02X:%02X:%02X:%02X", pkt_data[0], pkt_data[1], pkt_data[2], pkt_data[3], pkt_data[4], pkt_data[5]);

    // ��ȡ��
    WaitForSingleObject(print_mutex, INFINITE);

    // ��ʽ����ӡICMP���ĵ������Ϣ
    printf("[ICMP Packet]:\n");
    printf("\tType: %s\n", icmp_type < sizeof(icmp_types) / sizeof(icmp_types[0]) ? icmp_types[icmp_type] : "Unknown");
    printf("\tCode: %d\n", icmp_code);
    printf("\tIdentifier: %d\n", icmp_id);
    printf("\tSequence Number: %d\n", icmp_seq);
    printf("\tSource IP Address: %s\n", src_ip);
    printf("\tDestination IP Address: %s\n", dst_ip);
    printf("\tSource MAC Address: %s\n", src_mac);
    printf("\tDestination MAC Address: %s\n", dst_mac);
    printf("\n\n");

    // �ͷ���
    ReleaseMutex(print_mutex);
}

DWORD WINAPI sniff_icmp(LPVOID lpParam) {
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;

    pcap_t* adapter_handle = pcap_open_live(thedev->name, MAX_PACKET_SIZE, 1, 1000, errbuf);
    if (adapter_handle == NULL) {
        fprintf(stderr, "Error in pcap_open_live: %s\n", errbuf);
        return -1;
    }
    adapter_handles[PROTOCOL_ICMP] = adapter_handle;
    if (pcap_compile(adapter_handle, &fp, "icmp", 0, 0) == -1) {
        fprintf(stderr, "Error compiling filter: %s\n", errbuf);
        pcap_close(adapter_handle);
        return -1;
    }
    if (pcap_setfilter(adapter_handle, &fp) == -1) {
        fprintf(stderr, "Error setting filter: %s\n", errbuf);
        pcap_close(adapter_handle);
        return -1;
    }

    pcap_loop(adapter_handle, 0, handle_icmp, NULL);
    pcap_close(adapter_handle);
    return 0;
}