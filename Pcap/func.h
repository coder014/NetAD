#pragma once
#include <pcap.h>
#include <Windows.h>

#define MAX_PACKET_SIZE 65536

extern HANDLE print_mutex;
extern pcap_if_t* thedev;
extern pcap_t* adapter_handles[4];

DWORD WINAPI sniff_arp(LPVOID lpParam);
DWORD WINAPI sniff_icmp(LPVOID lpParam);
DWORD WINAPI sniff_udp(LPVOID lpParam);
DWORD WINAPI sniff_tcp(LPVOID lpParam);

void ifprint(pcap_if_t* d);
char* iptos(u_long in);
char* ip6tos(struct sockaddr* sockaddr, char* address, int addrlen);