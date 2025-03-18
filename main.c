#include <stdio.h>
#include "packet_struct.h"

void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}

int main(int argc, char* argv[]){
	char errbuf[PCAP_ERRBUF_SIZE];
	
	// 파라미터 없을 경우 에러 처리하기
	while(1){
		pcap_t* pcap = pcap_open_live(argv[1], BUFSIZ, 1, 1000, errbuf);
		struct pcap_pkthdr* header;
		const u_char* packet;
	
		int res = pcap_next_ex(pcap, &header, &packet);
		//에러처리 필요

		struct ethernet_header *eth = (struct ethernet_header *)packet;
		int ethernet_header_length = sizeof(struct ethernet_header); 
		
		struct ip_header *ip = (struct ip_header *)(packet + ethernet_header_length);
		int ip_header_length = (ip->VersionAndIhl & 0x0F) *4;
		
		struct tcp_header *tcp = (struct tcp_header	*)(packet + ethernet_header_length + ip_header_length);
		int tcp_header_length = (tcp->DataOffsetAndReserved >> 4) * 4; 

		printf("======================================================\n");
		
		printf("Source MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
			eth->srcMac[0], eth->srcMac[1], eth->srcMac[2],
			eth->srcMac[3], eth->srcMac[4], eth->srcMac[5]);
		
		printf("Destination MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
			eth->dstMac[0], eth->dstMac[1], eth->dstMac[2],
			eth->dstMac[3], eth->dstMac[4], eth->dstMac[5]);
		
		printf("Source IP: %d.%d.%d.%d\n",
		ip->SourceAddress[0],ip->SourceAddress[1],ip->SourceAddress[2],ip->SourceAddress[3]);
	
		printf("Destination IP: %d.%d.%d.%d\n",
			ip->DestinationAddress[0],ip->DestinationAddress[1],ip->DestinationAddress[2],ip->DestinationAddress[3]);
		
		printf("Source Port: %d\n", ntohs(tcp->SourcePort));
		printf("Destination Port: %d\n", ntohs(tcp->DestinationPort));

		const u_char* payload = packet + ethernet_header_length + ip_header_length + tcp_header_length;
	
		printf("Payload: ");
		for(int i = 0; i < 20; i++) {
			printf("%02x ", payload[i]);
		}
		printf("\n");
		pcap_close(pcap);
	}
	
	return 0;
	}