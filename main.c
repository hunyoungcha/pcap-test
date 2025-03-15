#include <stdio.h>
#include "packet_struct.h"

void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}

int main(int argc, char* argv[]){
	char errbuf[PCAP_ERRBUF_SIZE];
	
	// 파라미터 없을 경우 에러 처리하기

	pcap_t* pcap = pcap_open_live(argv[1], BUFSIZ, 1, 1000, errbuf);
	struct pcap_pkthdr* header;
	const u_char* packet;

	int res = pcap_next_ex(pcap, &header, &packet);
	
	struct ethernet_header *eth = (struct ethernet_header *)packet;
	struct ip_header *ip = (struct ip_header *)(packet + sizeof(struct ethernet_header));
	struct tcp_header *tcp = (struct tcp_header	*)(packet + sizeof(struct ip_header));

	//출력 함수로 빼기
	printf("Source MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
		eth->srcMac[0], eth->srcMac[1], eth->srcMac[2],
		eth->srcMac[3], eth->srcMac[4], eth->srcMac[5]);

	printf("Source IP: %d.%d.%d.%d\n",
	ip->SourceAddress[0],ip->SourceAddress[1],ip->SourceAddress[2],ip->SourceAddress[3]);

	printf("Source Port: %d\n", ntohs(tcp->SourcePort));

	int ethernet_header_length = sizeof(struct ethernet_header); 
	int ip_header_length = (ip->VersionAndIhl & 0x0F) * 4;        // IHL 값 * 4가 실제 IP 헤더 길이
	int tcp_header_length = (tcp->DataOffsetAndReserved >> 4) * 4; 

	const u_char* payload = packet + ethernet_header_length + ip_header_length + tcp_header_length;

	printf("Payload: ");
	for(int i = 0; i < 20; i++) {
		printf("%02x ", payload[i]);
	}
	printf("\n");

	pcap_close(pcap);
	return 0;
	}