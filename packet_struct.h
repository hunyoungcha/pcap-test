#include <pcap.h>
#include <arpa/inet.h>

#pragma pack(1)

struct ethernet_header {
    uint8_t dstMac[6];
    uint8_t srcMac[6];
    uint16_t type;
};

struct ip_header {
    uint8_t VersionAndIhl;
    uint8_t TOS;
    uint16_t TotalLength;

    uint16_t Identification;
    uint16_t FlagAndFragmentOffset;

    uint8_t TTL;
    uint8_t Protocol;
    uint16_t HeaderChecksum;

    uint8_t SourceAddress[4];
    uint8_t DestinationAddress[4];

};

struct tcp_header {
    uint16_t SourcePort;
    uint16_t DestinationPort;

    uint32_t SequenceNumber;
    uint32_t ACKNumber;

    uint8_t DataOffset[4];
    uint8_t Reserved[4];
    uint8_t Flag;
    uint16_t Window;
    
    uint16_t Checksum;
    uint16_t UrgentPointer;
};
