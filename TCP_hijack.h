#ifndef TCP_HIJACK_H_
#define TCP_HIJACK_H_

#define BUF_SIZE 65536
#define TEST_STRING "TCP_Hijack"

int header_type;
#define LINKTYPE_NULL 0
#define LINKTYPE_ETH 1
#define LINKTYPE_WIFI 127

int fd; //the raw socket

void set_up_attack(unsigned char *, const struct pcap_pkthdr *, const unsigned char *);

void print_information(struct iphdr*, struct tcphdr*);
int build_packet(unsigned char*, struct iphdr*, struct tcphdr*);

#endif 
