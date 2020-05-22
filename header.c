/*
 * header.c
 *
 *
 *      some of the code is from site BinaryTides, written by Silver Moon
 */

#include<sys/socket.h>
#include<arpa/inet.h>
#include<stdio.h>
#include<string.h>

#include "header.h"

unsigned short checksum(unsigned short *ptr,int nbytes)
{
    register long sum;
    unsigned short oddbyte;
    register short answer;

    sum=0;
    while(nbytes>1) {
        sum+=*ptr++;
        nbytes-=2;
    }
    if(nbytes==1) {
        oddbyte=0;
        *((u_char*)&oddbyte)=*(u_char*)ptr;
        sum+=oddbyte;
    }

    sum = (sum>>16)+(sum & 0xffff);
    sum = sum + (sum>>16);
    answer=(short)~sum;

    return(answer);
}

unsigned short TCP_checksum(struct iphdr *iph, struct tcphdr *tcph, char *data){
    int size = SIZE_PSD + tcph->doff*4 + strlen(data);

    char temp[65536];
    bzero(temp, 65536);

    struct pseudo_header *psh = (struct pseudo_header*)temp;
    bzero(psh, SIZE_PSD);
    psh->source_address = iph->saddr;
    psh->dest_address = iph->daddr;
    psh->placeholder = 0;
    psh->protocol = 6;
    psh->length = tcph->doff*4;

    tcph->check = 0;
    int padding = 0;
    if(strlen(data)%2) padding = 1;
    memcpy(temp+SIZE_PSD, tcph, tcph->doff*4 + strlen(data));

    return checksum((unsigned short*)temp, size+padding);
}
