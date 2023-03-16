#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "net.h"
#include "transport.h"

void swap(uint32_t *a, uint32_t *b) {
	uint32_t temp = *a;
	*a = *b;
	*b = temp;
}

uint16_t cal_tcp_cksm(struct iphdr iphdr, struct tcphdr tcphdr, uint8_t *pl, int plen)
{
    uint32_t sum = 0;
    // Pseudo IP header (fixed 8 bits is eight bits of zeros)
    int headerlen = tcphdr.doff * 4;
    int segmlen = headerlen + plen;
    sum += (iphdr.saddr >> 16);
    sum += (iphdr.saddr & 0xffff);
    sum += (iphdr.daddr >> 16);
    sum += (iphdr.daddr & 0xffff);
    sum += htons(IPPROTO_TCP);
    sum += htons(segmlen);
    // TCP Header
    uint16_t *tcpheader = (uint16_t *)(void *)&tcphdr;
    while(headerlen >= 2) { 
        sum += *tcpheader;
        tcpheader++;
        headerlen -= 2;
    }
    if(headerlen)
        sum += (*tcpheader) & htons(0xff00);
    //TCP Body
    uint16_t *tcpbody = (uint16_t *)pl;
    while(plen >= 2) {
        sum += *tcpbody;
        tcpbody++;
        plen -= 2;
    }
    if(plen)
        sum += (*tcpbody) & htons(0xff00);
    uint16_t checksum = ~((sum & 0xffff) + (sum >> 16));
    return checksum;
}

uint8_t *dissect_tcp(Net *net, Txp *self, uint8_t *segm, size_t segm_len)
{   // Collect information from segm
    // (Check IP addr & port to determine the next seq and ack value)
    // Return payload of TCP
    struct tcphdr *tcp = (struct tcphdr *)segm;
    memcpy(&(self->thdr), tcp, sizeof(struct tcphdr));
    self->hdrlen = (uint8_t)tcp->doff * 4;
    
    self->plen = segm_len - self->hdrlen;
    self->pl = (uint8_t *)malloc(self->plen * sizeof(uint8_t));
    memcpy(self->pl, segm + self->hdrlen, self->plen);

    if (strcmp(net->x_src_ip, net->dst_ip) == 0) {
        self->x_tx_seq = ntohl(self->thdr.th_ack);
        self->x_tx_ack = ntohl(self->thdr.th_seq) + self->plen;
        self->x_src_port = ntohs(self->thdr.th_dport);
        self->x_dst_port = ntohs(self->thdr.th_sport);
    }

    return self->pl;
}

Txp *fmt_tcp_rep(Txp *self, struct iphdr iphdr, uint8_t *data, size_t dlen)
{   // Fill up self->tcphdr (prepare to send)
    self->thdr.th_sport = htons(self->x_src_port);
    self->thdr.th_dport = htons(self->x_dst_port);
    self->thdr.th_seq = htonl(self->x_tx_seq);
    self->thdr.th_ack = htonl(self->x_tx_ack);
    
    self->hdrlen = sizeof(struct tcphdr);
    self->plen = dlen;
    
    memcpy(self->pl, data, dlen);
    self->thdr.check = 0;
    self->thdr.check = cal_tcp_cksm(iphdr, self->thdr, data, dlen);
    return self;
}

inline void init_txp(Txp *self)
{
    self->pl = (uint8_t *)malloc(IP_MAXPACKET * sizeof(uint8_t));
    self->hdrlen = sizeof(struct tcphdr);

    self->dissect = dissect_tcp;
    self->fmt_rep = fmt_tcp_rep;
}