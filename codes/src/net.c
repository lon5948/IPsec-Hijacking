#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ifaddrs.h>
#include <unistd.h>

#include "net.h"
#include "transport.h"
#include "esp.h"

uint16_t cal_ipv4_cksm(struct iphdr iphdr)
{   // Finish IP checksum calculation
    uint32_t sum = 0;
    uint16_t *ipheader = (uint16_t *)&iphdr;
    size_t headerlen = iphdr.ihl * 4;
    while(headerlen >= 2) {
        sum += *ipheader;
        ipheader++;
        headerlen -= 2;
    }
    if(headerlen)
        sum += (*ipheader) & htons(0xff00);
    while (sum >> 16) 
        sum = (sum & 0xffff) + (sum >> 16);
    uint16_t checksum = ~sum;
    return checksum;
}

uint8_t *dissect_ip(Net *self, uint8_t *pkt, size_t pkt_len)
{   // Collect information from pkt.
    // Return payload of network layer

    struct iphdr *ip = (struct iphdr *)pkt;
    memcpy(&self->ip4hdr, ip, sizeof(struct iphdr));
    
    self->hdrlen = ip->ihl * 4;
    self->plen = ntohs(ip->tot_len) - self->hdrlen;
    self->pro = (Proto)ip->protocol;

    inet_ntop(AF_INET, &(ip->saddr), self->src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip->daddr), self->dst_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip->saddr), self->x_dst_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip->daddr), self->x_src_ip, INET_ADDRSTRLEN);

    return pkt + self->hdrlen;
}

Net *fmt_net_rep(Net *self)
{   // Fill up self->ip4hdr (prepare to send
    inet_pton(AF_INET, self->x_src_ip, &(self->ip4hdr.saddr));
    inet_pton(AF_INET, self->x_dst_ip, &(self->ip4hdr.daddr));
    self->ip4hdr.tot_len = htons(self->plen + self->hdrlen);
    self->ip4hdr.check = 0;
    self->ip4hdr.check = cal_ipv4_cksm(self->ip4hdr);
    return self;
}

void init_net(Net *self)
{
    if (!self) {
        fprintf(stderr, "Invalid arguments of %s.", __func__);
        exit(EXIT_FAILURE);
    }

    self->src_ip = (char *)malloc(INET_ADDRSTRLEN * sizeof(char));
    self->dst_ip = (char *)malloc(INET_ADDRSTRLEN * sizeof(char));
    self->x_src_ip = (char *)malloc(INET_ADDRSTRLEN * sizeof(char));
    self->x_dst_ip = (char *)malloc(INET_ADDRSTRLEN * sizeof(char));
    self->hdrlen = sizeof(struct iphdr);

    self->dissect = dissect_ip;
    self->fmt_rep = fmt_net_rep;
}