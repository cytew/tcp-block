#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

#include <arpa/inet.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <sys/ioctl.h> 
#include <sys/socket.h>
#include <sys/types.h>

#include <unistd.h>
#include <cstring>
#include <cstdio>
#include <pcap.h>

#include "mac.h"
#include "ip.h"
#include "ethhdr.h"
#include "arphdr.h"

#include "tcpblock.h"

#define MAC_ALEN 6

extern Mac my_Mac;
extern Ip my_Ip;


Mac GetMyMacAddr(const char* ifname){ //https://tttsss77.tistory.com/138
    
    struct ifreq ifr;
    int sockfd, ret;
	uint8_t macAddr[MAC_ALEN];
    
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if(sockfd < 0) {
        fprintf(stderr, "Fail to get interface MAC address - socket() failed - %m\n");
        exit(0);
    }

    strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
    ret = ioctl(sockfd, SIOCGIFHWADDR, &ifr);
    if (ret < 0) {
        fprintf(stderr, "Fail to get interface MAC address - ioctl(SIOCSIFHWADDR) failed - %m\n");
        close(sockfd);
        exit(0);
    }

    close(sockfd);
    
    memcpy(macAddr, ifr.ifr_hwaddr.sa_data, MAC_ALEN);
    return macAddr;
}


Ip GetMyIp(const char* ifname){
    struct ifreq ifr;
    int sockfd, ret;
    char ipAddr[40];

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if(sockfd < 0) {
        fprintf(stderr, "Fail to get interface MAC address - socket() failed - %m\n");
        exit(0);
    }

    strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
    ret = ioctl(sockfd, SIOCGIFADDR, &ifr);
    if (ret < 0) {
        fprintf(stderr, "Fail to get interface MAC address - ioctl(SIOCSIFADDR) failed - %m\n");
        close(sockfd);
        exit(0);
    }

    close(sockfd);
    inet_ntop(AF_INET, ifr.ifr_addr.sa_data+2, ipAddr, sizeof(struct sockaddr));
    //change network info to char LE
	//sockaddr: 2byte family 14byte IP+Port

    return Ip(ipAddr);
}


uint16_t ip_checksum(uint8_t * ip_packet , uint8_t len){
	uint16_t *pIpH = (uint16_t *)ip_packet;
    uint32_t checksum = 0;
	uint16_t res;
	int length;
	length = len / 2;
    for(int i=0; i<length;i++){
        checksum += *pIpH++;
    }
    checksum=(checksum>>16)+(checksum&0xffff);
	checksum += (checksum >> 16);

	res = (~checksum & 0xffff);
    return res;
}


uint16_t tcp_checksum(struct ip_header * packet_ip) { //https://slowknight.tistory.com/4 참고

	uint16_t *iph = (uint16_t*)packet_ip;
	uint16_t * tcph =(uint16_t*)(packet_ip + 20);
	uint16_t * tmp;

	uint16_t dataLen = (ntohs( packet_ip->ip_len )) - 20;
	uint16_t nLen = dataLen;
	uint16_t checksum=0;
	uint16_t res=0;

	nLen = nLen/2;

	for( int i = 0; i < nLen; i++ ) { 
		checksum += *tcph++;
	}

	if( dataLen % 2 == 1 ){
		checksum += *tcph++ & 0x00ff;
	}

	tmp = (uint16_t*) (&packet_ip->ip_src);
	for( int i = 0; i < 2; i ++ ){
		checksum += *tmp++;
	}
	tmp = (uint16_t*) (&packet_ip->ip_dst);
	for( int i = 0; i < 2; i ++ ){
		checksum += *tmp++;
	}

	checksum += htons(6);
	checksum += htons(dataLen);

	checksum=(checksum>>16)+(checksum&0xffff);
	checksum += (checksum >> 16);

	res = (~checksum & 0xffff);
    return res;
}


void forward_rst(pcap_t * handle, uint8_t* pkt) {
    int ip_len = 20;

	struct ip_header * rcvpacket_ip = (struct ip_header *)(pkt + 14);
	struct tcp_header * rcvpacket_tcp = (struct tcp_header *)(pkt + 14 + ip_len);

    
	int tcp_len = (((rcvpacket_tcp->th_len) & 0xf0) >> 4) *4;
	int http_len = ntohs(rcvpacket_ip->ip_len) - ip_len - tcp_len;


	uint8_t packet[14 + ip_len + tcp_len];
    struct ether_header * packet_ether = (struct ether_header *)(packet);
	struct ip_header * packet_ip = (struct ip_header *)(packet + 14);
	struct tcp_header * packet_tcp = (struct tcp_header *)(packet + 14 + ip_len);
	
	memcpy(packet, pkt, 14 + ip_len + tcp_len);
	memcpy(packet_ether->src_mac, my_Mac, 6);


	packet_ip->ip_len = htons(ip_len + tcp_len);

    
	packet_tcp->th_seq = htonl(ntohl(rcvpacket_tcp->th_seq) + http_len);
    packet_tcp->th_ack = rcvpacket_tcp->th_ack;
    
    packet_tcp->th_flags = 0x14;
    
	packet_ip->ip_sum = 0;
	packet_ip->ip_sum = (ip_checksum((packet + 14),ip_len));
	packet_tcp->th_sum = 0;
	packet_tcp->th_sum = htons(tcp_checksum(packet_ip));
    
	pcap_sendpacket(handle, packet, 14 + ntohs(packet_ip->ip_len));
}

void backward_fin(pcap_t * handle, uint8_t * pkt, const char * data) {
    int ip_len = 20;

	struct ip_header * rcvpacket_ip = (struct ip_header *)(pkt + 14);
	struct tcp_header * rcvpacket_tcp = (struct tcp_header *)(pkt + 14 + ip_len);
    struct ether_header * rcvpacket_ether = (struct ether_header *)(pkt);

	int tcp_len = (((rcvpacket_tcp->th_len) & 0xf0) >> 4) *4;
	int http_len = ntohs(rcvpacket_ip->ip_len) - ip_len - tcp_len;

	uint8_t packet[14 + ip_len + tcp_len + strlen(data)];
	struct ip_header * packet_ip = (struct ip_header *)(packet + 14);
	struct tcp_header * packet_tcp = (struct tcp_header *)(packet + 14 + ip_len);
	struct ether_header * packet_ether = (struct ether_header *)(packet);

	
	memcpy(packet, pkt, 14 + ip_len + tcp_len);
	memcpy(packet_ether->dest_mac, rcvpacket_ether->src_mac, 6);
	memcpy(packet_ether->src_mac, my_Mac, 6);

	packet_ip->ip_src = rcvpacket_ip->ip_dst;
	packet_ip->ip_dst = rcvpacket_ip->ip_src;

	packet_tcp->th_sport = rcvpacket_tcp->th_dport;
	packet_tcp->th_dport = rcvpacket_tcp->th_sport;

	memcpy(packet + 14 + ip_len + tcp_len, data, strlen(data));

	packet_ip->ip_len = htons(ip_len + tcp_len + strlen(data));
	packet_ip->ip_ttl = 128;

	packet_tcp->th_flags = 0x11;
	packet_tcp->th_seq = rcvpacket_tcp->th_ack;
	packet_tcp->th_ack = htonl((ntohl(rcvpacket_tcp->th_seq) + http_len)+1);

	packet_ip->ip_sum = 0;
	packet_ip->ip_sum =(ip_checksum((packet + 14),ip_len));
	packet_tcp->th_sum = 0;
	packet_tcp->th_sum = htons(tcp_checksum(packet_ip));
	pcap_sendpacket(handle, packet, 14 + ntohs(packet_ip->ip_len));
}


