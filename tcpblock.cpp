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



uint16_t calc(uint16_t * data, int len) {
	uint16_t result;
	int tmp = 0;
	int length;
	bool flag = false;
	if ((len % 2) == 0)
		length = len / 2;
	else {
		length = (len / 2) + 1;
		flag = true;
	}

	for (int i = 0; i < length; ++i) {
		if (i == length - 1 && flag)
			tmp += ntohs(data[i] & 0x00ff);
		else
			tmp += ntohs(data[i]);
		if (tmp > 65536)
			tmp = (tmp - 65536) + 1;
	}
	result = tmp;
	return result;
}


uint16_t ip_checksum(uint8_t * ip_packet , uint8_t len){
    uint32_t sum = 0;
    for(int i=0; i<len;i++){
        sum+=ip_packet[i];
    }
    uint16_t res=(sum>>16)+(sum&0xffff);
    return ~res;
}


uint16_t tcp_checksum(uint8_t * ip_packet, int len) { //https://slowknight.tistory.com/4 참고
	struct pseudo_header pseh;
	struct ip_header * iph = (struct ip_header *)ip_packet;
	struct tcp_header * tcph = (struct tcp_header *)(ip_packet + 20);

	memcpy(&pseh.src_IP, &iph->ip_src, sizeof(pseh.src_IP));
	memcpy(&pseh.dest_IP, &iph->ip_dst, sizeof(pseh.dest_IP));
	pseh.protocol = iph->ip_p;
	pseh.tcp_len = htons(len - (20));

	uint16_t pseudoResult = calc((uint16_t *)&pseh, sizeof(pseh));

	tcph->th_sum = 0;
	uint16_t tcpHeaderResult = calc((uint16_t *)tcph, ntohs(pseh.tcp_len));

	uint16_t checksum;

	int tempCheck;
	if ((tempCheck = pseudoResult + tcpHeaderResult) > 65536)
		checksum = (tempCheck - 65536) + 1;
	else
		checksum = tempCheck;

	checksum = ntohs(~checksum);
	tcph->th_sum = checksum;

	return checksum;
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
	packet_ip->ip_sum = htons(ip_checksum((packet + 14),ip_len));
	packet_tcp->th_sum = 0;
	packet_tcp->th_sum = htons(tcp_checksum(packet + 14, ntohs(packet_ip->ip_len)));
    
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
	packet_ip->ip_sum =htons(ip_checksum((packet + 14),ip_len));
	packet_tcp->th_sum = 0;
	packet_tcp->th_sum = htons(tcp_checksum(packet + 14, ntohs(packet_ip->ip_len)));
	pcap_sendpacket(handle, packet, 14 + ntohs(packet_ip->ip_len));
}


