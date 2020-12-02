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

Mac my_Mac;
Ip my_Ip;

const char* HTTP_METHOD[] = { "GET","POST","HEAD","PUT","DELETE","OPTIONS" };


void usage() {
	printf("syntax : tcp-block <interface> <pattern>\n");
	printf("sample : tcp-block wlan0 \"Host: test.gilgil.net\"\n");
}


int main(int argc, char* argv[]) {
	
	if (argc !=3 ){
		usage();
		return -1;
	}

	char* dev = argv[1];
	char * block_site = argv[2];
	char errbuf[PCAP_ERRBUF_SIZE];
	char warning[7] = "block!";

    struct pcap_pkthdr * header;

	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}
	
    my_Mac=GetMyMacAddr(dev);
    my_Ip=GetMyIp(dev);

	printf("My Mac Addr: %s\n",my_Mac.operator std::string().c_str());
	printf("My Ip Addr: %s\n",my_Ip.operator std::string().c_str()); //c_str: exchange string to char*

    uint8_t * pkt;
	while (1) {
		int res = pcap_next_ex(handle, &header, (const u_char **)&pkt);
		if (res == 0) continue;
		if (res == -1 || res == -2) {
			pcap_close(handle);
            printf("Error1\n");
			return 0;
		}

		int ip_len = 20;
		struct ether_header * packet_ether = (struct ether_header *)pkt;
		struct ip_header * packet_ip = (struct ip_header *)(pkt + 14);
		struct tcp_header * packet_tcp = (struct tcp_header *)(pkt + 14 + ip_len);
		int tcp_len = (((packet_tcp->th_len) & 0xf0) >> 4) *4;
		int http_len = ntohs(packet_ip->ip_len) - ip_len - tcp_len;


		uint8_t * packet_http = pkt + 14 + ip_len + tcp_len;
		
		int i;
		for ( i = 0; i < 6; ++i) {
			if (memcmp(HTTP_METHOD[i], packet_http, strlen(HTTP_METHOD[i])) != 0)
				break;
		}

		if (i == 6) continue;
		for (i = 0; i < http_len - 6; i++) {
			if (!memcmp(packet_http + i, "Host: ", 6)) {
				if (!memcmp(packet_http + i + 6, block_site, strlen(block_site))) {
					forward_rst(handle, pkt);
					backward_fin(handle, pkt, warning);
				}
			}
		}
	}
	pcap_close(handle);
	return 0;
}
