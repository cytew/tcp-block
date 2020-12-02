#pragma once

Mac GetMyMacAddr(const char* ifname);
Ip GetMyIp(const char* ifname);


struct pseudo_header {
	uint32_t src_IP;
	uint32_t dest_IP;
	uint8_t reserved = 0;
	uint8_t protocol;
	uint16_t tcp_len;
};

struct ether_header {
	uint8_t dest_mac[6];
	uint8_t src_mac[6];
	uint16_t type;

};

struct ip_header
{
    u_int8_t ip_v:4,       /* version */
           ip_hl:4;        /* header length */
    u_int8_t ip_tos;       /* type of service */
    u_int16_t ip_len;         /* total length */
    u_int16_t ip_id;          /* identification */
    u_int16_t ip_off;
    u_int8_t ip_ttl;          /* time to live */
    u_int8_t ip_p;            /* protocol */
    u_int16_t ip_sum;         /* checksum */
    u_int32_t ip_src, ip_dst; /* source and dest address */
};


struct tcp_header
{
    u_int16_t th_sport;       /* source port */
    u_int16_t th_dport;       /* destination port */
    u_int32_t th_seq;          /* sequence number */
    u_int32_t th_ack;          /* acknowledgement number */
    u_int8_t th_len;         /* tcp length*/
    u_int8_t  th_flags;       /* control flags */
    u_int16_t th_win;         /* window */
    u_int16_t th_sum;         /* checksum */
    u_int16_t th_urp;         /* urgent pointer */
};

void forward_rst(pcap_t * handle, uint8_t * pkt);
void backward_fin(pcap_t * handle, uint8_t * pkt, const char * data);
uint16_t ip_checksum(uint8_t * ip_packet);
uint16_t tcp_checksum(uint8_t * ip_packet, int ip_len);