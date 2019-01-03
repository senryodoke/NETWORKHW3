#include<netinet/in.h>
#include<stdio.h>
#include<string.h>
#include<stdlib.h>
#include<pcap.h>
#include<sys/socket.h>
#include<time.h>
#include<arpa/inet.h>
#define SIZE_ETHERNET 14
#define ETHER_ADDR_LEN  6
struct sniff_ethernet {
	u_char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
	u_char ether_shost[ETHER_ADDR_LEN]; /* Source host address */
	u_short ether_type; /* IP? ARP? RARP? etc */
};
struct sniff_ip {
	u_char ip_vhl;      /* version << 4 | header length >> 2 */
	u_char ip_tos;      /* type of service */
	u_short ip_len;     /* total length */
	u_short ip_id;      /* identification */
	u_short ip_off;     /* fragment offset field */
#define IP_RF 0x8000        /* reserved fragment flag */
#define IP_DF 0x4000        /* dont fragment flag */
#define IP_MF 0x2000        /* more fragments flag */
#define IP_OFFMASK 0x1fff   /* mask for fragmenting bits */
	u_char ip_ttl;      /* time to live */
	u_char ip_p;        /* protocol */
	u_short ip_sum;     /* checksum */
	struct in_addr ip_src;
	struct in_addr ip_dst; /* source and dest address */
};
#define IP_HL(ip)       (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)        (((ip)->ip_vhl) >> 4)
struct sniff_tcp {
	u_short th_sport;   /* source port */
	u_short th_dport;   /* destination port */
	u_int32_t th_seq;       /* sequence number */
	u_int32_t th_ack;
	u_char th_offx2;    /* data offset, rsvd */
#define TH_OFF(th)  (((th)->th_offx2 & 0xf0) >> 4)
	u_char th_flags;
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0x80
#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
	u_short th_win;     /* window */
	u_short th_sum;     /* checksum */
	u_short th_urp;     /* urgent pointer */
};
int main(int argc, char *argv[])
{
	if(argc<2){
		printf("need filename\n");
		return 0;
	}
	const char *filter = "";
	if(argc == 3) {
		filter = argv[2];
	}//end if
	char *filename = argv[1];
	char errbuff[PCAP_ERRBUF_SIZE];
	char a[INET_ADDRSTRLEN],b[INET_ADDRSTRLEN];
	pcap_t * handler = pcap_open_offline(filename, errbuff);
	if(!handler) {
		fprintf(stderr, "pcap_open_offline(): %s\n", errbuff);
		exit(1);
	}//end if
	printf("Open: %s\n", filename);
	struct pcap_pkthdr *header;
	const u_char *packet;   
	int packetCount = 0;
	int i;
	//tcp info
	const struct sniff_ethernet *ethernet; /* The ethernet header */
	const struct sniff_ip *ip; /* The IP header */
	const struct sniff_tcp *tcp; /* The TCP header */
	char tmbuf[100];
	time_t at;
	struct tm *nat;
	u_int size_ip;
	u_int size_tcp;
	struct bpf_program fcode;
	if(-1 == pcap_compile(handler, &fcode, filter, 1, PCAP_NETMASK_UNKNOWN)) {
		fprintf(stderr, "pcap_compile(): %s\n", pcap_geterr(handler));
		pcap_close(handler);
		exit(1);
	}//end if

	if(strlen(filter) != 0) {
		printf("Filter: %s\n", filter);
	}//end if
	while (pcap_next_ex(handler, &header, &packet) >= 0)
	{
		if(pcap_offline_filter(&fcode, header, packet) != 0) { 
			// Show the packet number
			printf("Packet # %i\n", ++packetCount);
			// Show the size in bytes of the packet
			printf("Packet size: %d bytes\n", header->len);
			// Show a warning if the length captured is different
			if (header->len != header->caplen)
				printf("Warning! Capture size different than packet size: %d bytes\n", header->len);
			// Show Epoch Time
			at=header->ts.tv_sec;
			nat=localtime(&at);
			strftime(tmbuf,sizeof(tmbuf),"%Y-%m-%d %H:%M:%S",nat);
			printf("Time: %s . %06ldms \n", tmbuf, header->ts.tv_usec);
			ethernet = (struct sniff_ethernet*)(packet);
			ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
			size_ip = IP_HL(ip)*4;
			if (size_ip < 20) {
				printf("   * Invalid IP header length: %u bytes\n", size_ip);
				return 0;
			}
			tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);

			printf("src port: %d dest port: %d \n", tcp->th_sport, tcp->th_dport);
			inet_ntop(AF_INET,&(ip->ip_src),a,INET_ADDRSTRLEN);
			inet_ntop(AF_INET,&(ip->ip_dst),b,INET_ADDRSTRLEN);
			printf("src address: %s dest address: %s \n",  a,  b);
			printf("\n");
		}
	}
	return 0;
}

