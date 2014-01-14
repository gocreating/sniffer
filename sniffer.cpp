#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/if_arp.h>
#include <linux/ip.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <iostream>

using namespace std;

struct ethhdr *hdr_ether;
struct iphdr  *hdr_ip;

void decodeIPPacket(unsigned char *buffer, int size) {
	hdr_ip = (struct iphdr*)buffer;

	printf("\trcvlen:%4d\t", size);

	int version = hdr_ip->version;
	printf("version: %d\n\t", version);
	switch (version) {
		case 4:
			printf("header length: %d\t", hdr_ip->ihl);

			struct in_addr ip_addr;
			ip_addr.s_addr = hdr_ip->saddr;
			printf("%s -> ", inet_ntoa(ip_addr));
			ip_addr.s_addr = hdr_ip->daddr;
			printf("%s\t", inet_ntoa(ip_addr));
			break;
		case 6:
			break;
		default:
			printf("Exception");
	};
	printf("\n");
}

void decodeEtherFrame(unsigned char *buffer, int size) {
	hdr_ether = (struct ethhdr*)buffer;

	printf("rcvlen:%4d\t", size);

	// source MAC address
	printf("%02X:%02X:%02X:%02X:%02X:%02X",
		hdr_ether->h_source[0], hdr_ether->h_source[1], hdr_ether->h_source[2], hdr_ether->h_source[3], hdr_ether->h_source[4], hdr_ether->h_source[5]);

	printf(" -> ");

	// destination MAC address
	printf("%02X:%02X:%02X:%02X:%02X:%02X\t",
		hdr_ether->h_dest[0], hdr_ether->h_dest[1], hdr_ether->h_dest[2], hdr_ether->h_dest[3], hdr_ether->h_dest[4], hdr_ether->h_dest[5]);

	// EtherType
	// Deal with endian
	int etherType = ((int)buffer[12] << 8) + buffer[13];
	switch (etherType) {
		case 0x0800:
			printf("IPv4\n");
			decodeIPPacket(&buffer[ETH_HLEN], size - ETH_HLEN);
			break;
		case 0x0806:
			printf("ARP\n");
			break;
		case 0x86DD:
			printf("IPv6\n");
			decodeIPPacket(&buffer[ETH_HLEN], size - ETH_HLEN);
			break;
		default:
			printf("EtherType 0x%04X", etherType);
	};

	printf("\n");
}

int main() {
	int sListen = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

	if (sListen == -1) {
		cout << "Invalid socket" << endl;
		perror("listener: socket");
		return 0;
	}

	while (true) {
		unsigned char buffer[ETH_FRAME_LEN]; // buffer for ethernet frame
		int length = 0; // length of the received frame
		length = recvfrom(sListen, buffer, ETH_FRAME_LEN, 0, NULL, NULL);
		if (length == -1) {
			// error handling
		} else {
			// cout << buffer << endl;
			decodeEtherFrame(buffer, length);
		}
	}

	close(sListen);

	return 0;
}
