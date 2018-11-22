#pragma once

#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>

#define PCAP_BUF_SIZE 1024
#define PCAP_OPENFLAG_PROMISCUOUS 1
#define PCAP_SRC_FILE 2

class PcapManager
{
protected:
	pcap_t * fp = NULL;
	pcap_t * dp = NULL;
	u_int netmask = 0xffffff;
	char *ip = NULL;
	char *mac = NULL;

	unsigned long swapBytes(unsigned long dword);
	char * iptos(u_long in);
	void ifPrint(pcap_if_t *d, int index);
	unsigned short bytesTo16(unsigned char X, unsigned char Y);
	unsigned short calculateUDPChecksum(unsigned char* UserData,
		int UserDataLen,
		unsigned int SourceIP,
		unsigned int DestIP,
		unsigned short SourcePort,
		unsigned short DestinationPort,
		unsigned char Protocol,
		unsigned char * FinalPacket);
	short calculateIPChecksum(unsigned char *packet);
	unsigned char* macStringToBytes(const char *String);


public:
	PcapManager();
	~PcapManager();

	char *Ip() { return ip; }
	char *Mac() { return mac; }
	pcap_t *Fp() { return fp; }

	void DevicePrint();
	void DeviceClose();
	bool DeviceOpen(char * ifname);
	bool FileOpen(char * filename);
	void CopyTo(char * ip, char * mac);
	unsigned long ipStrToInt(const char *ip);
	bool SetFilter(char *packet_filter);
	unsigned char * CreateIpv4UDPPacket(
		const	char*	SourceMAC,
		const	char*	DestinationMAC,
		unsigned int	SourceIP,
		unsigned int	DestIP,
		unsigned short	SourcePort,
		unsigned short	DestinationPort,
		unsigned char*	UserData,
		unsigned int	UserDataLen);
};
