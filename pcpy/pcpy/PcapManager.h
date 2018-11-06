#pragma once

#include <stdio.h>
#include <pcap.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>

class PcapManager
{
protected:
	pcap_t * fp;
	char *ip;
	char *mac;

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
	bool DeviceOpen(int inum);
	void CopyTo(char * ip, char * mac);
	unsigned long ipStrToInt(const char *ip);

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
