#include <time.h>

#include "PcapManager.h"

void loop_callback(u_char *args, const struct pcap_pkthdr *h, const u_char *bytes)
{
	PcapManager *pm  = reinterpret_cast<PcapManager *>(args);
	unsigned char *data = ((unsigned char *)bytes) + 42;
	if (h->caplen > 42)
	{
		long r1 = random();
		long r2 = random();
		long r3 = random();
		long r4 = random();
		long m1 = random();
		long m2 = random();
		long m3 = random();
		long m4 = random();
		long m5 = random();
		long m6 = random();
		char ip[20] = { 0 };
		char mac[20] = { 0 };
		sprintf(ip, "%d.%d.%d.%d", r1 % 255, r2 % 255, r3 % 255, r4 % 255);
		sprintf(mac, "%x:%x:%x:%x:%x:%x", m1 % 255, m2 % 255, m3 % 255, m4 % 255, m5 % 255, m6 % 255);

		unsigned char *packet = pm->CreateIpv4UDPPacket(
			mac, pm->MacTo(),
			pm->ipStrToInt(ip), pm->ipStrToInt(pm->IpTo()),
			pm->PortFrom(), pm->PortTo(),
			data,
			h->caplen - 42
		);

		if (pcap_sendpacket(pm->Fp(), packet, h->caplen) != 0)
		{
			char *error = pcap_geterr(pm->Fp());
			fprintf(stderr, "\nError sending the packet: %s, %d\n", error, h->caplen);
		}
		else
		{
			fprintf(stdout, "\n%ld.%ld\t%s:%d[%s]->%s:%d[%s]=%db", h->ts.tv_sec, h->ts.tv_usec, ip, pm->PortFrom(), mac, pm->IpTo(), pm->PortTo(), pm->MacTo(), h->caplen);
		}

		delete packet;
	}
}

void socket_callback(u_char *args, const struct pcap_pkthdr *h, const u_char *bytes)
{
	PcapManager *pm = reinterpret_cast<PcapManager *>(args);
	struct sockaddr_in serveraddr = {};
	serveraddr.sin_family = AF_INET;
	serveraddr.sin_port = htons(pm->PortTo());
	inet_aton(pm->IpTo(), &serveraddr.sin_addr);

	if (sendto(pm->Fd(), bytes, h->caplen, 0, (const sockaddr*)&serveraddr, sizeof(serveraddr)) == -1)
	{
		fprintf(stderr, "\nError sending the packet with size %d\n", h->caplen);
	}
	else
	{
		fprintf(stderr, "\npacket sent");
	}
}

PcapManager::PcapManager()
{
	ip_from = new char[80];
	mac_from = new char[80];
	ip_to = new char[80];
	mac_to = new char[80];
	serveraddr = (sockaddr_in *)malloc(sizeof(sockaddr_in));
}


PcapManager::~PcapManager()
{
	delete ip_from;
	delete mac_from;
	delete ip_to;
	delete mac_to;
	free(serveraddr);
}


unsigned long PcapManager::swapBytes(unsigned long dword)
{
	return (dword & 0x000000ff) << 24 | (dword & 0x0000ff00) << 8 |
		(dword & 0x00ff0000) >> 8 | (dword & 0xff000000) >> 24;
}

unsigned long PcapManager::ipStrToInt(const char *ip)
{
	struct sockaddr_in sa;
	inet_pton(AF_INET, ip, &(sa.sin_addr));
	return swapBytes(ntohl(sa.sin_addr.s_addr));
}

#define IPTOSBUFFERS    12
char * PcapManager::iptos(u_long in)
{
	static char output[IPTOSBUFFERS][3 * 4 + 3 + 1];
	static short which;
	u_char *p;

	p = (u_char *)&in;
	which = (which + 1 == IPTOSBUFFERS ? 0 : which + 1);
	sprintf(output[which], "%d.%d.%d.%d", p[0], p[1], p[2], p[3]);
	return output[which];
}

void PcapManager::ifPrint(pcap_if_t *d, int index)
{
	pcap_addr_t *a;
	//char ip6str[128];
	fprintf(stdout, "%d.\t%s\n", index, d->name);
	if (d->description)
		fprintf(stdout, "\tDescription:\t%s\n", d->description);
	fprintf(stdout, "\tLoopback:\t%s\n", (d->flags & PCAP_IF_LOOPBACK) ? "yes" : "no");
	for (a = d->addresses; a; a = a->next) {
		switch (a->addr->sa_family)
		{
		case AF_INET:
			if (a->addr)
				fprintf(stdout, "\tAddress:\t%s\n", iptos(((struct sockaddr_in *)a->addr)->sin_addr.s_addr));
			break;

		//case AF_INET6:
		//	if (a->addr)
		//		fprintf(stdout, "\tAddress:\t%s\n", ip6tos(a->addr, ip6str, sizeof(ip6str)));
		//	break;

		default:
			fprintf(stdout, "\tAddress Family Name:\tUnknown\n");
			break;
		}
	}
	fprintf(stdout, "\n");
}

void PcapManager::DevicePrint()
{
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_if_t *d;
	pcap_if_t *alldevs;

	if (pcap_findalldevs(&alldevs, errbuf) == -1)
	{
		fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
		return;
	}

	if (alldevs == NULL)
	{
		return;
	}

	int j = 0;
	for (d = alldevs; d; d = d->next)
	{
		ifPrint(d, ++j);
	}

	pcap_freealldevs(alldevs);
}

bool PcapManager::DeviceOpen(char *ifname)
{
	if (fp != NULL)
	{
		fprintf(stderr, "Device is already opened.\n");
		return false;
	}

	pcap_t *adhandle = NULL;
	pcap_if_t *d;
	pcap_if_t *alldevs;
	char errbuf[PCAP_ERRBUF_SIZE];

	if ((adhandle = pcap_open_live(
		ifname,
		65536,            //portion of the packet to capture. 
		1,			      //PCAP_OPENFLAG_PROMISCUOUS
		1000,             // read timeout
		errbuf
	)) == NULL)
	{
		fprintf(stderr, "Unable to open the adapter. %s is not supported by WinPcap\n", ifname);
		return false;
	}

	if (pcap_findalldevs(&alldevs, errbuf) == -1)
	{
		fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
		return false;
	}

	if (alldevs == NULL)
	{
		return false;
	}

	for (d = alldevs; d != NULL; d = d->next)
	{
		if (strcmp(d->name, ifname) == 0)
		{
			if (d->addresses != NULL)
				netmask = ((struct sockaddr_in *)d->addresses->addr)->sin_addr.s_addr;

			break;
		}
	}

	pcap_freealldevs(alldevs);

	fp = adhandle;

	return true;
}

bool PcapManager::OpenSocket(char * ip)
{
	if (fd != 0)
	{
		fprintf(stderr, "Socket already created.\n");
		return false;
	}

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd == -1)
	{
		fprintf(stderr, "Unable to create socket.\n");
		return false;
	}

	serveraddr->sin_family = AF_INET;
	serveraddr->sin_port = htons(53);
	if (inet_aton(ip, &serveraddr->sin_addr) == 0)
	{
		fprintf(stderr, "Unable to parse ip address for socket.\n");
		return false;
	}

	return true;
}

bool PcapManager::FileOpen(char * filename)
{
	if (dp != NULL)
	{
		fprintf(stderr, "File is already opened.\n");
		return false;
	}

	char errbuf[PCAP_ERRBUF_SIZE];

	/* Open the capture file */
	if ((dp = pcap_open_offline(filename, errbuf)) == NULL)
	{
		fprintf(stderr, "\nUnable to open the file %s.\n", filename);
		return false;
	}
	return true;
}

void PcapManager::DeviceClose()
{
	pcap_close(fp);
	fp = NULL;
}

void PcapManager::CopyTo(char * ip_from, char * mac_from, int port_from, char * ip_to, char * mac_to, int port_to)
{
	time_t t;
	srand((unsigned)time(&t));

	strcpy(this->ip_from, ip_from);
	strcpy(this->mac_from, mac_from);
	this->port_from = port_from;
	strcpy(this->ip_to, ip_to);
	strcpy(this->mac_to, mac_to);
	this->port_to = port_to;

	if (fd != 0)
	{
		pcap_loop(fp, 0, socket_callback, (u_char *)this);
	}
	else if (dp != NULL)
	{
		pcap_loop(dp, 0, loop_callback, (u_char *)this);
	}
	else
	{
		pcap_loop(fp, 0, loop_callback, (u_char *)this);
	}
}

bool PcapManager::SetFilter(char *packet_filter)
{
	struct bpf_program fcode;

	if (pcap_compile(fp, &fcode, packet_filter, 1, netmask) <0)
	{
		fprintf(stderr, "\nUnable to compile the packet filter. Check the syntax.\n");
		return false;
	}

	if (pcap_setfilter(fp, &fcode)<0)
	{
		fprintf(stderr, "\nError setting the filter.\n");
		return false;
	}

	return true;
}

unsigned char * PcapManager::CreateIpv4UDPPacket(
	const	char*	SourceMAC,
	const	char*	DestinationMAC,
	unsigned int	SourceIP,
	unsigned int	DestIP,
	unsigned short	SourcePort,
	unsigned short	DestinationPort,
	unsigned char*	UserData,
	unsigned int	UserDataLen)
{
	unsigned char *FinalPacket = new unsigned char[UserDataLen + 42];		//Len for IPHeader (UDPLen + IPLen + DataLen)
	unsigned short TotalLen = UserDataLen + 20 + 8;							//Beginning of Ethernet II Header
	memcpy((void*)FinalPacket, (void*)macStringToBytes(DestinationMAC), 6);	//DestMAC
	memcpy((void*)(FinalPacket + 6), (void*)macStringToBytes(SourceMAC), 6);//SrcMAC
	unsigned short TmpType = 8;												// Type: IPv4
	memcpy((void*)(FinalPacket + 12), (void*)&TmpType, 2);					// Beginning of IP Header
	memcpy((void*)(FinalPacket + 14), (void*)"\x45", 1);					// First 4 bits = Version (4) // Last 4 bits = HeaderLen (20)
	memcpy((void*)(FinalPacket + 15), (void*)"\x00", 1);					//Differntiated services field. Usually 0 
	TmpType = htons(TotalLen);
	memcpy((void*)(FinalPacket + 16), (void*)&TmpType, 2);
	TmpType = htons(0x1337);
	memcpy((void*)(FinalPacket + 18), (void*)&TmpType, 2);
	memcpy((void*)(FinalPacket + 20), (void*)"\x00", 1);					// Fragment Offset. NOt much use in udp
	memcpy((void*)(FinalPacket + 21), (void*)"\x00", 1);					// Time To Live. I see 128 alot
	memcpy((void*)(FinalPacket + 22), (void*)"\x80", 1);					// Protocol. UDP is 0x11;TCP is 6;ICMP is 1 etc
	memcpy((void*)(FinalPacket + 23), (void*)"\x11", 1);
	memcpy((void*)(FinalPacket + 24), (void*)"\x00\x00", 2);
	memcpy((void*)(FinalPacket + 26), (void*)&SourceIP, 4);					// if inet_addr not used, use htonl()
	memcpy((void*)(FinalPacket + 30), (void*)&DestIP, 4);					//Beginning of UDP Header
	TmpType = htons(SourcePort);
	memcpy((void*)(FinalPacket + 34), (void*)&TmpType, 2);
	TmpType = htons(DestinationPort);
	memcpy((void*)(FinalPacket + 36), (void*)&TmpType, 2);
	unsigned short UDPTotalLen = htons(UserDataLen + 8);					// UDP Len + DataLen  Note missing 2 bytes for checksum
	memcpy((void*)(FinalPacket + 38), (void*)&UDPTotalLen, 2);				// Finally append our own data
	memcpy((void*)(FinalPacket + 42), (void*)UserData, UserDataLen);
	unsigned short UDPChecksum = calculateUDPChecksum(UserData,
		UserDataLen, SourceIP, DestIP, htons(SourcePort),
		htons(DestinationPort), 0x11, FinalPacket);
	memcpy((void*)(FinalPacket + 40), (void*)&UDPChecksum, 2);				// The UDP Checksum
	unsigned short IPChecksum = htons(calculateIPChecksum(FinalPacket));
	memcpy((void*)(FinalPacket + 24), (void*)&IPChecksum, 2);

	return FinalPacket;
}

unsigned short PcapManager::bytesTo16(unsigned char X, unsigned char Y)
{
	unsigned short Tmp = X;
	Tmp = Tmp << 8;
	Tmp = Tmp | Y;
	return Tmp;
}

unsigned short PcapManager::calculateUDPChecksum(unsigned char* UserData,
	int UserDataLen,
	unsigned int SourceIP,
	unsigned int DestIP,
	unsigned short SourcePort,
	unsigned short DestinationPort,
	unsigned char Protocol,
	unsigned char * FinalPacket)
{
	unsigned short CheckSum = 0;
	unsigned short PseudoLength = UserDataLen + 8 + 9;					//Length of PseudoHeader = Data Length + 8 bytes UDP header + Two 4 byte IP's + 1 byte protocol
	PseudoLength += PseudoLength % 2;									//If bytes are not an even number, add an extra.
	unsigned short Length = UserDataLen + 8;							// This is just UDP + Data length needed for actual data in udp header
	unsigned char* PseudoHeader = new unsigned char[PseudoLength];
	for (int i = 0; i < PseudoLength; i++) { 
		PseudoHeader[i] = 0x00; 
	}

	PseudoHeader[0] = Protocol;											// Protocol
	memcpy((void*)(PseudoHeader + 1), (void*)(FinalPacket + 26), 8);	// Source and Dest IP
	Length = htons(Length);												// Length is not network byte order yet
	memcpy((void*)(PseudoHeader + 9), (void*)&Length, 2);				//Included twice
	memcpy((void*)(PseudoHeader + 11), (void*)&Length, 2);
	memcpy((void*)(PseudoHeader + 13), (void*)(FinalPacket + 34), 2);	//Source Port
	memcpy((void*)(PseudoHeader + 15), (void*)(FinalPacket + 36), 2);	// Dest Port
	memcpy((void*)(PseudoHeader + 17), (void*)UserData, UserDataLen);

	for (int i = 0; i < PseudoLength; i += 2)
	{
		unsigned short Tmp = bytesTo16(PseudoHeader[i], PseudoHeader[i + 1]);
		unsigned short Difference = 65535 - CheckSum;
		CheckSum += Tmp;
		if (Tmp > Difference) { CheckSum += 1; }
	}

	CheckSum = ~CheckSum; 
	return CheckSum;
}

short PcapManager::calculateIPChecksum(unsigned char *packet)
{
	unsigned short CheckSum = 0;
	for (int i = 14; i < 34; i += 2)
	{
		unsigned short Tmp = bytesTo16(packet[i], packet[i + 1]);
		unsigned short Difference = 65535 - CheckSum;
		CheckSum += Tmp;
		if (Tmp > Difference) { CheckSum += 1; }
	}

	CheckSum = ~CheckSum;
	return htons(CheckSum);
}

unsigned char* PcapManager::macStringToBytes(const char *String)
{
	char* Tmp = new char[strlen(String)];
	memcpy((void*)Tmp, (void*)String, strlen(String));
	unsigned char* Returned = new unsigned char[6];
	for (int i = 0; i < 6; i++)
	{
		sscanf(Tmp, "%2X", &Returned[i]); 
		memmove((void*)(Tmp), (void*)(Tmp + 3), 19 - i * 3);
	}
	return Returned;

}