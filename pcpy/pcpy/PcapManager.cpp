#include "PcapManager.h"

void loop_callback(u_char *args, const struct pcap_pkthdr *h, const u_char *bytes)
{
	PcapManager *pm  = reinterpret_cast<PcapManager *>(args);
	unsigned char * packet = pm->CreateIpv4UDPPacket(
		pm->Mac(), pm->Mac(),
		pm->ipStrToInt(pm->Ip()), pm->ipStrToInt(pm->Ip()),
		8080, 8080,
		(unsigned char *)bytes,
		h->caplen
	);

	int size = h->caplen + 42;
	if (pcap_sendpacket(pm->Fp(), packet, size) != 0)
	{
		char *error = pcap_geterr(pm->Fp());
		fprintf(stderr, "\nError sending the packet: %s\n", error);
	}

	delete packet;
}

PcapManager::PcapManager()
{
	ip = new char[80];
	mac = new char[80];
}


PcapManager::~PcapManager()
{
	delete ip;
	delete mac;
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
	return /*swapBytes(*/ntohl(sa.sin_addr.s_addr)/*)*/;
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
	char ip6str[128];
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

bool PcapManager::DeviceOpen(int inum)
{
	if (fp != NULL)
	{
		fprintf(stderr, "Device is already opened.");
		return false;
	}

	pcap_t *adhandle = NULL;
	pcap_if_t *d;
	pcap_if_t *alldevs;
	int i = 0;
	char errbuf[PCAP_ERRBUF_SIZE];

	if (pcap_findalldevs(&alldevs, errbuf) == -1)
	{
		fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
		return false;
	}
	int j = 0;
	for (d = alldevs; d; d = d->next)
	{
		++j;
	}

	if (inum < 1 || inum > j)
	{
		fprintf(stdout, "\nInterface number out of range.\n");
		pcap_freealldevs(alldevs);
		return false;
	}

	for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++);
	if ((adhandle = pcap_open_live(
		d->name,
		65536,            //portion of the packet to capture. 
		1,			      //PCAP_OPENFLAG_PROMISCUOUS
		1000,             // read timeout
		errbuf            
	)) == NULL)
	{
		fprintf(stderr, "\nUnable to open the adapter. %s is not supported by WinPcap\n", d->name);
		pcap_freealldevs(alldevs);
		return false;
	}

	pcap_freealldevs(alldevs);

	fp = adhandle;

	return true;
}

void PcapManager::DeviceClose()
{
	pcap_close(fp);
	fp = NULL;
}

void PcapManager::CopyTo(char * ip, char * mac)
{
	strcpy(this->ip, ip);
	strcpy(this->mac, mac);

	pcap_loop(fp, 0, loop_callback, (u_char *)this);
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