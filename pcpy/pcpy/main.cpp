#include <pcap.h>

#include "PcapManager.h"

int main(int argc, char *argv[])
{
	PcapManager *pm = new PcapManager();
	
	pm->DevicePrint();

	FILE *fp;
	char ip[80] = "127.0.0.1";
	char mac[80] = "AA:BB:CC:DD:EE:FF"; 
	char interface[80] = "eth0";
	
	if ((fp = fopen("config.dat", "r")) != NULL)
	{
		char buf[80] = {};
		int i = 0;
		while (fgets(buf, sizeof(buf), fp) != NULL)
		{
			for (char* p = buf; p = strchr(p, '\r'); ++p) { *p = '\0'; }
			for (char* p = buf; p = strchr(p, '\n'); ++p) { *p = '\0'; }
			if (++i == 1) strcpy(ip, buf);
			if (i == 2) strcpy(mac, buf);
			if (i == 3) strcpy(interface, buf);
		}
	}

	fprintf(stdout, "\n%s", ip);
	fprintf(stdout, "\n%s", mac);
	fprintf(stdout, "\n%s", interface);

	if (pm->DeviceOpen(interface))
	{
		pm->CopyTo(ip, mac);
	}
}