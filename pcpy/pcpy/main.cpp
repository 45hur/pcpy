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
	char filter[80] = "udp";
	char replayfile[255] = "";

	if (argc == 6)
	{
		strcpy(ip, argv[1]);
		strcpy(mac, argv[2]);
		strcpy(interface, argv[3]);
		strcpy(filter, argv[4]);
		strcpy(replayfile, argv[5]);
	}
	else if ((fp = fopen("config.dat", "r")) != NULL)
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
			if (i == 4) strcpy(filter, buf);
			if (i == 5) strcpy(replayfile, buf);
		}
	}

	char * env_ip = getenv("IP");
	char * env_mac = getenv("MAC");
	char * env_interface = getenv("INTERFACE");
	char * env_filter = getenv("FILTER");
	char * env_replay = getenv("REPLAY");
	if (env_ip) strcpy(ip, env_ip);
	if (env_mac) strcpy(mac, env_mac);
	if (env_interface) strcpy(interface, env_interface);
	if (env_filter) strcpy(filter, env_filter);
	if (env_replay) strcpy(replayfile, env_replay);

	fprintf(stderr, "\n%s", ip);
	fprintf(stderr, "\n%s", mac);
	fprintf(stderr, "\n%s", interface);
	fprintf(stderr, "\n%s", filter);
	fprintf(stderr, "\n%s", replayfile);

	if (strlen(replayfile) > 0)
	{
		pm->FileOpen(replayfile);
	}

	if (pm->DeviceOpen(interface))
	{
		if (pm->SetFilter(filter))
		{
			fprintf(stderr, "\nFilter %s applied.\n", filter);
		}

		pm->CopyTo(ip, mac);
	}
	else
	{
		fprintf(stderr, "\nfailed to open %s", interface);
	}
}