#include <pcap.h>

#include "PcapManager.h"

int main(int argc, char *argv[])
{
	PcapManager *pm = new PcapManager();
	
	pm->DevicePrint();

	FILE *fp;
	char ip_from[80] = "127.0.0.1";
	char mac_from[80] = "AA:BB:CC:DD:EE:FF";
	char port_from[80] = "53";
	char ip_to[80] = "127.0.0.1";
	char mac_to[80] = "AA:BB:CC:DD:EE:FF";
	char port_to[80] = "53";
	char interface[80] = "eth0";
	char filter[80] = "udp";
	char replayfile[255] = "";
	char socket[255] = "";

	if (argc == 10)
	{
		strcpy(ip_from, argv[1]);
		strcpy(mac_from, argv[2]);
		strcpy(port_from, argv[3]);
		strcpy(ip_to, argv[1]);
		strcpy(mac_to, argv[2]);
		strcpy(port_to, argv[3]);
		strcpy(interface, argv[4]);
		strcpy(filter, argv[5]);
		strcpy(replayfile, argv[6]);
		strcpy(socket, argv[7]);
	}
	else if ((fp = fopen("config.dat", "r")) != NULL)
	{
		char buf[80] = {};
		int i = 0;
		while (fgets(buf, sizeof(buf), fp) != NULL)
		{
			for (char* p = buf; p = strchr(p, '\r'); ++p) { *p = '\0'; }
			for (char* p = buf; p = strchr(p, '\n'); ++p) { *p = '\0'; }
			if (++i == 1) strcpy(ip_from, buf);
			if (i == 2) strcpy(mac_from, buf);
			if (i == 3) strcpy(port_from, buf);
			if (i == 4) strcpy(ip_to, buf);
			if (i == 5) strcpy(mac_to, buf);
			if (i == 6) strcpy(port_to, buf);
			if (i == 7) strcpy(interface, buf);
			if (i == 8) strcpy(filter, buf);
			if (i == 9) strcpy(replayfile, buf);
			if (i == 10) strcpy(socket, buf);
		}
	}

	char * env_ip_from = getenv("IPF");
	char * env_mac_from = getenv("MACF");
	char * env_port_from = getenv("PORTF");
	char * env_ip_to = getenv("IPT");
	char * env_mac_to = getenv("MACT");
	char * env_port_to = getenv("PORTT");
	char * env_interface = getenv("INTERFACE");
	char * env_filter = getenv("FILTER");
	char * env_replay = getenv("REPLAY");
	char * env_socket = getenv("SOCKET");
	if (env_ip_from) strcpy(ip_from, env_ip_from);
	if (env_mac_from) strcpy(mac_from, env_mac_from);
	if (env_port_from) strcpy(port_from, env_port_from);
	if (env_ip_to) strcpy(ip_to, env_ip_to);
	if (env_mac_to) strcpy(mac_to, env_mac_to);
	if (env_port_to) strcpy(port_to, env_port_to);
	if (env_interface) strcpy(interface, env_interface);
	if (env_filter) strcpy(filter, env_filter);
	if (env_replay) strcpy(replayfile, env_replay);
	if (env_socket) strcpy(socket, env_socket);

	int iport_from = atoi(port_from);
	int iport_to = atoi(port_to);

	fprintf(stderr, "FROM IP:\t%s\tMAC:\t%s\tPORT:\t%s\n", ip_from, mac_from, port_from);
	fprintf(stderr, "TO   IP:\t%s\tMAC:\t%s\tPORT:\t%s\n", ip_to, mac_to, port_to);
	fprintf(stderr, "IFACE:\t%s\n", interface);
	fprintf(stderr, "FILTER:\t%s\n", filter);
	fprintf(stderr, "REPLAY:\t%s\n", replayfile);
	fprintf(stderr, "SOCKET:\t%s\n", socket);

	if (strlen(replayfile) > 0)
	{
		if (pm->FileOpen(replayfile))
		{
			fprintf(stderr, "replay file opened");
		}
	}

	if (strlen(socket) > 0)
	{
		if (pm->OpenSocket(socket))
		{
			fprintf(stderr, "socket opened");
		}
	}

	if (pm->DeviceOpen(interface))
	{
		if (pm->SetFilter(filter))
		{
			fprintf(stderr, "Filter %s applied.\n", filter);
		}

		pm->CopyTo(ip_from, mac_from, iport_from, ip_to, mac_to, iport_to);
	}
	else
	{
		fprintf(stderr, "failed to open %s\n", interface);
	}
}