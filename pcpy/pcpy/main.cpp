#include <pcap.h>

#include "PcapManager.h"


int main(int argc, char *argv[])
{
	PcapManager *pm = new PcapManager();
	
	pm->DevicePrint();
	int index = 1;
	//fprintf(stdout, "\nSelect interface: ");
	//scanf("%d", &index);

	char ip[80] = "172.24.1.181";
	fprintf(stdout, "\n%s", ip);
	//scanf("Enter IP to copy to: %s", &ip);
	char mac[80] = "aa-bb-cc-dd-ee-ff";
	fprintf(stdout, "\n%s", mac);
	//scanf("Enter mac to copy to: %s", &mac);


	if (pm->DeviceOpen(index))
	{
		pm->CopyTo(ip, mac);
	}
}