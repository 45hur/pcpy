#include <pcap.h>

#include "PcapManager.h"


int main(int argc, char *argv[])
{
	PcapManager *pm = new PcapManager();
	
	pm->DevicePrint();
	int index = 1;
	//fprintf(stdout, "\nSelect interface: ");
	//scanf("%d", &index);

	char ip[80] = "213.220.230.170";
	fprintf(stdout, "\n%s", ip);
	//scanf("Enter IP to copy to: %s", &ip);
	char mac[80] = "00:08:9B:CB:F0:CF";
	fprintf(stdout, "\n%s", mac);
	//scanf("Enter mac to copy to: %s", &mac);


	if (pm->DeviceOpen(index))
	{
		pm->CopyTo(ip, mac);
	}
}