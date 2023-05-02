#include <iostream>
#include <pcap.h>
#include <winsock2.h>
#include <ctime>
#include <map>
#include <vector>
#include <chrono>

#define HAVE_REMOTE
#include "pcap.h"

using namespace std;

struct packetInfo {
    const char *devName;
    int packCount;
};

vector<packetInfo> devList;

void packet_handler(u_char *user, const struct pcap_pkthdr *header, const u_char *packet) {
    packetInfo *devStats = (packetInfo *)user;
    devStats->packCount++;
}

int main() {
    pcap_if_t *alldevices;
    pcap_if_t *d;

    char errbuf[PCAP_ERRBUF_SIZE];

    if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevices, errbuf) == -1) {
        cerr << "Error finding pcap_findalldevs_ex: " << errbuf << endl;
        return 1;
    }

    cout << "Your devices listed below: " << endl;

    vector<pcap_t *> handles;
    for (d = alldevices; d != NULL; d = d->next) {
        cout << d->name << " - " << (d->description ? d->description : "No description available") << endl;

        pcap_t *handle = pcap_open_live(d->name, BUFSIZ, 1, 1000, errbuf);
        if (handle == NULL) {
            fprintf(stderr, "Error opening device %s: %s\n", d, errbuf);
        } else {
            handles.push_back(handle);
        }
    }

    for (int i = 0; i < handles.size(); i++) {
        pcap_t *currHandle = handles[i];
        const char *currDev = alldevices[i].name;

        packetInfo devStats;
        devStats.devName = currDev;
        devStats.packCount = 0;

        if (pcap_setnonblock(currHandle, 1, errbuf) == -1) {
            cerr << "Error setting non-blocking mode for " << currDev << ": " << errbuf << endl;
            continue;
        }

        auto start = chrono::steady_clock::now();
        int captureDuration = 3; // Duration in seconds

        while (chrono::steady_clock::now() - start < chrono::seconds(captureDuration)) {
            pcap_dispatch(currHandle, 1, packet_handler, (u_char *)&devStats);
        }

        devList.push_back(devStats);
        pcap_close(currHandle);

    }
    pcap_freealldevs(alldevices);
    cout << "Device list with packet counts:" << endl;
    for (int i = 0; i < devList.size(); i++) {
        cout << i + 1 << ". " << devList[i].devName << " - " << devList[i].packCount << endl;
    }

    return 0;
}
