#include <stdio.h>
#include <pcap/pcap.h>
#include <getopt.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/ip_icmp.h>

pcap_t* handle; // Session handle
int linkhdrlen; // Link layer type
int packets;

#define SIGTERM 15
#define SIGINT 2
#define SIGQUIT 3
#define ICMP_ECHOREPLY 0
#define ICMP_ECHO 8

void get_link_header_len(pcap_t* handle) {
    int linktype;

    if ((linktype = pcap_datalink(handle)) == PCAP_ERROR) {
        fprintf(stderr, "pcap_datalink() failed: %s\n", pcap_geterr(handle));
        return;
    }

    switch (linktype) {
        case DLT_NULL:
            linkhdrlen = 4;
            break;

        case DLT_PPP:
            linkhdrlen = 4;
            break;

        case DLT_EN10MB:
            linkhdrlen = 14;
            break;

        default:
            printf("Unsupported link type %d\n", linktype);
            linkhdrlen = 0;
    }
}

void packet_handler(u_char* user, const struct pcap_pkthdr* packethdr, const u_char* packetptr) {
    struct ip* iphdr;
    struct icmp* icmphdr;
    char iphdrInfo[256];
    char srcip[256];
    char dstip[256];
    char* typeICMP;

    // Get IP header
    packetptr += linkhdrlen;
    iphdr = (struct ip*)packetptr;
    strcpy(srcip, inet_ntoa(iphdr->ip_src));
    strcpy(dstip, inet_ntoa(iphdr->ip_dst));
    sprintf(iphdrInfo, "ID:%d TOS:0x%x TTL:%d", ntohs(iphdr->ip_id), iphdr->ip_tos, iphdr->ip_ttl, 4 * iphdr->ip_hl, ntohs(iphdr->ip_len));

    // Transport layer ICMP
    packetptr += 4 * iphdr->ip_hl;
    switch (iphdr->ip_p) {
        case IPPROTO_ICMP:
            icmphdr = (struct icmp*)packetptr;
            printf("ICMP %s -> %s\n", srcip, dstip);
            printf("%s\n", iphdrInfo);
            if (icmphdr->icmp_type == ICMP_ECHOREPLY) {
                typeICMP = "Echo Reply";
            } else if (icmphdr->icmp_type == ICMP_ECHO) {
                typeICMP = "Echo Request";
            } else {
                typeICMP = "Unknown";
            }
            printf("Type:%d (%s) Code:%d ID:%d Seq:%d Chk:%d\n", icmphdr->icmp_type, typeICMP,
                   icmphdr->icmp_code, ntohs(icmphdr->icmp_hun.ih_idseq.icd_id),
                   ntohs(icmphdr->icmp_hun.ih_idseq.icd_seq), ntohs(icmphdr->icmp_cksum));
            printf("+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+\n");
            packets += 1;
            break;
    }

    // Retrieve the pcap_dumper_t handle from user data
    pcap_dumper_t* pcap_dumper = (pcap_dumper_t*)user;

    // Dump the packet to the pcap file
    pcap_dump((u_char*)pcap_dumper, packethdr, packetptr);
}

void stop_capture(int signo) {
    struct pcap_stat stats;
    pcap_t* pd = handle;

    if (pcap_stats(pd, &stats) >= 0) {
        printf("\n%d packets captured\n", packets);
        printf("%d packets received\n", stats.ps_recv);
        printf("%d packets dropped\n", stats.ps_drop);
    }
    pcap_close(pd);
    exit(0);
}

pcap_t* create_pcap_handle(char* device, char* filter) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = NULL;
    pcap_if_t* devices = NULL;
    struct bpf_program bpf;
    bpf_u_int32 netmask;
    bpf_u_int32 srcip;

    // If no device is specified, take the first one from the list
    if (!*device) {
        if (pcap_findalldevs(&devices, errbuf) < 0) {
            fprintf(stderr, "pcap_findalldevs() failed: %s\n", errbuf);
            return NULL;
        }
        strcpy(device, devices[0].name);
    }

    // Obtain the device source IP and netmask
    if (pcap_lookupnet(device, &srcip, &netmask, errbuf) == PCAP_ERROR) {
        fprintf(stderr, "pcap_lookupnet() failed: %s\n", errbuf);
        return NULL;
    }

    // Open device in promiscuous mode to get the MAC address
    pcap_t* promisc_handle = pcap_open_live(device, BUFSIZ, 1, 1000, errbuf);
    if (promisc_handle == NULL) {
        fprintf(stderr, "pcap_open_live(): %s\n", errbuf);
        return NULL;
    }

    // Get the MAC address
    struct pcap_addr* addresses;
    if (pcap_findalldevs_addresses(promisc_handle, &addresses, errbuf) == PCAP_ERROR) {
        fprintf(stderr, "pcap_findalldevs_addresses() failed: %s\n", errbuf);
        pcap_close(promisc_handle);
        return NULL;
    }
    struct pcap_addr* address = addresses;
    if (address && address->addr && address->addr->sa_family == AF_LINK) {
        struct sockaddr_dl* sdl = (struct sockaddr_dl*)address->addr;
        memcpy(mac_address, LLADDR(sdl), sdl->sdl_alen);
    }
    pcap_freealldevs_addresses(addresses);
    pcap_close(promisc_handle);

    // Open device capture handle
    handle = pcap_create(device, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "pcap_create() failed: %s\n", errbuf);
        return NULL;
    }

    // Set promiscuous mode
    if (pcap_set_promisc(handle, 1) != 0) {
        fprintf(stderr, "pcap_set_promisc() failed: %s\n", pcap_geterr(handle));
        pcap_close(handle);
        return NULL;
    }

    // Set MAC address filter
    if (pcap_set_rfmon(handle, 0) != 0) {
        fprintf(stderr, "pcap_set_rfmon() failed: %s\n", pcap_geterr(handle));
        pcap_close(handle);
        return NULL;
    }
    if (pcap_set_snaplen(handle, 65535) != 0) {
        fprintf(stderr, "pcap_set_snaplen() failed: %s\n", pcap_geterr(handle));
        pcap_close(handle);
        return NULL;
    }
    if (pcap_activate(handle) != 0) {
        fprintf(stderr, "pcap_activate() failed: %s\n", pcap_geterr(handle));
        pcap_close(handle);
        return NULL;
    }

    // Compile and set the packet filter
    if (pcap_compile(handle, &bpf, filter, 0, netmask) == PCAP_ERROR) {
        fprintf(stderr, "pcap_compile(): %s\n", pcap_geterr(handle));
        pcap_close(handle);
        return NULL;
    }

    if (pcap_setfilter(handle, &bpf) == PCAP_ERROR) {
        fprintf(stderr, "pcap_setfilter(): %s\n", pcap_geterr(handle));
        pcap_close(handle);
        return NULL;
    }

    return handle;
}



int main(int argc, char* argv[]) {

    char device[256];
    char filter[256];
    int count = 0;
    int opt;

    pcap_dumper_t* pcap_dumper = NULL;  // pcap_dumper_t handle for pcap file
    char* nameFile;

    *device = 0;
    *filter = 0;

    printf("ICMP Sniffer\n");
    printf("============\n");

    while ((opt = getopt(argc, argv, "hi:n:f:")) != -1) {
        switch (opt) {
            case 'h':
                printf("Usage: %s [-i interface] [-n number of packets] [-f output file] [filter]\n", argv[0]);
                return 0;
            case 'i':
                strcpy(device, optarg);
                break;
            case 'f':
                nameFile = optarg;
                break;
            case 'n':
                count = atoi(optarg);
                break;
            default:
                fprintf(stderr, "Unknown option: %c\n", optopt);
                return 1;
        }
    }

    // Get the packet filter expression (if any)
    if (optind < argc) {
        strncpy(filter, argv[optind], sizeof(filter) - 1);
    }

    // Create the pcap handle
    handle = create_pcap_handle(device, filter);
    if (handle == NULL) {
        return 1;
    }

    // Create the pcap_dumper_t handle for writing packets to a pcap file
    pcap_dumper = pcap_dump_open(handle, nameFile);
    if (pcap_dumper == NULL) {
        fprintf(stderr, "pcap_dump_open() failed: %s\n", pcap_geterr(handle));
        pcap_close(handle);
        return 1;
    }

    // Get the link layer header length
    get_link_header_len(handle);

    // Register the signal handler to stop the capture
    signal(SIGINT, stop_capture);
    signal(SIGQUIT, stop_capture);
    signal(SIGTERM, stop_capture);

    // Start capturing packets
    if (pcap_loop(handle, count, packet_handler, (u_char*)pcap_dumper) < 0) {
        fprintf(stderr, "pcap_loop() failed: %s\n", pcap_geterr(handle));
        pcap_dump_close(pcap_dumper);
        pcap_close(handle);
        return 1;
    }

    // Close the pcap_dumper_t handle
    pcap_dump_close(pcap_dumper);

    // Close the pcap handle
    pcap_close(handle);

    return 0;
}
