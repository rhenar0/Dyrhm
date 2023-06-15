#include <stdio.h>
#include <pcap/pcap.h>
#include <getopt.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/ip_icmp.h>

pcap_t* handle; // Session handle
pcap_dumper_t* pcap_dumper; // Pcap buffer
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

    switch (linktype)
    {
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

pcap_t* create_pcap_handle(char* device, char* filter) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = NULL;
    struct bpf_program bpf;
    bpf_u_int32 netmask;
    bpf_u_int32 srcip;

    // Open pcap file for writing
    handle = pcap_open_dead(DLT_EN10MB, BUFSIZ);
    if (handle == NULL) {
        fprintf(stderr, "pcap_open_dead() failed\n");
        return NULL;
    }

    // Create the pcap file dumper
    pcap_dumper = pcap_dump_open(handle, "output.pcap");
    if (pcap_dumper == NULL) {
        fprintf(stderr, "pcap_dump_open() failed\n");
        pcap_close(handle);
        return NULL;
    }

    // Conversion packet filter
    if (pcap_compile(handle, &bpf, filter, 0, netmask) == PCAP_ERROR) {
        fprintf(stderr, "pcap_compile(): %s\n", pcap_geterr(handle));
        pcap_dump_close(pcap_dumper);
        pcap_close(handle);
        return NULL;
    }

    // Set the packet filter
    if (pcap_setfilter(handle, &bpf) == PCAP_ERROR) {
        fprintf(stderr, "pcap_setfilter(): %s\n", pcap_geterr(handle));
        pcap_dump_close(pcap_dumper);
        pcap_close(handle);
        return NULL;
    }

    return handle;
}

void packet_handler(u_char *user, const struct pcap_pkthdr *packethdr, const u_char *packetptr) {
    struct ip* iphdr;
    struct icmp* icmphdr;
    char iphdrInfo[256];
    char srcip[256];
    char dstip[256];
    char *typeICMP;

    // Get IP header
    packetptr += linkhdrlen;
    iphdr = (struct ip*)packetptr;
    strcpy(srcip, inet_ntoa(iphdr -> ip_src));
    strcpy(dstip, inet_ntoa(iphdr->ip_dst));
    sprintf(iphdrInfo, "ID:%d TOS:0x%x TTL:%d", ntohs(iphdr->ip_id), iphdr->ip_tos, iphdr->ip_ttl, 4*iphdr->ip_hl, ntohs(iphdr->ip_len));

    //Transport layer ICMP
    packetptr += 4*iphdr->ip_hl;
    switch (iphdr->ip_p) {
        case IPPROTO_ICMP:
            icmphdr = (struct icmp*)packetptr;
            printf("ICMP %s -> %s\n", srcip, dstip);
            printf("%s\n", iphdrInfo);
            if(icmphdr->icmp_type == ICMP_ECHOREPLY) {
                typeICMP = "Echo Reply";
            } else if (icmphdr->icmp_type == ICMP_ECHO) {
                typeICMP = "Echo Request";
            } else {
                typeICMP = "Unknown";
            }
            printf("Type:%d (%s) Code:%d ID:%d Seq:%d Chk:%d\n", icmphdr->icmp_type, typeICMP, icmphdr->icmp_code, ntohs(icmphdr->icmp_hun.ih_idseq.icd_id), ntohs(icmphdr->icmp_hun.ih_idseq.icd_seq), ntohs(icmphdr->icmp_cksum));
            printf("+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+\n");
            packets += 1;
            break;
    }

    // Write the packet to the pcap file
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
    pcap_dump_close(pcap_dumper);
    exit(0);
}

int main(int argc, char *argv[]) {

    char device[256];
    char filter[256];
    int count = 0;
    int opt;

    *device = 0;
    *filter = 0;

    printf("ICMP Sniffer\n");
    printf("============\n");

    while ((opt = getopt(argc, argv, "hi:n:f:")) != -1) {
        switch (opt) {
            case 'h':
                printf("Usage: %s [-i interface] [-n number of packets] [filter]\n", argv[0]);
                return 0;
            case 'i':
                strcpy(device, optarg);
                break;
            case 'n':
                count = atoi(optarg);
                break;
            default:
                printf("Usage: %s [-i interface] [-n number of packets] [filter]\n", argv[0]);
                return 0;
        }
    }

    printf("Sniffing on device %s\n", device);

    for (int i = optind; i < argc; i++) {
        strcat(filter, argv[i]);
        strcat(filter, " ");
    }

    signal(SIGINT, stop_capture);
    signal(SIGTERM, stop_capture);
    signal(SIGQUIT, stop_capture);

    printf("The job will be outputed in output.pcap\n");

    handle = create_pcap_handle(device, filter);
    if (handle == NULL) {
        return -1;
    }

    get_link_header_len(handle);
    if (linkhdrlen == 0) {
        return -1;
    }

    if (pcap_loop(handle, count, packet_handler, (u_char*)NULL) < 0){
        fprintf(stderr, "pcap_loop() failed: %s\n", pcap_geterr(handle));
        return -1;
    }

    stop_capture(0);
    printf("The job is done.\n");
    return 0;
}
