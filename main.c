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
            printf("Data : %s\n", icmphdr->icmp_dun.id_data);
            printf("+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+\n");
            packets += 1;
            break;
    }
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
    pcap_t  *handle = NULL;
    pcap_if_t* devices = NULL;
    struct bpf_program bpf;
    bpf_u_int32 netmask;
    bpf_u_int32 srcip;

    // Si aucun device n'est spécifié, on prend le premier de la liste
    if (!*device) {
        if (pcap_findalldevs(&devices, errbuf) < 0) {
            fprintf(stderr, "pcap_findalldevs() failed: %s\n", errbuf);
            return NULL;
        }
        strcpy(device, devices[0].name);
    }

    // Obtenir le device src IP et netmask
    if (pcap_lookupnet(device, &srcip, &netmask, errbuf) == PCAP_ERROR) {
        fprintf(stderr, "pcap_lookupnet() failed: %s\n", errbuf);
        return NULL;
    }

    // Open device live capture
    handle = pcap_open_live(device, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "pcap_open_live(): %s\n", errbuf);
        return NULL;
    }

    // Conversion packet filter
    if (pcap_compile(handle, &bpf, filter, 0, netmask) == PCAP_ERROR) {
        fprintf(stderr, "pcap_compile(): %s\n", pcap_geterr(handle));
        return NULL;
    }

    // Appliquer le filtre
    if (pcap_setfilter(handle, &bpf) == PCAP_ERROR) {
        fprintf(stderr, "pcap_setfilter(): %s\n", pcap_geterr(handle));
        return NULL;
    }

    return handle;
}

int main(int argc, char *argv[]) {

    char device[256];
    char filter[256];
    int count = 0;
    int opt;

    *device = 0;
    *filter = 0;

    while ((opt = getopt(argc, argv, "hi:n:")) != -1) {
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

    for (int i = optind; i < argc; i++) {
        strcat(filter, argv[i]);
        strcat(filter, " ");
    }

    signal(SIGINT, stop_capture);
    signal(SIGTERM, stop_capture);
    signal(SIGQUIT, stop_capture);

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
    return 0;
}
