#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <ctype.h>
#include <string.h>

struct ethheader {
    u_char  ether_dhost[6];
    u_char  ether_shost[6];
    u_short ether_type;
};

struct ipheader {
    unsigned char      iph_ihl:4,
                       iph_ver:4;
    unsigned char      iph_tos;
    unsigned short int iph_len;
    unsigned short int iph_ident;
    unsigned short int iph_flag:3,
                       iph_offset:13;
    unsigned char      iph_ttl;
    unsigned char      iph_protocol;
    unsigned short int iph_chksum;
    struct  in_addr    iph_sourceip;
    struct  in_addr    iph_destip;
};

struct tcpheader {
    u_short tcp_sport;
    u_short tcp_dport;
    u_int   tcp_seq;
    u_int   tcp_ack;
    u_char  tcp_offx2;
#define TH_OFF(th)      (((th)->tcp_offx2 & 0xf0) >> 4)
    u_char  tcp_flags;
    u_short tcp_win;
    u_short tcp_sum;
    u_short tcp_urp;
};

void print_mac(const u_char *mac) {
    for (int i = 0; i < 6; i++) {
        printf("%02X", mac[i]);
        if (i < 5) printf(":");
    }
}

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    struct ethheader *eth = (struct ethheader *)packet;
    if (ntohs(eth->ether_type) != 0x0800) return;

    struct ipheader *ip = (struct ipheader *)(packet + sizeof(struct ethheader));
    if (ip->iph_protocol != IPPROTO_TCP) return;

    int ip_header_len = ip->iph_ihl * 4;
    struct tcpheader *tcp = (struct tcpheader *)(packet + sizeof(struct ethheader) + ip_header_len);
    int tcp_header_len = TH_OFF(tcp) * 4;

    const u_char *payload = packet + sizeof(struct ethheader) + ip_header_len + tcp_header_len;
    int payload_len = ntohs(ip->iph_len) - ip_header_len - tcp_header_len;

    printf("\n===== PACKET CAPTURED =====\n");

    printf("[Ethernet Header]\n");
    printf("   Src MAC : "); print_mac(eth->ether_shost); printf("\n");
    printf("   Dst MAC : "); print_mac(eth->ether_dhost); printf("\n");

    printf("[IP Header]\n");
    printf("   Src IP  : %s\n", inet_ntoa(ip->iph_sourceip));
    printf("   Dst IP  : %s\n", inet_ntoa(ip->iph_destip));

    printf("[TCP Header]\n");
    printf("   Src Port: %d\n", ntohs(tcp->tcp_sport));
    printf("   Dst Port: %d\n", ntohs(tcp->tcp_dport));

    printf("[Payload] ");
    if (payload_len > 0) {
        int to_print = payload_len > 30 ? 30 : payload_len;
        for (int i = 0; i < to_print; i++) {
            if (isprint(payload[i]))
                printf("%c", payload[i]);
            else
                printf(".");
        }
        printf("\n");
    } else {
        printf("No message.\n");
    }

    printf("===========================\n");
}

int main() {
    char *dev = "eth0";
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;

    struct bpf_program fp;
    char filter_exp[] = "tcp";
    bpf_u_int32 net;

    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return 2;
    }

    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Bad filter - %s\n", pcap_geterr(handle));
        return 2;
    }

    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter - %s\n", pcap_geterr(handle));
        return 2;
    }

    printf("Listening on %s...\n", dev);
    pcap_loop(handle, 0, got_packet, NULL);

    pcap_close(handle);
    return 0;
}
