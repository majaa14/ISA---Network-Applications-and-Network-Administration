/*
** VUT FIT ISA projekt
** varianta: Monitorování DHCP komunikace
** autor: Marie Pařilová
** login: xparil05
** datum: 17.10.2023
** soubor: zdrojový soubor dhcp-stats.c
*/

#include <syslog.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <errno.h>
#include <err.h>
#include <ncurses.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h> 
#include <math.h>

#ifndef PCAP_ERRBUF_SIZE
#define PCAP_ERRBUF_SIZE (256)
#endif

#define ETHERNET_HEADER (14)

/* Struktura pro prefixy */
typedef struct {
    char ip_address[20];        // max delka IPv4 prefixu
    int prefix_length;          // delka prefixu
    int max_hosts;              // maximalni pocet adres
    int allocated_addresses;    // pocet alokovanych adres
    double utilization;         // vytizeni prefixu
    bool log_written;           // hlidani zapisu do logu, aby se zbytecne nevypisoval vickrat
} IP_Prefix;

IP_Prefix prefixes[1000];
int num_prefixes = 0;

/* Pomocna funkce pro vypocet vytizenosti prefixu*/
int calculate_utilization(IP_Prefix *prefix) {
    return (prefix->utilization = ((double)prefix->allocated_addresses / prefix->max_hosts) * 100.0);
}

/* Funkce pro zjisteni, zda patri IP adresa do prefixu*/
int is_ip_in_prefix(const char *ip_address, const char *prefix) {
    struct in_addr ip, network, mask;

    const char* original_prefix = prefix;
    char* mutable_prefix = strdup(original_prefix);

    /* Prevedeni IP adresy na sitovy format */
    if (inet_pton(AF_INET, ip_address, &ip) <= 0) {
        perror("inet_pton");
        return 1;
    }

    /* Rozdeleni na adresu a delku */
    char* token = strtok(mutable_prefix, "/");
    if (token == NULL) {
        return 1;
    }

    /* Prevedeni sitove adresy a masky na sit. format */
    if (inet_pton(AF_INET, token, &network) <= 0) {
        perror("inet_pton");
        return 1;
    }

    token = strtok(NULL, "/");
    if (token == NULL) {
        return 1;
    }

    /* Tvorba sit. masky z delky prefixu */
    int prefix_length = atoi(token);
    mask.s_addr = htonl(~((1u << (32 - prefix_length)) - 1u));

    free(mutable_prefix);

    /* Porovnani */
    return (ip.s_addr & mask.s_addr) == (network.s_addr & mask.s_addr);
}

/* Funkce pro aktualizaci statistiky */
void updateStatistics(const char* ipAddress) {
    for (int i = 0; i < num_prefixes; i++) {
        /* Pokud IP adresa patri do prefixu, pricteme prefixu alokovanou adresu (+1) */
        if (is_ip_in_prefix(ipAddress, prefixes[i].ip_address)) {
            if (prefixes[i].allocated_addresses != prefixes[i].max_hosts) {
                prefixes[i].allocated_addresses++;
                prefixes[i].utilization = calculate_utilization(&prefixes[i]);
            }
            mvprintw(1+i, 0, "%s %d %d %.2f%%\n",
                    prefixes[i].ip_address,
                    prefixes[i].max_hosts, 
                    prefixes[i].allocated_addresses,
                    prefixes[i].utilization);
            refresh();

            /* Vetev pro hlidani vytizeni vetsi nez 50 % */
            if(prefixes[i].utilization > 50.0) {
                /* Hlidame, aby se log nevypisoval vicekrat pro stejny prefix */
                if(prefixes[i].log_written == false)
                {
                    /* Zapis do logu */
                    syslog(LOG_NOTICE, "Prefix %s exceeded 50%% of allocations\n", prefixes[i].ip_address);
                    prefixes[i].log_written = true;
                }
            }
        }
    }
}

/* Funkce pro tisk vyslednych statistik */
void print_statistics(IP_Prefix *prefixes, int num_prefixes) {

    for (int i = 0; i < num_prefixes; i++) {

        mvprintw(1+i, 0, "%s %d %d %.2f%%\n",
            prefixes[i].ip_address,
            prefixes[i].max_hosts, 
            prefixes[i].allocated_addresses,
            prefixes[i].utilization);

        /* zobraz obsah obrazovky na terminal */
        refresh();
    }
}

/* Funkce pro zjisteni IP adresy a typu zpravy z DHCP paketu */
void dhcp_parser(const uint8_t *options, int len) {
    int position = 0;
        /* Prochazime DHCP zpravu*/
        while (position < len) {
            int option_code = options[position];
            /* Hledame moznost 53 obsahujici informaci o typu zpravy */
            if (option_code == 53) {
                int option_length = options[position + 1];
                /* Delka moznosti 53 je 1 */
                if (option_length == 1) {
                    /* Typ zpravy se nachazi na prislusnych bytech DHCP zpravy */
                    int message_type = options[position + 2];
                    /* Typ zpravy musi byt 5 = ACK (potvrzeni uspesneho prideleni adresy) */
                    if(message_type == 5)
                    {
                        /* IP adresa se nachazi na prislusnych bytech DHCP zpravy */
                        uint32_t ip_address = *(uint32_t*)(options + 16);
                        struct in_addr ip_addr;
                        ip_addr.s_addr = (ip_address);
                        /* Kontrola adresy, jestli spada do nejakeho ze zadanych prefixu */
                        updateStatistics(inet_ntoa(ip_addr));
                    }
                }
            }
            position++;
        }
}

/* 
Následující funkce analyze_udp a analyze_ip jsou inspirované ze souboru read-pcap.c dostupný z: https://moodle.vut.cz/pluginfile.php/707807/mod_folder/content/0/pcap/read-pcap.c?forcedownload=1
Autor: Matoušek Petr doc. Ing. Ph.D., M.A.
*/

/* Funkce analyzy UDP paketu */
void analyze_udp(const u_char *packet) {
    const struct udphdr *my_udp = (const struct udphdr*)packet;
    int udp_header_size = sizeof(struct udphdr);
    /* Analyzujeme UDP porty (67 a 68 jsou standartni porty pro DHCP) */
    if (ntohs(my_udp->source) == 67 || ntohs(my_udp->dest) == 68) {
        /* Spoustime analyzu obsahu DHCP zpravy bez UDP hlavicky */
        dhcp_parser(packet + udp_header_size, ntohs(my_udp->len) - udp_header_size);
    }
    return;
}

/* Funkce pro analyzu IP adresy */
void analyze_ip(const u_char *packet){
    u_int header_len;
    struct ip* my_ip;

    my_ip = (struct ip*) (packet);
    header_len = my_ip->ip_hl*4;

    switch (my_ip->ip_p){
        case IPPROTO_UDP:                       // UDP protokol = 17
            analyze_udp(packet + header_len);
            break;
        default: 
            break;
    }
    return;
}

int main(int argc, char *argv[]) {

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle; 
    char *file = NULL;
    char *interface = NULL;
    char *token;
    char *prefix_len;
    uint32_t mask;

    openlog("dhcp-stats", LOG_CONS | LOG_PID | LOG_NDELAY, LOG_LOCAL1);

    /* Kontrola poctu argumentu */
    if (argc < 2) {
        fprintf(stderr, "Usage: %s [-r <filename>] [-i <interface-name>] <ip-prefix> [<ip-prefix> ...]\n", argv[0]);
        return 1;
    }

    /* Zpracovani argumentu */
    int opt;
    while ((opt = getopt(argc, argv, "r:i:")) != -1) {
        switch (opt) {
            case 'r':
                file = optarg;
                // otevreni souboru
                if ((handle = pcap_open_offline(file, errbuf)) == NULL)
                    err(1, "Can't open file %s for reading\n", file);
                break;
            case 'i':
                interface = optarg;
                // "otevreni" rozhrani
                if ((handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf)) == NULL)
                    err(1, "Can't open %s\n", interface);
                break;
            default:
                fprintf(stderr, "Usage: %s [-r <filename>] [-i <interface-name>] <ip-prefix> [<ip-prefix> ...]\n", argv[0]);
                return 1;
        }
    }

    /* Zpracovani zadanych IP prefixu */
    if (optind == argc) {
        fprintf(stderr, "Usage: %s [-r <filename>] [-i <interface-name>] <ip-prefix> [<ip-prefix> ...]\n", argv[0]);
        return 1;
    }
    for (int i = optind; i < argc; i++) {
        num_prefixes++;
        token = strtok(argv[i], "/");
        prefix_len = NULL;
        /* Rozdeleni na adresu a masku */
            while (token != NULL) {
                prefix_len = token;
                token = strtok(NULL, "/");
            }
            /* Kontrola delky prefixu */
            if (prefix_len != NULL) {
                int prefix_length = atoi(prefix_len);
                if (prefix_length < 0 || prefix_length > 31) {
                    return 1;
                }
                else {
                    /* Vypocet maximalniho poctu hostovskych IP adres */
                    int maxHosts = pow(2, (32 - prefix_length)) - 2;
                    char prefix[20];
                    /* Pridani prefixu do struktury IP_Prefix */
                    sprintf(prefix, "%s/%d", argv[i], prefix_length);
                    strcpy(prefixes[i - optind].ip_address, prefix);
                    prefixes[i - optind].prefix_length = prefix_length;
                    prefixes[i - optind].max_hosts = maxHosts;
                    prefixes[i - optind].allocated_addresses = 0;
                    prefixes[i - optind].utilization = 0.0;
                    prefixes[i - optind].log_written = false;
                }
            } 
            else {
                fprintf(stderr, "Invalid IP Prefix format: %s\n", argv[i]);
                return 1;
            }
    }

    /* inicializace ncurses */
    initscr();
    noecho();
    cbreak();
    curs_set(0);

    /* vymaz obrazovku */
    clear();

    mvprintw(0, 0, "IP-Prefix Max-hosts Allocated addresses Utilization\n");

    /* Cteni souboru/rozhrani */
    int n = 0;
    const u_char *packet;
    struct pcap_pkthdr header;
    struct ether_header *eptr;

    /* 
    Následující cyklus while je inspirován ze souboru read-pcap.c dostupný z: https://moodle.vut.cz/pluginfile.php/707807/mod_folder/content/0/pcap/read-pcap.c?forcedownload=1
    Autor: Matoušek Petr doc. Ing. Ph.D., M.A.
    */

    while ((packet = pcap_next(handle,&header)) != NULL){
        n++;
        /* Cteni ethernetove hlavicky */
        eptr = (struct ether_header *) packet;

        switch (ntohs(eptr->ether_type)){
            case ETHERTYPE_IP:    // zajima nas IPv4
            /* Spusteni analyzy IP adresy */
            analyze_ip(packet+ETHERNET_HEADER);
            break;
        }
    }

    /* Zavreni souboru/rozhrani */
    pcap_close(handle);

    /* Vysledny tisk statistik */
    print_statistics(prefixes, num_prefixes);
    
    /* Zavreni logu */
    closelog();

    /* Obnoveni okna */
    refresh();

    (void) getchar();

    /* Zavreni okna */
    endwin();

    return 0;
}