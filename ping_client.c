#include <sys/types.h>
#include <sys/time.h>

#include <netinet/in.h>

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <errno.h>
#include <arpa/inet.h>
#include <netdb.h>
int w_drop=40, c_drop=80,c_wait=800,w_wait=200;

void help(void) __attribute__ ((noreturn));

void help(void)
{
fprintf(stderr,"Use: ping_client [-b size{32}] [-i interval{3s}] [-T times{180s}]"
		"[ -w warning_{wait,lost}{%dms,%d%%}] [-c critical_{wait,lost}{%dms,%d%%}"
		" [-P pingserver{127.0.0.1:19988}] [ -H host ] [host]\n",
			w_wait,w_drop,c_wait,c_drop);
exit(2);
}

char *a_msg=NULL;
char *a_host = NULL;

void my_alarm(int s) {
	printf(a_msg ? a_msg : "ERR: ping server timeout %s\n",a_host);
	exit(2);
}


static char *parse_host_port(struct sockaddr_in *addr,char *str) {
char *p,*e;
int r;
p = strchr(str,':');
if(p) *p = 0;
bzero(addr,sizeof(*addr));
addr->sin_family = AF_INET;
r = inet_pton(AF_INET,str,&addr->sin_addr);
if(p) *p++ = ':';
if(r < 0) return NULL;
if(p) {
	addr->sin_port = htons(strtol(p,&e,10) & 0xffff);
	return e;
}
p = str;
while(*p && *p != ',') p++;
return p;
}

void parse_ms_proc(int *ms,int *prc,char *buf) {
char *c = strchr(buf,',');
if(c) {
	*c++ = 0;
	*ms = atoi(buf);
	*prc = atoi(c);
} else {
	*prc = atoi(buf);
}
}

int parse_answer(char *buf,char *rhost) {
char *c,*eq,*a[10]={NULL,};
int i,a_s=0,a_r=0,a_e=0,a_c=0,a_av=0,a_min=0,a_max=0,a_st=0,ret = 0,drop;

if(strncmp(buf,"OK",2)) {
	printf("ERROR: not ok! '%.128s'\n",buf);
	return 2;
}

/*
 OK PHOST=10.200.2.1 RUN=19 AVG=241 MIN=184 MAX=441 STATE=0 CHG=0 SEND=6 RECV=6 ERR=0

 OK - 10.200.2.1: rta 0.187ms, lost 0%|rta=0.187ms;200.000;500.000;0; pl=0%;40;80;; rtmax=0.265ms;;;; rtmin=0.110ms;;;;
 */

if(strstr(buf,"ACTIVE=")) {
	printf("%s\n",buf);
	return 0;
}

for(c = strtok(buf," \t"), i = 0; c && i < 16; i++,c = strtok(NULL," \t") ) {
    if(!strcmp(c,"OK")) continue;

    if(!strncmp(c,"NEW",3)) {
	printf("OK - %s: new\n",rhost);
	return 0;
    }
    eq=strchr(c,'=');
    if(!eq) {
	    printf("ERROR\n");
	    return 2;
    }
    *eq++ = 0;
    if(!strcmp(c,"PHOST")) {
	    rhost = eq;
	    continue;
    }
    if(!strcmp(c,"RUN")) {
	    a[0] = eq;
	    continue;
    }
    if(!strcmp(c,"AVG")) {
	    a[1] = eq;
	    a_av = atoi(eq);
	    continue;
    }
    if(!strcmp(c,"MIN")) {
	    a[2] = eq;
	    a_min = atoi(eq);
	    continue;
    }
    if(!strcmp(c,"MAX")) {
	    a[3] = eq;
	    a_max = atoi(eq);
	    continue;
    }
    if(!strcmp(c,"STATE")) {
	    a[4] = eq;
	    a_st = atoi(eq);
	    continue;
    }
    if(!strcmp(c,"CHG")) {
	    a[5] = eq;
	    a_c = atoi(eq);
	    continue;
    }
    if(!strcmp(c,"SEND")) {
	    a[6] = eq;
	    a_s = atoi(eq);
	    continue;
    }
    if(!strcmp(c,"RECV")) {
	    a[7] = eq;
	    a_r = atoi(eq);
	    continue;
    }
    if(!strcmp(c,"ERR")) {
	    a[8] = eq;
	    a_e = atoi(eq);
	    continue;
    }
}
for(i=0; i <= 8; i++) 
	if(!a[i]) { printf("ERROR\n"); return 2; }
eq = "UNKNOWN";
drop = 100 - a_r*100/(a_s > 0 ? a_s:1); 
do {
  switch(a_st) {
   case 0:
	if(!a_e && a_s > 0 && a_s == a_r) {
		eq = "OK"; ret = 0;
		if(a_av > c_wait*1000) {
			eq = "ERR wait"; ret = 2;
			break;
		}
		if(a_av > w_wait*1000) {
			eq = "WARN wait"; ret = 1;
			break;
		}
		break;
	}
	if(drop < w_drop) {
		eq = "OK"; ret = 0;
		if(a_av > c_wait*1000) {
			eq = "ERR lost"; ret = 2;
			break;
		}
		if(a_av > w_wait*1000) {
			eq = "WARN lost"; ret = 1;
			break;
		}
		break;
	}
	if(drop < c_drop) {
		eq = "WARN"; ret = 1;
		if(a_av > c_wait*1000) {
			eq = "ERR lost"; ret = 2;
			break;
		}
		break;
	}
	eq = "ERR lost"; ret = 2;
	break;
   case 1: // Timeout
   case 2: // Data error
   case 3: // DNS
	if(a_r > 0) {
	    if(drop < c_drop) {
		eq = "WARN lost"; ret = 1;
		break;
	    }
	}
	if(a_st == 1) eq = "ERR wait";
	if(a_st == 2) eq = "ERR data";
	if(a_st == 3) eq = "ERR dns";
	ret = 2;
	break;
  }
} while(0);
// OK - 10.200.2.1: rta 0.187ms, lost 0%|
// rta=0.187ms;200.000;500.000;0; pl=0%;40;80;; rtmax=0.265ms;;;; rtmin=0.110ms;;;;
printf( "%s - %s: rta %gms, lost %d%% S:%d|"
	"rta=%gms;%d.0;%d.0;0; pl=%d%%;%d;%d;; rtmax=%gms;;;; rtmin=%gms;;;; chg=%d\n",
	 eq, rhost, (float)a_av/1000.0, drop, a_s,
	 (float)a_av/1000.0, w_wait, c_wait, drop, w_drop, c_drop,
	 (float)a_max/1000.0, (float)a_min/1000.0,a_c);
return ret;
}


int main(int argc,char **argv)
{
struct sockaddr_in sa;
int fd;
char msg[256],rhost_addr[128],*rhost=NULL;
int i;
int interval=3,times=180,len=32,c;

    bzero((char *)&sa,sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(0x7f000001);
    sa.sin_port = htons(19988);

    while((c=getopt(argc,argv,"H:b:i:T:P:w:c:")) != -1) {
	switch(c) {
	    case 'P':
		    {
			char *cmd = parse_host_port(&sa,optarg);
			if(*cmd) {
				fprintf(stderr,"Bad addr:port %s\n",optarg);
				exit(1);
			}
		    }
	            break;
	    case 'H':
		    rhost = strdup(optarg);
	            break;
	    case 'b':
		    len = atoi(optarg);
	            break;
	    case 'i':
		    interval = atoi(optarg);
	            break;
	    case 'T':
		    times = atoi(optarg);
	            break;
	    case 'w':
		    parse_ms_proc(&w_wait,&w_drop,optarg);
	            break;
	    case 'c':
		    parse_ms_proc(&c_wait,&c_drop,optarg);
	            break;
	    default:
		    help();
	}
    }
 if(!rhost && optind < argc && argv[optind])
	rhost = strdup(argv[optind]);

 if(!rhost)
	 help();

 a_host = rhost;

if(strcmp(rhost,"STAT")) {
  struct sockaddr_in6 ca;
  socklen_t lca;

  struct hostent *he = gethostbyname2(rhost,AF_INET);
    if(!he)
	    he = gethostbyname2(rhost,AF_INET6);

    if(he && he->h_addrtype == AF_INET && he->h_length == 4 && he->h_addr) {
	struct sockaddr_in *ca4 = (void *)&ca;
	lca = sizeof(struct sockaddr_in);
        bzero((char *)&ca,lca);
        ca4->sin_family = AF_INET;
        memcpy(&ca4->sin_addr,he->h_addr,he->h_length);
    } else if(he && he->h_addrtype == AF_INET6 && he->h_length == 16 && he->h_addr) {
	struct sockaddr_in6 *ca6 = (void *)&ca;
	lca = sizeof(struct sockaddr_in6);
        bzero((char *)&ca,lca);
        ca6->sin6_family = AF_INET6;
        memcpy(&ca6->sin6_addr,he->h_addr,he->h_length);
    } else {
	printf("ERR dns - %s: rta 0ms, lost 100%% |rta=0ms;200.0;800.0;0; pl=0%%;40;80;; rtmax=0ms;;;; rtmin=0ms;;;; chg=1\n",rhost);
	exit(1);
    }
    if(!getnameinfo ((struct sockaddr *)&ca, lca, rhost_addr, sizeof rhost_addr,
				 NULL, 0, NI_NUMERICHOST | NI_NUMERICSERV))
	    rhost = rhost_addr;
}


 fd = socket(PF_INET,SOCK_STREAM,0);
 if(fd < 0) abort();

 signal(SIGALRM,my_alarm);
 a_msg = "ERROR: %s connect timeout\n";

 alarm(5);

 while(connect(fd,(struct sockaddr *)&sa,sizeof(sa))) {
	if(errno == EINTR) continue;
	printf("ERROR connect: %s\n", strerror(errno));
	exit(2);
 }
 alarm(0);
 if(strcmp(rhost,"STAT")) {
	snprintf(msg,sizeof(msg),"%.64s %d %d %d\n",rhost,len,interval,times);
 } else
	 strcpy(msg,"STAT\n");
 a_msg = "ERROR %d send timeout\n";
 alarm(5);
 i=send(fd,msg,strlen(msg),0);
 if(i < 0)
	my_alarm(0);

 a_msg = "ERROR %s read timeout\n";
 alarm(10);
 bzero(msg,sizeof(msg));
 i=recv(fd,msg,sizeof(msg),0);
 if(i < 0) {
	printf("ERROR %s read: %s\n",rhost,strerror(errno));
	exit(2);
 }
 shutdown(fd,SHUT_RDWR);
 close(fd);
 return parse_answer(msg,rhost);
}

