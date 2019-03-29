#define __STDC_FORMAT_MACROS
#include <inttypes.h>

#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netdb.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <signal.h>
#include <time.h>
#include <sys/epoll.h>

struct ping_stat {
	int		send,
			error,
			changes,
			replay,
			last_state;
	long int	min_time,
			max_time,
			avg_time;
} __attribute__ ((packed));;

#define PING_ERROR_NONE	0
#define PING_ERROR_TMO	1
#define PING_ERROR_DATA	2
#define PING_ERROR_DNS	3

#define TIMER_MULT 1000000

/* ping */
#define PING_MAGIC htonl(0x70696E67)

union host_any {
	struct in_addr	v4;
	struct in6_addr v6;
};

struct ping_payload {
	uint32_t			magic; /* ping in hex */
	struct timespec		tm;
	union host_any		host;
	char				pad[0];
} __attribute__ ((packed));


struct ping_host {
	struct ping_host	*next_host;

	char				v6,hostname[63];
	union {
		struct sockaddr		any;
		struct sockaddr_in	v4;
		struct sockaddr_in6 v6;
	} host;
// async answer
	int					cfd; // client wait answer if > 0 
	char				*reply; // msg

	int					size;		// packet size > 32
	int					interval;	// seconds
	int					times;		// max time
	int					new_interval;
	int					new_times;

	uint16_t			seq;
	volatile uint8_t	no_addr;
	volatile uint8_t	active; //  0 - stop, 1 - ping running
	volatile int64_t	rto;
	uint64_t			start_time,
						next_send,
						last_time;
	struct timeval		r_start_time;
	struct ping_stat	stat;
	char 				*buf;
	struct icmphdr		*icmp_hdr;
	struct icmp6_hdr	*icmp6_hdr;
	struct ping_payload	*data;
	
};

struct ping_acl {
	struct sockaddr_in	host;
	int					masklen;
	struct ping_acl		*next;
};

struct cidr_acl {
	union host_any		dst;
	uint16_t			masklen,v6;
	struct cidr_acl		*next;
};

#define MAXEVENTS 128
#define REPLY_LEN 192

#define DBG_CMD		0x01
#define DBG_NET		0x02
#define DBG_HOST	0x04
#define DBG_EVENT	0x08
#define DBG_FD		0x10
#define DBG_INFO	0x20
#define DBG_ERR		0x40
#define DBG_CMD2	0x80
#define DBG_NET2	0x100
#define DBG_EVENT2	0x200
#define DBG_CRIT	0xffff

#define CTO 5

struct ping_cmd {
		uint64_t stop; // start time + CTO
		char	cmd[110];
		char	wait_reply;
		size_t	p;
};

char *pid_file = NULL;
int pid_file_created = 0;
int debug_level = DBG_ERR|DBG_INFO;
pid_t main_pid=-1;
int icmp_socket = -1;
int icmp6_socket = -1;
struct ping_acl *ACL=NULL;
struct cidr_acl *DST_ACL=NULL;
volatile int do_work=1;
struct ping_cmd **fd_ping = NULL;
int n_fd_ping = 0;
struct ping_host *ping_host_list = NULL;
struct epoll_event *events = NULL;

// global counter
uint32_t ping_total_send_ok = 0,
		 ping_total_send_err = 0,
		 ping_total_recv_ok = 0,
		 ping_total_recv_err = 0,
		 ping_total_cmd_ok = 0,
		 ping_total_cmd_err = 0;

/*************************************************************************/

void ping_host_error(struct ping_host *ph,int code);
void ping_it(struct sockaddr_in *caddr,int csock);
struct ping_cmd * get_ping_fd(int fd);

/*************************************************************************/

void _ping_log(char *fmt,...)
{
va_list args;
int l;
struct timeval tv;
char logbuf[512],dstr[64],*c;

	va_start(args, fmt);
	l = vsnprintf(logbuf,sizeof(logbuf)-2, fmt, args);
	va_end(args);
	if(!l || logbuf[l-1] != '\n') logbuf[l++] = '\n';
	logbuf[l] = '\0';
	gettimeofday(&tv,NULL);
	strncpy(dstr,ctime(&tv.tv_sec),sizeof(dstr)-1);
	c = strchr(dstr,'\n'); if(c) *c = 0;
	fprintf(stderr,"%s %s",dstr,logbuf);
}

#define ping_log(l,f, ...) { if(((l) & debug_level) != 0) _ping_log(f, ## __VA_ARGS__); }

int check_acl(struct sockaddr_in *a) {
struct ping_acl *acl;
    for(acl=ACL; acl; acl=acl->next)
	if(a->sin_addr.s_addr == acl->host.sin_addr.s_addr) return 0;
    return ACL ? 1:0;
}

static inline uint32_t maskv4(int m) {
		if(m > 32) m = 32;
		return htonl(0xfffffffful << (32 - m));
}

static int check_dst_acl_ent(union host_any *h,struct cidr_acl *acl) {
uint32_t m;

	if(!acl->v6) {
		m = maskv4(acl->masklen);
		return ((h->v4.s_addr & m) == acl->dst.v4.s_addr) ? 0:1;
	} else {
		int i,ml = acl->masklen;
		int ok = 0;
		for(i=0; i < 4 && ml > 0; i++,ml-=32) {
			m = maskv4(ml);
			if((h->v6.s6_addr32[i] & m) != acl->dst.v6.s6_addr32[i]) 
				break;
			else
				ok++;
			if(ml <= 32) {
				ok = 4; break;
			}
		}
		return (ok == 4) ? 0:1;
	}
}

int check_dst_acl(union host_any *h,int v6) {
struct cidr_acl *acl;
    for(acl=DST_ACL; acl; acl=acl->next) {
		if(v6 != acl->v6) continue;
		if(check_dst_acl_ent(h,acl) == 0) return 0;
	}
    return DST_ACL ? 1:0;
}


int read_pid(char *file) {
char buf[64],*e;
int r;
int fd = open(file,O_RDONLY);

	if(fd < 0) return -1;
	r = read(fd,buf,sizeof(buf));
	close(fd);
	if(r <= 1) return 1;
	e = strchr(buf,'\r'); if(e) *e = 0;
	e = strchr(buf,'\n'); if(e) *e = 0;
	r = strtol(buf,&e,10);
	if(e && *e) return -1;
	return r;
}

int write_pid(void) {
	char buf[64];
	int pid,fd;

	if(!pid_file) return 0;
	if(pid_file_created) return 0;
	pid = read_pid(pid_file);
	if(pid > 0) {
		struct stat st;
		snprintf(buf,sizeof(buf)-1,"/proc/%d",pid);
		if(!stat(buf,&st) && S_ISDIR(st.st_mode)) {
			fprintf(stderr,"Pid file and process exists!\n");
			return 1;
		}
	}
	fd = creat(pid_file,0644);
	if(fd < 0) {
		fprintf(stderr,"Cant create PID file %s : %s\n",
						pid_file,strerror(errno));
		return 1;
	}
	snprintf(buf,sizeof(buf)-1,"%d\n",getpid());
	write(fd,buf,strlen(buf));
	pid_file_created = 1;
	close(fd);
	return 0;
}

uint64_t long_timer(struct timeval *tv) {
	return (uint64_t)tv->tv_sec*TIMER_MULT+tv->tv_usec;
}
uint64_t long_timer_n(struct timespec *tv) {
	return (uint64_t)tv->tv_sec*TIMER_MULT+(tv->tv_nsec/1000);
}

long int diffmsec(struct timeval *tv,struct timeval *rtv) {
uint64_t t1 =  long_timer(tv);
uint64_t t2 =  long_timer(rtv);
	return (long)(t2-t1);
}

long int diffmsec2(struct timespec *tv,struct timespec *rtv) {
uint64_t t1 =  long_timer_n(tv);
uint64_t t2 =  long_timer_n(rtv);
	return (long)(t2-t1);
}

int64_t get_delta_time(struct timeval *rts,struct timespec *rtm) {
struct timeval ts;
struct timespec tm;
	if(rts && rts->tv_sec ) {
		ts = *rts;
	} else {
		gettimeofday(&ts,NULL);
		if(rts) *rts = ts;
	}
	if(rtm && rtm->tv_sec ) {
		tm = *rtm;
	} else {
		clock_gettime(CLOCK_MONOTONIC, &tm);
		if(rtm) *rtm = tm;
	}
	return long_timer(&ts)-long_timer_n(&tm);
}
uint64_t clock_gettime_mono(struct timespec *tm) {
	struct timespec tmp;
	if(!tm) tm = &tmp;
	clock_gettime(CLOCK_MONOTONIC, tm);
	return long_timer_n(tm);
}

void sysvsignal(int signum, void (*handler)(int))
{
struct  sigaction  act;

bzero((char *)&act,sizeof(act));
act.sa_handler = handler;
act.sa_flags = 0;//SA_NOMASK|SA_RESTART;
sigaction(signum,&act,NULL);
}

int
make_socket_non_blocking (int sfd,int flag)
{
	int flags, s;

	flags = fcntl (sfd, F_GETFL, 0);
	if (flags < 0) {
		perror ("fcntl");
		return -1;
	}
	if(flag)
		flags |= O_NONBLOCK;
	else
		flags &= ~O_NONBLOCK;

	s = fcntl (sfd, F_SETFL, flags);
	if (s < 0) {
		perror ("fcntl");
		return -1;
	}

	return 0;
}

static struct sock_opts {
	int	name,val;
	char	*txt;
} _sock_opts[] = {
	{ .name = SO_TIMESTAMP, .val = 0, .txt="SO_TIMESTAMP" },
	{ .name = SO_TIMESTAMPNS, .val = 1, .txt="SO_TIMESTAMPNS" },
	{ .name = SO_TIMESTAMPING, .val = 0, .txt="SO_TIMESTAMPING" } };

int set_timestamping(int sock) {
socklen_t len;
int val,i;
	for(i=0; i < sizeof(_sock_opts)/sizeof(_sock_opts[0]); i++) {
		if ( setsockopt(sock, SOL_SOCKET, _sock_opts[i].name,
			   &_sock_opts[i].val, sizeof(_sock_opts[0].val)) < 0) {
			fprintf(stderr,"setsockopt %s error: %s\n",_sock_opts[i].txt,
					strerror(errno));
			return 1;
		}

		len = sizeof(val);
		if (getsockopt(sock, SOL_SOCKET, _sock_opts[i].name, &val, &len) < 0) {
			fprintf(stderr, "getsockopt  %s:%s\n",
					_sock_opts[i].txt , strerror(errno));
			return 1;
		} else {
			if(val != _sock_opts[i].val) {
				fprintf(stderr,"%s %d\n", _sock_opts[i].txt,val);
				return 1;
			}
		}
	}
return 0;
}

int recvpacket(int sock, char *data, size_t data_size,int recvmsg_flags,
		struct sockaddr *from_addr,struct timeval *rcv)
{
	struct msghdr msg;
	struct iovec entry;
	struct {
		struct cmsghdr cm;
		char control[128];
	} control;
	int res;

	memset(&msg, 0, sizeof(msg));
	msg.msg_iov = &entry;
	msg.msg_iovlen = 1;
	entry.iov_base = data;
	entry.iov_len = data_size;
	msg.msg_name = (caddr_t)from_addr;
	msg.msg_namelen = sock == icmp6_socket ? sizeof(struct sockaddr_in6) : sizeof(struct sockaddr_in);
	msg.msg_control = &control;
	msg.msg_controllen = sizeof(control);

	res = recvmsg(sock, &msg, recvmsg_flags|MSG_DONTWAIT);
	if (res < 0) {
		ping_log(DBG_NET2,"recvmsg %s: %s\n",
		       (recvmsg_flags & MSG_ERRQUEUE) ? "error" : "regular",
		       strerror(errno));
	} else {
		struct cmsghdr *cmsg;
	   for (cmsg = CMSG_FIRSTHDR(&msg);
	        cmsg;
	        cmsg = CMSG_NXTHDR(&msg, cmsg)) {
		    if(cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SO_TIMESTAMPNS) {

			struct timespec *stamp = (struct timespec *)CMSG_DATA(cmsg);
			rcv->tv_sec = stamp->tv_sec;
			rcv->tv_usec = stamp->tv_nsec/1000;
			break;
		}
	   }
	}
	return res;
}

int get_ctrl_socket(struct sockaddr_in *addr) {

static int one=1;

int sock = socket(AF_INET,SOCK_STREAM,0);

    if(sock < 0) return -1;
    setsockopt(sock,SOL_SOCKET,SO_REUSEPORT,&one,sizeof(one));
    setsockopt(sock,SOL_SOCKET,SO_REUSEADDR,&one,sizeof(one));
    if(bind(sock,(struct sockaddr *)addr,sizeof(*addr))) {
	perror("bind");
	close(sock);
	return -1;
    }
    listen(sock,1024);
    return sock;
}

/******************************************************************************/

int add_ping_fd(int fd) {
	ping_log(DBG_FD,"add cfd %d n=%d\n",fd,n_fd_ping);
	if(fd >= n_fd_ping) {
		int new_n_fd = (fd + 8) & ~7;
		void *tmp = realloc((void *)fd_ping,new_n_fd*sizeof(struct ping_cmd *));
		if(!tmp) {
			ping_log(DBG_ERR,"realloc %d fds failed!\n",new_n_fd);
			return 1;
		}
		fd_ping = tmp;
		ping_log(DBG_FD,"alloc %d fd\n",new_n_fd-n_fd_ping);
		for(; n_fd_ping < new_n_fd; n_fd_ping++)
				fd_ping[n_fd_ping] = NULL;
	}
	if(fd_ping[fd]) { // BUG!
		ping_log(DBG_CRIT,"already %d fd\n",fd);
		return 1;
	}
	fd_ping[fd] = calloc(1,sizeof(struct ping_cmd));
	fd_ping[fd]->stop = clock_gettime_mono(NULL) + CTO*TIMER_MULT;
	return 0;
}

struct ping_cmd * get_ping_fd(int fd) {
	if(fd >= n_fd_ping) return NULL;
	return fd_ping[fd];
}


int del_ping_fd(int fd) {
struct ping_host *ph;

	if(fd >= n_fd_ping) return 1;
	if(!fd_ping[fd]) return 1;
	free(fd_ping[fd]);
	fd_ping[fd] = NULL;
	for(ph = ping_host_list; ph ; ph = ph->next_host) {
		if(ph->cfd > 0 && ph->cfd == fd) {
			ph->cfd = 0;
			if(ph->reply) free(ph->reply);
			ph->reply = NULL;
		}
	}

	return 0;
}

int ping_resolve(struct ping_host *ph) {
uint8_t r=1;

	bzero((char *)&ph->host.v4,sizeof(ph->host.v4));
	if(inet_pton(AF_INET,ph->hostname,&ph->host.v4.sin_addr)) {
		ph->host.v4.sin_family = AF_INET;
		ph->data = (struct ping_payload *)(ph->buf + sizeof(struct icmphdr));
		ph->data->host.v4 = ph->host.v4.sin_addr;
		ph->v6 = 0;
		r = 0;
	} else {
		bzero((char *)&ph->host.v6,sizeof(ph->host.v6));
		if(inet_pton(AF_INET6,ph->hostname,&ph->host.v6.sin6_addr)) {
			ph->data = (struct ping_payload *)(ph->buf + sizeof(struct icmp6_hdr));
			ph->host.v6.sin6_family = AF_INET6;
			ph->data->host.v6 = ph->host.v6.sin6_addr;
			ph->v6 = 1;
			r = 0;
		}
	}
	ph->no_addr = r;
	return r;
}

struct ping_host *ping_host_init(char *hostname,int len,int interval,int max_time) {

	struct ping_host *ph;

	size_t buf_size = sizeof (struct icmp6_hdr) + sizeof(struct ping_payload) + len;
	ph = calloc(1,sizeof(*ph));
	if(!ph) return ph;
	ph->buf = calloc(1,buf_size);
	if(!ph->buf) {
		free(ph);
		return NULL;
	}

	strncpy(ph->hostname,hostname,sizeof(ph->hostname));
	{
		char *c = ph->hostname + strlen(ph->hostname);
		if(c && c > ph->hostname && *(c-1) == '.') *(c-1) = 0;
	}
	ph->size = buf_size;
	if(interval < 1) interval = 1;
	ph->interval = interval;
	ph->times = max_time;
	ph->stat.min_time = LONG_MAX;
	ph->seq = 1;

	ph->icmp_hdr = (struct icmphdr *)ph->buf;
	ph->icmp6_hdr = (struct icmp6_hdr *)ph->buf;



	if(ping_resolve(ph))
		ping_host_error(ph,PING_ERROR_DNS);
	else {
		if(ph->v6) {
			ph->icmp6_hdr->icmp6_type = ICMP6_ECHO_REQUEST;
		} else {
			ph->icmp_hdr->type = ICMP_ECHO;
		}
		memset(&ph->data->pad[0], random()&0xff ,len);
		ph->data->magic = PING_MAGIC;
	}
	ping_log(DBG_HOST,"host init %s%s\n",ph->hostname,
					ph->v6 ? " ipv6":"",ph->no_addr ? " bad_IP":"");

	return ph;
}

void ping_host_free(struct ping_host *ph) {
	free(ph->buf);
	free(ph);
}

void ping_host_status(struct ping_host *ph,char *buf,size_t len,uint64_t ts) {
    snprintf(buf,len,
	"PHOST=%s RUN=%d AVG=%ld MIN=%ld MAX=%ld STATE=%d CHG=%d SEND=%d RECV=%d ERR=%d SEQ=%d\n",
	ph->hostname,
	ph->active ? (int32_t)((ts-ph->start_time)/TIMER_MULT):0,
	ph->stat.avg_time,
	ph->stat.replay ? ph->stat.min_time : 0,
	ph->stat.max_time,
	ph->stat.last_state,
	ph->stat.changes,
	ph->stat.send - (!ph->no_addr && ph->active && !ph->rto ? 1:0),
	ph->stat.replay,ph->stat.error,ph->seq);
}

void ping_host_stat_info(char *buf,size_t len) {
struct ping_host *ph,*nh;
int a_hosts=0,i_hosts=0,e_hosts=0,s_hosts=0,r_hosts=0;

    for(ph = ping_host_list; ph; ph=nh) {
		if(ph->active) a_hosts++; else i_hosts++;
		if(ph->stat.last_state) e_hosts++;
		s_hosts += ph->stat.send;
		r_hosts += ph->stat.replay;
		nh = ph->next_host;
    }
    snprintf(buf,len,"ACTIVE=%d INACT=%d ERRORS=%d SEND=%d RECV=%d "
					 "TSEND=%d TSEND_ERR=%d TRECV=%d TRECV_ERR=%d "
					 "TCMD=%d TCMD_ERR=%d\n",
		    a_hosts,i_hosts,e_hosts,s_hosts,r_hosts,
			ping_total_send_ok,ping_total_send_err,
			ping_total_recv_ok,ping_total_recv_err,
			ping_total_cmd_ok, ping_total_cmd_err);
}

void my_sig_quit(int s) {
	ping_log(DBG_CRIT,"Quit signal %d\n",s);
	do_work = 0;
}

void my_sig_hup(int s) {
	ping_log(DBG_EVENT,"Got signal %d\n",s);
	// use for interrupt main loop
}

void my_sig_int(int s) {
char buf[128];
struct ping_host *ph;
uint64_t tv;

    tv = clock_gettime_mono(NULL);
    ping_log(DBG_INFO,"Sig %d\n",s);
    for(ph = ping_host_list; ph; ph=ph->next_host) {
		ping_host_status(ph,buf,sizeof(buf)-1,tv);
		ping_log(DBG_INFO,"%s",buf);
    }
}

int ping_send(struct ping_host *ph) {

	int ret;
	/*
	 * !active && !start_time == ready for start
	 *  active && start_time && !rto = send ping, wait replay
	 *  active && start_time && rto = got replay, wait next send
	 *  !active && start_time = stopped
	 */

	ph->seq++;
	ph->icmp_hdr->un.echo.sequence = htons(ph->seq);
	ph->stat.send++;

	if(!ph->rto && ph->start_time) 
		ping_host_error(ph,PING_ERROR_TMO); // timeout

	ph->rto = 0;
	ph->r_start_time.tv_sec = 0;
	ph->data->tm.tv_sec = 0;
	(void)get_delta_time(&ph->r_start_time,&ph->data->tm);

	if(!ph->start_time) {
		ph->start_time = long_timer_n(&ph->data->tm);
		ph->next_send = ph->start_time;
		ph->last_time = ph->start_time + (ph->times+ph->interval)*TIMER_MULT;
		ph->active = 1;
	}

	ph->next_send += ph->interval*TIMER_MULT;

    ret = sendto(ph->v6 ? icmp6_socket: icmp_socket,
					(char *)ph->icmp_hdr,  ph->size, 0,
					&ph->host.any, ph->v6 ? sizeof (struct sockaddr_in6):
											sizeof (struct sockaddr_in));
	ping_log(DBG_NET2,"host %s send_time %6u next_send %6u seq %d ret %d %s\n",
			ph->hostname,
			(uint32_t)(long_timer_n(&ph->data->tm) - ph->start_time)/TIMER_MULT,
			(uint32_t)(ph->next_send - ph->start_time)/TIMER_MULT,
			ph->seq,ret,ret < 0 ? strerror(errno):"");
	++(*(ret < 0 ? &ping_total_send_err : &ping_total_send_ok));
	return ret;
}

struct ping_host *ping_host_find(struct ping_host *add) {
	struct ping_host *ph;

	for(ph = ping_host_list; ph; ph = ph->next_host) {
		if(!strcmp(ph->hostname,add->hostname)) break;
	}
	if(!ph && add->times) {
		add->next_host = ping_host_list;
		ping_host_list = add;
		ph = add;
	}

	return ph;
}

struct ping_host *ping_host_find_addr(struct sockaddr_in *addr) {
	struct ping_host *ph;


	for(ph = ping_host_list; ph; ph = ph->next_host) {
		if(ph->host.v4.sin_addr.s_addr == addr->sin_addr.s_addr) 
				break;
	}

	return ph;
}

struct ping_host *ping_host_find_addr6(struct sockaddr_in6 *addr) {
	struct ping_host *ph;


	for(ph = ping_host_list; ph; ph = ph->next_host) {
		if(!memcmp(&ph->host.v6.sin6_addr, &addr->sin6_addr,sizeof(struct in6_addr))) 
				break;
	}

	return ph;
}

int ping_host_stat(struct ping_host *ph,struct timeval *rtv,char *data,size_t len) {

struct ping_payload *pd = (struct ping_payload *) (data + sizeof(struct icmphdr));
int64_t d1,d2;
int err = 0;

//	len -= sizeof(struct icmphdr);

	do {
		if(len != ph->size) {
			ping_log(DBG_NET2,"Error: %s wrong size\n",ph->hostname);
			err = 1;
			break;
		}
		if(pd->magic != PING_MAGIC) {
			ping_log(DBG_ERR,"Error: %s bad magic\n",ph->hostname);
			err = 2;
			break;
		}
		if(memcmp(&pd->host.v6,&ph->data->host.v6,sizeof(struct sockaddr))) {
			ping_log(DBG_ERR,"Error: %s wrong host address\n",
						ph->hostname);
			err = 3;
			break;
		}
		if(memcmp(pd->pad,ph->data->pad,len-sizeof(struct icmphdr)-sizeof(struct ping_payload))) {
			int i,l;
			ping_log(DBG_ERR,"Error: %s bad payload %d\n",ph->hostname,len-sizeof(struct ping_payload));
			l = len-sizeof(struct ping_payload)-sizeof(struct icmphdr);
			for(i=0; i < l; i++) {
				if(pd->pad[i] != ph->data->pad[i])
					ping_log(DBG_ERR,"%d: %02x != %02x\n",i,pd->pad[i]&0xff,ph->data->pad[i]&0xff);
			}
			err = 3;
			break;
		}
	} while(0);

	if(err) {
		ping_host_error(ph,PING_ERROR_DATA);
		return err;
	}
	if(ph->rto || !ph->active) return 0;

	ph->rto = diffmsec(&ph->r_start_time,rtv);

/* 
 * d1 = 10_000000; d2 = 13_000000 -> system time shift forward on 3 seconds
 * rto must be corrected on 3 seconds
 *
 */

	d1 = long_timer(&ph->r_start_time)-long_timer_n(&ph->data->tm);
	d2 = get_delta_time(NULL,NULL);
	d2 -= d1;
	ph->rto -= d2;
	ph->stat.replay++;
	ping_host_error(ph,PING_ERROR_NONE);
	if(ph->stat.avg_time) {
		ph->stat.avg_time += ph->rto;
		ph->stat.avg_time >>= 1;
	} else {
		ph->stat.avg_time = ph->rto;
	}
	if(ph->rto < ph->stat.min_time) ph->stat.min_time = ph->rto;
	if(ph->rto > ph->stat.max_time) ph->stat.max_time = ph->rto;

	if(ph->reply && !ph->reply[0]) {
		strcpy(ph->reply,"OK ");
		ping_host_status(ph,ph->reply+3,REPLY_LEN-4,long_timer(rtv));
	}
	if(abs(d2 < 250))
			d2 = 0;
		else
			ping_log(DBG_CRIT,"Host %s rto %" PRIi64 " d2  %" PRIi64 "\n",ph->hostname,ph->rto,d2);

	ping_log(DBG_NET2,"host %s rto %" PRIi64 " delta %" PRIi64 "\n",
				ph->hostname,ph->rto,d2);

return 0;
}

void ping_host_error(struct ping_host *ph,int code) {
    if(code != ph->stat.last_state)
	ping_log(DBG_NET2,"%s seq:%d old:%d new %d\n",
			ph->hostname,ph->seq, ph->stat.last_state,code);

    switch(code) {
	case PING_ERROR_NONE:
		if(ph->stat.last_state)
			ph->stat.changes++;
		break;
	case PING_ERROR_DNS:
	case PING_ERROR_DATA:
	case PING_ERROR_TMO:
		if(code != PING_ERROR_DNS) ph->stat.error++;
		if(ph->stat.last_state != code)
			ph->stat.changes++;
		break;
    }
    ph->stat.last_state = code;

}

void ping_host_restart(struct ping_host *old) {
uint64_t tv;

	tv = clock_gettime_mono(NULL);
    if(old->active) {
		if(!old->rto)
			ping_log(DBG_EVENT,"Restart active host %s\n",old->hostname);
		
		old->stat.send =  old->rto == 0;
		old->last_time = tv + (old->new_times + old->new_interval)*TIMER_MULT;
    } else {
    	old->stat.send  = 0;
		old->start_time = 0;
    }
    if(!old->new_times) {
	    old->active = 0;
	    old->rto = 10*TIMER_MULT;
	    old->start_time = 0;
		old->last_time = tv;
    }
    old->times = old->new_times;
    old->interval = old->new_interval;
    old->stat.replay = 0;
    old->stat.error = 0;
    old->stat.changes = 0;
    old->stat.avg_time = 0;
    old->stat.min_time = LONG_MAX;
    old->stat.max_time = 0;
}

static inline int ping_have_rto(struct ping_host *ph) {
	return ph->no_addr == 0 && ph->active != 0 && ph->rto != 0;
}

int ping_command(char *buf,int nc) {

struct ping_host *ph = NULL;
char host[64],stbuf[192],*c;
int p_l,p_i,p_t,n,no,ret = 0;

    no = 0;
	do {
		c =  strchr(buf,'\n');
		if(c) *c = '\0';
		c =  strchr(buf,'\r');
		if(c) *c = '\0';
		n=sscanf(buf,"%64s %d %d %d",host,&p_l,&p_i,&p_t);
		ping_log(DBG_CMD2,"Cmd: %s n %d\n",buf,n);

		if(n == 1) { // command
		    if(!strcmp(host,"STAT")) {
		        char stbuf[128];
		        snprintf(stbuf,sizeof(stbuf),"OK ");
		        ping_host_stat_info(&stbuf[3],sizeof(stbuf)-4);
		        send(nc,stbuf,strlen(stbuf),0);
				ping_total_cmd_ok++;
				break;
		    }
		    no = 1;
			break;
		}
		no = 1;
		if(n != 4) break;
		ph = ping_host_init(host,p_l,p_i,p_t);
		if(ph) {
		    struct ping_host *old;

			stbuf[0] = 0;
			if(check_dst_acl(&ph->data->host,ph->v6)) {
				ping_total_cmd_err++;
				snprintf(stbuf,sizeof(stbuf)-1,"Deny by acl %s\n",ph->hostname);
				ping_host_free(ph);
			} else {
		    old = ping_host_find(ph);
			if(!old) {
				ping_total_cmd_err++;
				snprintf(stbuf,sizeof(stbuf)-1,"BAD %s not exist\n",ph->hostname);
			} else
			    if(old != ph) {
					strcpy(stbuf,"OK ");
					ping_host_status(old,&stbuf[3],sizeof(stbuf)-4,clock_gettime_mono(NULL));
					old->new_interval = ph->interval;
					old->new_times	  = ph->times;
					ping_host_free(ph);
					ping_host_restart(old);
					ping_log(DBG_CMD2,"%s",stbuf);
					ping_total_cmd_ok++;
			    } else {
					ph->reply = calloc(1,REPLY_LEN);
					if(get_ping_fd(nc) && ph->reply) {
						ph->cfd = nc;
						fd_ping[nc]->wait_reply = 1;
						ret = 1;
						no = 0;
						ping_log(DBG_CMD2,"Wait data for %s\n",ph->hostname);
					} else {
						if(ph->reply)
								free(ph->reply), ph->reply = NULL;
						ping_log(DBG_CRIT,"No memory for %s or bad fd\n",ph->hostname);
						snprintf(stbuf,sizeof(stbuf),"ERR %s; out of memory or bad FD\n",ph->hostname);
					}
				}
			}
		    if(stbuf[0]) {
				send(nc,stbuf,strlen(stbuf),0);
				no = 0;
			}
		}
    } while(0);
    if(no) {
		send(nc,"INV\n",4,0);
		ping_total_cmd_err++;
	}
	return ret;
}
/************************************************************************/

void usage(void) {
	printf("ping_server [-4kD] [-d level] [-P pidfile] [-b addr:port{127.0.0.1:19988}] [-a ip,...,ip ] [-A ip[v6][/masklen][,ip[v6][/masklen]...]\n");
printf(
"	-4	- no ipv6\n"
"	-k	- kill daemon using pidfile\n"
"	-D	- no daemon\n"
"	-b	- listen address:port (ipv4 only)\n"
"	-a	- ACL for client requests (ipv4 only)\n"
"	-A	- ACL for destination requests (v4/v6)\n"
"	-x	- ACL list for destination requests (v4/v6)\n"
"Debug level:\n"
"	DBG_CMD		0x01 	DBG_NET		0x02\n"
"	DBG_HOST	0x04	DBG_EVENT	0x08\n"
"	DBG_FD		0x10	DBG_INFO	0x20\n"
"	DBG_ERR		0x40	DBG_CMD2	0x80\n"
"	DBG_NET2	0x100	DBG_EVENT2	0x200\n"
"	DBG_ALL		0xffff\n");

	exit(0);
}

static char *parse_host_port(struct sockaddr_in *addr,char *str) {
char *p,*e;
int r;
e = strchr(str,',');
if(e) *e = 0;
p = strchr(str,':');
if(p) *p = 0;
bzero(addr,sizeof(*addr));
addr->sin_family = AF_INET;
r = inet_pton(AF_INET,str,&addr->sin_addr);
if(p) *p = ':';
if(r < 0) {
		if(e) *e = ',';
		return NULL;
}
if(p) {
	char *en;
	addr->sin_port = htons(strtol(p,&en,10) & 0xffff);
	if(en && !*en) {
		if(e) *e = ',';
		return NULL;
	}
}
if(e) *e = ',';

return e ? e : str + strlen(str);
}

static char *cidr_dst_acl_parse(struct cidr_acl *acl,char *str) {
char *p,*e;
int r;

e = strchr(str,',');
if(e) *e = 0;

p = strchr(str,'/');
if(p) *p = 0;

bzero((char *)&acl->dst,sizeof(acl->dst));
r = 0;
if(inet_pton(AF_INET,str,&acl->dst.v4.s_addr)) {
	acl->v6 = 0;
	r = 1;
} else {
	bzero((char *)&acl->dst,sizeof(acl->dst));
	if(inet_pton(AF_INET6,str,&acl->dst.v6.s6_addr)) {
		acl->v6 = 1;
		r = 1;
	}
}
if(p) *p = '/';

if(!r) {
	fprintf(stderr,"Bad acl addr %s\n",str);
	if(e)  *e = ',';
	return NULL;
}

if(p) {
	acl->masklen = atoi(p+1);
	if(acl->v6 && acl->masklen > 128) acl->masklen=128;
	if(!acl->v6 && acl->masklen > 32) acl->masklen=32;
} else
	acl->masklen = acl->v6 ? 128:32;

if(check_dst_acl_ent(&acl->dst,acl)) {
	fprintf(stderr,"Bad acl addr/mask %s\n",str);
    return NULL;
}

if(e) *e = ',';

return e ? e : str + strlen(str);
}

int get_next_event(struct itimerspec *its,int efd) {
struct ping_host *ph,*pph;
struct timespec ts;
uint64_t tv;
time_t wait;
int i;
	
	wait= 10*TIMER_MULT;
	tv = clock_gettime_mono(&ts);

	for(ph = ping_host_list; ph ; ph = ph->next_host) {
		ping_log(DBG_EVENT2,"host %s int %d times %d  act %d rto %d start_tm %d next_send %d last_time %d\n",
				ph->hostname,ph->interval,ph->times,
				ph->active,(int)ph->rto,
				ph->active ? (int)((tv - ph->start_time)/TIMER_MULT):0,
				ph->active ? (int)((int64_t)(ph->next_send - tv )/TIMER_MULT):0,
				ph->active ? (int)((ph->last_time - tv )/TIMER_MULT):0
				);
		
		if(ph->no_addr) continue;
		if(ph->reply && ph->reply[0]) {
			if(get_ping_fd(ph->cfd)) {
				ping_total_cmd_ok++;
				send(ph->cfd,ph->reply,strlen(ph->reply),0);
				shutdown(ph->cfd,SHUT_RDWR);
				close (ph->cfd);
			}
			free(ph->reply);
			ph->reply = NULL;
			epoll_ctl (efd, EPOLL_CTL_DEL, ph->cfd, NULL);
			del_ping_fd(ph->cfd);
			ph->cfd = 0;
		}
		if(!ph->times) continue;
		if(!ph->start_time && ph->times) {
			ping_send(ph);
			tv = clock_gettime_mono(&ts);
			if(wait > ph->interval*TIMER_MULT/2)
				wait = ph->interval*TIMER_MULT/2;
			continue;
		}
		if(ph->active) {
			if(!ph->rto) {
				uint64_t tmo1=long_timer_n(&ph->data->tm) +
								ph->interval*TIMER_MULT * 5/10;
				uint64_t tmo2 = tmo1 + ph->interval*TIMER_MULT/10;

				if(tv < tmo1 && wait > tmo2-tv) {
					wait = tmo2-tv;
				}
				if(tv >= tmo2) {
					ph->rto = diffmsec2(&ph->data->tm,&ts);
					if(!ph->stat.last_state)
						ping_log(DBG_EVENT|DBG_NET,"host %s timeout %d.%04d\n",
									 ph->hostname,(int)(ph->rto/TIMER_MULT),
									 (int)(ph->rto % TIMER_MULT)/100);
					ping_host_error(ph,PING_ERROR_TMO);
					if(ph->reply && !ph->reply[0]) {
						strcpy(ph->reply,"OK ");
						ping_host_status(ph,ph->reply+3,REPLY_LEN-4,clock_gettime_mono(NULL));

						if(get_ping_fd(ph->cfd)) {
							ping_total_cmd_ok++;
							send(ph->cfd,ph->reply,strlen(ph->reply),0);
							shutdown(ph->cfd,SHUT_RDWR);
							close (ph->cfd);
						}
						free(ph->reply);
						ph->reply = NULL;
						epoll_ctl (efd, EPOLL_CTL_DEL, ph->cfd, NULL);
						del_ping_fd(ph->cfd);
						ph->cfd = 0;
					}
				}
			}
			if(wait > ph->next_send - tv)
					wait = ph->next_send - tv;
			if( tv > ph->next_send - TIMER_MULT/4 &&
				tv < ph->last_time - ph->interval*TIMER_MULT) {
					ping_send(ph);
					tv = clock_gettime_mono(&ts);
					if(wait > ph->interval*TIMER_MULT/2)
						wait = ph->interval*TIMER_MULT/2;
			}
			if( tv >= ph->last_time) {
				if(!ph->rto) ping_log(DBG_EVENT,"host %s last timeout\n", ph->hostname);
				ping_log(DBG_EVENT,"host %s stop\n", ph->hostname);
				ph->active = 0;
			}
		}
//		ping_log(3,"wait %ld\n",wait);
	}

	for(pph = NULL,ph = ping_host_list; ph ; ) { 
	    // delete inactive hosts
	    if( !ph->times || (!ph->active && tv >= ph->last_time + 3 * ph->times * TIMER_MULT)) {
			struct ping_host *nh = ph->next_host;
			if(!pph) {
				ping_host_list = ph->next_host;
			} else {
				pph->next_host = ph->next_host;
			}
			ping_log(DBG_EVENT,"host %s delete\n", ph->hostname);
			ping_host_free(ph);
			ph = nh;
			continue;
	    }
	    pph = ph;
	    ph = ph->next_host;
	}
	if(fd_ping)
		for(i=1; i < n_fd_ping;i++) {
			struct ping_cmd *pc = fd_ping[i];
			if(!pc) continue;
			if(tv >= pc->stop) {
					send(i,"ERR\n",4,0);
					epoll_ctl (efd, EPOLL_CTL_DEL, i, NULL);
					shutdown(i,SHUT_RDWR);
					close (i);
					del_ping_fd(i);
					continue;
			}
			if(wait > pc->stop - tv)
				wait = pc->stop - tv;
		}
	its->it_interval.tv_sec = 0;
	its->it_interval.tv_nsec = 0;
	its->it_value.tv_sec = wait/TIMER_MULT;
	its->it_value.tv_nsec = (wait % TIMER_MULT) * 1000;

return wait > 0;
}



char rcv_data[1024*8];

void ping_it(struct sockaddr_in *caddr,int csock) {
	int rc;
	int efd,nfs;
	struct epoll_event event;
	struct sigevent se;
	timer_t i_timer;
	struct itimerspec its;
	struct sockaddr_in6 reply;
	struct sockaddr_in *reply4;
	struct sockaddr_in6 *reply6;

	reply4 = (struct sockaddr_in *)&reply;
	reply6 = (struct sockaddr_in6 *)&reply;

	efd = epoll_create1 (0);
	if (efd == -1) {
		perror ("epoll_create");
		return;
	}

	bzero((char *)&event,sizeof(event));
	event.data.fd = csock;
	event.events = EPOLLIN | EPOLLET | EPOLLRDHUP | EPOLLPRI | EPOLLERR ;
	rc = epoll_ctl (efd, EPOLL_CTL_ADD, csock, &event);
	if (rc == -1) {
		perror ("epoll_ctl");
		return;
	}

	event.data.fd = icmp_socket;
	event.events = EPOLLIN | EPOLLET | EPOLLRDHUP | EPOLLPRI | EPOLLERR ;
	rc = epoll_ctl (efd, EPOLL_CTL_ADD, icmp_socket, &event);
	if (rc == -1) {
		perror ("epoll_ctl2");
		return;
	}
	if(icmp6_socket > 0) {
		event.data.fd = icmp6_socket;
		event.events = EPOLLIN | EPOLLET | EPOLLRDHUP | EPOLLPRI | EPOLLERR ;
		rc = epoll_ctl (efd, EPOLL_CTL_ADD, icmp6_socket, &event);
		if (rc == -1) {
			perror ("epoll_ctl2");
			return;
		}
	}
	bzero((char *)&se,sizeof(se));
	bzero((char *)&i_timer,sizeof(i_timer));

	se.sigev_notify = SIGEV_SIGNAL;
    se.sigev_signo = SIGALRM;
	se.sigev_value.sival_ptr = &i_timer;
    rc = timer_create(CLOCK_MONOTONIC, &se, &i_timer);
    if (rc) {
		perror ("timer_create");
        return;
	}
	nfs = 0;
	/* The event loop */
	while (do_work) {
		int n, i;
		int done = 0;
		if(get_next_event(&its,efd)) {
			ping_log(DBG_EVENT,"Wait %d.%03d\n",its.it_value.tv_sec,its.it_value.tv_nsec/1000000);
			timer_settime(i_timer, 0, &its, NULL);
		}
		bzero((char *)events, MAXEVENTS*sizeof(struct epoll_event));
		n = epoll_wait (efd, events, MAXEVENTS, 10*1000);

		if(n < 0 && errno == EINTR) {
			continue;
		}
		if(n < 0) {
			break;
		}
		for (i = 0; i < n; i++) {
			int cfd = events[i].data.fd;
			if ((events[i].events & EPOLLERR) ||
				(events[i].events & EPOLLHUP) ||
				(!(events[i].events & EPOLLIN))) {
						/* An error has occured on this fd, or the socket is not
							 ready for reading (why were we notified then?) */
					if(cfd == icmp_socket || cfd == icmp6_socket || cfd == csock) {
						do_work = 0;
					}
				continue;
			}

			while (cfd == icmp_socket || cfd == icmp6_socket ) {
				struct timeval rtv;
				struct icmphdr *rcv_hdr;
				struct icmp6_hdr *rcv6_hdr;
				struct ping_host *ph;
				char   reply_addr[64];

				rc = recvpacket(cfd,rcv_data,sizeof rcv_data, 0,(struct sockaddr *)&reply,&rtv);
				reply_addr[0] = 0;
				if(rc > 0) {
					if(cfd == icmp6_socket)
						inet_ntop(AF_INET6,&reply6->sin6_addr,reply_addr,sizeof(reply_addr)-1);
					else
						inet_ntop(AF_INET, &reply4->sin_addr,reply_addr,sizeof(reply_addr)-1);
				}
				ping_log(DBG_NET2,"ICMP packet, %s  %d bytes %d:%s\n",
								reply_addr, rc,	rc < 0 ? errno:0, rc < 0 ? strerror(errno):"");
				if (rc <= 0) {
					if(errno == EAGAIN) {
							cfd = -1;
							break;
					}
					if(errno == EINTR) continue;
					ping_total_recv_err++;
					perror("recvfrom");
					cfd = -1;
					break;
				}

				if (rc < sizeof (struct ping_payload)) {
					ping_total_recv_err++;
					ping_log(DBG_ERR,"Error, got short ICMP packet, %d bytes from %s\n", rc, reply_addr);
					continue;
				}
				ph = NULL;
				if(cfd == icmp6_socket) {
                	rcv6_hdr = (void *)&rcv_data[0];
					if (rcv6_hdr->icmp6_type == ICMP6_ECHO_REPLY)
						ph =  ping_host_find_addr6(reply6);
					else
                    	ping_log(DBG_ERR,"Got ICMP6 packet with type 0x%x ?!? from  %s\n", rcv6_hdr->icmp6_type,reply_addr);
				} else {
	                rcv_hdr = (void *)&rcv_data[0];
					if (rcv_hdr->type == ICMP_ECHOREPLY)
						ph = ping_host_find_addr(reply4);
					else
	                    ping_log(DBG_ERR,"Got ICMP packet with type 0x%x ?!? from  %s\n", rcv_hdr->type,reply_addr);
				}
				if(!ph) {
						ping_total_recv_err++;
						ping_log(DBG_ERR,"Unwanted ICMP from %s\n",reply_addr);
						continue;
				}
				if(ping_host_stat(ph,&rtv,rcv_data,rc)) {
						ping_total_recv_err++;
						ping_log(DBG_ERR,"Bad answer from %s\n",reply_addr);
						continue;
				}
				ping_total_recv_ok++;
				ping_log(DBG_NET2, "ICMP Reply,  sequence =  0x%x from %-16s rto %" PRIi64 "  payload %zu\n",
								htons(rcv_hdr->un.echo.sequence),
								reply_addr, ph->rto, rc);
			}
			if(cfd < 0) continue;

			if (csock == cfd) {
				/* We have a notification on the listening socket, which
								 means one or more incoming connections. */
				do {
					struct sockaddr in_addr;
					socklen_t in_len;
					int infd;

					in_len = sizeof in_addr;
					infd = accept (csock, &in_addr, &in_len);
					if (infd == -1) {
						if ((errno != EAGAIN) && (errno != EWOULDBLOCK)) 
							perror ("accept");
						break;
					}
					/* Make the incoming socket non-blocking and add it to the
						 list of fds to monitor. */
					if(check_acl((struct sockaddr_in *)&in_addr) ||
					   make_socket_non_blocking(infd,1) ||
					   add_ping_fd(infd)) {
							shutdown(infd,SHUT_RDWR);
							close(infd);
							continue;
					}
					bzero((char *)&event,sizeof(event));
					event.data.fd = infd;
					event.events = EPOLLIN | EPOLLET | EPOLLRDHUP | EPOLLPRI | EPOLLERR ;
					rc = epoll_ctl (efd, EPOLL_CTL_ADD, infd, &event);
					if (rc == -1) {
						perror ("epoll_ctl");
						shutdown(infd,SHUT_RDWR);
						close(infd);
						del_ping_fd(infd);
					}
					nfs++;
				} while(1);
				continue;
			}
			/* clients connects */
			done = 0;
			while (!done) {
				ssize_t count;
				char buf[256];
				struct ping_cmd *cmd;

				count = read (cfd, buf, sizeof(buf) -1);
				if (count < 0) {
					if (errno != EAGAIN) done = 1,perror ("read");
						else break;
					continue;
				}
				if (count == 0) { // EOF
					done = 1;
					break;
				}
				buf[count] = '\0';
				ping_log(DBG_FD,"cfd %d part read: %s\n",cfd,buf);
				cmd = get_ping_fd(cfd);
				if(!cmd) {
					ping_log(DBG_CRIT,"BUG! get_ping_fd %d NULL\n",cfd);
					done = 1;
					break;
				}
				if(!cmd->wait_reply) {
					if(cmd->p < sizeof(cmd->cmd) - 1) {
						if(sizeof(cmd->cmd) - cmd->p - 1 < count)
								count = sizeof(cmd->cmd) - cmd->p - 1;
						strncat(&cmd->cmd[cmd->p],buf,count);
					}
					if(strchr(buf,'\n')) {
						ping_log(DBG_CMD,"Command: %s n %d\n",cmd->cmd,cfd);
						make_socket_non_blocking(cfd,0);
						if(!ping_command(cmd->cmd,cfd))
								done = 1;
						make_socket_non_blocking(cfd,1);
					}
				}
			}

			if (done) {
				nfs--;
				ping_log (DBG_FD,"cfd %d CLOSE  rest %d\n", cfd,nfs);
				epoll_ctl (efd, EPOLL_CTL_DEL, cfd, NULL);
				shutdown(cfd,SHUT_RDWR);
				close (cfd);
				del_ping_fd(cfd);
			}
		} // for events
	} //while 

	return;
}
void cidr_acl(char *optarg) {
	struct sockaddr_in addr;
	struct ping_acl *acl;
	char *cmd = parse_host_port(&addr,optarg);
	while(cmd && (*cmd == ',' || !*cmd)) {
		acl = calloc(1,sizeof(*acl));
		acl->host = addr;
		acl->next = ACL;
		ACL = acl;
		if(!*cmd) break;
		cmd = parse_host_port(&addr,cmd+1);
	}
	if(*cmd) {
		fprintf(stderr,"Bad addr %s\n",optarg);
		exit(1);
	}
}
void cidr_dst_acl(char *optarg) {

		struct cidr_acl dst;
		char *cmd = cidr_dst_acl_parse(&dst,optarg);
		while(cmd && (*cmd == ',' || !*cmd)) {
			struct cidr_acl *acl = calloc(1,sizeof(struct cidr_acl));
			*acl = dst;
			acl->next = DST_ACL;
			DST_ACL = acl;
			if(!*cmd) break;
			cmd = cidr_dst_acl_parse(&dst,cmd+1);
		}
		if(!cmd || *cmd) {
			exit(1);
		}
}


int main(int argc, char *argv[])
{
    struct sockaddr_in caddr;
    int i,c,do_daemon = 1,do_kill=0;
	int ipv4only = 0;
    int sock=-1,sock6=-1,csock=-1;

    if(!getenv("TZ")) {
		if(!access("/etc/localtime",R_OK))
			setenv("TZ",":/etc/localtime",0);
		else
			fprintf(stderr,"Warning TZ not defined and /etc/localtime not readable!\n");
	}
    tzset();

    pid_file = strdup("/run/ping_server.pid");
    bzero((char *)&caddr,sizeof(caddr));
    caddr.sin_family = AF_INET;
    caddr.sin_addr.s_addr = htonl(0x7f000001);
    caddr.sin_port = htons(19988);
    srandom(getpid());

    while((c=getopt(argc,argv,"4kDd:b:a:A:x:P:")) != -1) {
	switch(c) {
	    case 'a':
			cidr_acl(optarg);
            break;
	    case 'A':
			cidr_dst_acl(optarg);
			break;
	    case 'x':
		    {
			FILE *facl = fopen(optarg,"r");
			if(!facl) {
				fprintf(stderr,"File %s error %s\n",optarg,strerror(errno));
				exit(1);
			}
			while(fgets(rcv_data,sizeof(rcv_data),facl)) {
				char *eol = strchr(rcv_data,'\n');
				if(eol) *eol = '\0';
				cidr_dst_acl(rcv_data);
			}
			fclose(facl);
		    }
			break;
	    case 'b':
		    {
			char *cmd = parse_host_port(&caddr,optarg);
			if(*cmd) {
				fprintf(stderr,"Bad addr:port %s\n",optarg);
				exit(1);
			}
		    }
	        break;
	    case 'd':
		    debug_level = strtol(optarg,NULL,16);
	        break;
	    case 'D':
		    do_daemon = 0;
	        break;
	    case '4':
		    ipv4only  = 1;
	        break;
	    case 'k':
		    do_kill = 1;
	        break;
	    case 'P':
		    pid_file = strdup(optarg);
	        break;
	    case 'h':
	    default:
		    usage();
	}
    }
    if(do_kill) {
	    struct stat pst;
	    int pid = pid_file ? read_pid(pid_file):-1;
	    if(pid > 0) {
		kill(pid,SIGTERM);
		printf("kill -TERM %d\n",pid);
		for(pid=0; pid < 5; pid++) {
			sleep(1);
			if(stat(pid_file,&pst)) {
				printf("Success!\n");
				exit(0);
			}
		}
		printf("Failed!\n");
	    }
	    exit(0);
    }
	/* Buffer where events are returned */
	events = calloc (MAXEVENTS, sizeof(struct epoll_event));
	if(!events) {
			perror("malloc");
			exit(1);
	}
	if(!ACL)
		cidr_acl("127.0.0.1");

    sock = socket(AF_INET,SOCK_DGRAM,IPPROTO_ICMP);
    if (sock < 0) {
        fprintf(stderr,"create ICMP socket: %s\nsysctl -w net.ipv4.ping_group_range=\"%u %u\" missing?\n", strerror(errno), getegid(),getegid());
        exit(1);
    }
    if(set_timestamping(sock))
		exit(1);
	icmp_socket = sock;

	if(!ipv4only) {
	    sock6 = socket(AF_INET6,SOCK_DGRAM,IPPROTO_ICMPV6);
	    if (sock6 < 0) {
	        fprintf(stderr,"create ICMP6 socket: %s\nsysctl -w net.ipv6.ping_group_range=\"%u %u\" missing?\n", strerror(errno), getegid(),getegid());
	    }
    	if(set_timestamping(sock6))
			exit(1);
		icmp6_socket = sock6;	
	}

    for(i = optind; i < argc; i++) {
		struct ping_host *ph = ping_host_init(argv[i],4,3,180);
		if(!ph) {
			fprintf(stderr,"error %s\n",argv[i]);
			close(sock);
			exit(1);
		}
		ph->next_host = ping_host_list;
		ping_host_list = ph;
    }
    if(do_daemon) {
        if(daemon(1,0) < 0) {
			close(sock);
			abort();
		}
		stderr = freopen("/tmp/ping_error.log","a",stderr);
		if(stderr) setlinebuf(stderr);
    }
    if(write_pid()) {
		exit(1);
    }
    csock = get_ctrl_socket(&caddr);
    if(csock < 0 || make_socket_non_blocking (csock,1) < 0) {
		fprintf(stderr,"create ctrl socket error\n");
		goto die;
    }
    {
	static int sig_list[]={SIGINT,SIGTERM,SIGQUIT,SIGALRM};
	int i;
	sigset_t s;
	sigemptyset(&s);
	for(i=0; i < sizeof(sig_list)/sizeof(sig_list[0]); i++) {
		sigaddset(&s,sig_list[i]);
		sysvsignal(sig_list[i],my_sig_quit);
		siginterrupt(sig_list[i],1);
	}
	sigprocmask(SIG_UNBLOCK,&s,NULL);

	sigemptyset(&s);
	sigaddset(&s,SIGPIPE);
	sigprocmask(SIG_BLOCK,&s,NULL);
    }

    signal(SIGALRM,my_sig_hup);
    signal(SIGHUP,my_sig_hup);
    signal(SIGINT,my_sig_int);

    ping_it(&caddr,csock);

die:
	free (events);
	if(sock6 > 0) {
	    shutdown(sock6,SHUT_RDWR);
	    close(sock6);
	}
    shutdown(sock,SHUT_RDWR);
    close(sock);
    shutdown(csock,SHUT_RDWR);
    close(csock);
    if(pid_file_created && pid_file) unlink(pid_file);
    exit(0);
}



/*
 gcc -g -O -o ping_server  -Wall ping_server.c -lrt

 vim: set ts=4:
*/
