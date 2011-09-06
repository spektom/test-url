/*
   +----------------------------------------------------------------+
   | Zend Test Engine                                               |
   +----------------------------------------------------------------+
   | Copyright (c) 1998-2004 Zend Technologies Ltd.                 |
   +----------------------------------------------------------------+
   | The contents of this source file is the sole property of       |
   | Zend Technologies Ltd.  Unauthorized duplication or access is  |
   | prohibited.                                                    |
   +----------------------------------------------------------------+
   | Author:  Michael Spector <michael@zend.com>                    |
   +----------------------------------------------------------------+
*/

#include <sys/types.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <signal.h>

#if defined (WIN32) || defined (WINDOWS)
# define M_WIN32 1
#else
# define M_UNIX 1
#endif


#ifdef M_UNIX
# include <sys/time.h>
# include <sys/resource.h>
# include <sys/ioctl.h>
# include <netdb.h>
# include <netinet/in.h>
# include <netinet/tcp.h>
# include <sys/socket.h>
# include <arpa/inet.h>
# include <sys/wait.h>
# include "config.h"

#if defined(HAVE_HSTRERROR) && !defined(h_errno)
extern int h_errno;
#endif

#else /* M_WIN32 */

# include <stdlib.h>
# include <process.h>
# include <winsock2.h>
# include <io.h>
# include <sys/timeb.h>

# ifndef strcasecmp
#  define strcasecmp _stricmp
# endif

#define WINSOCK_MAJOR 2
#define WINSOCK_MINOR 2

#endif /* M_UNIX */

#if !defined(errno)
extern int errno;
#endif

#ifdef _POSIX_PATH_MAX
# define RESOURCE_PATH_MAX _POSIX_PATH_MAX
#elif defined _MAX_PATH
# define RESOURCE_PATH_MAX _MAX_PATH
#else
# define RESOURCE_PATH_MAX 256
#endif

#define CRLF "\r\n"
#define MAX_HEADER_SIZE 512
#define MAX_RESOURCE_SIZE RESOURCE_PATH_MAX + MAX_HEADER_SIZE
#define MAX_REQUEST_SIZE MAX_RESOURCE_SIZE + MAX_HEADER_SIZE
#define BUF_SIZE 8192
#define SELECT_TIMEOUT 60
#define MAX_ADDR_SIZE 512

#ifndef timersub
# define timersub(a, b, result) \
  do { \
    (result)->tv_sec = (a)->tv_sec - (b)->tv_sec; \
    (result)->tv_usec = (a)->tv_usec - (b)->tv_usec; \
    if ((result)->tv_usec < 0) { \
      --(result)->tv_sec; \
      (result)->tv_usec += 1000000; \
    } \
  } while (0)
# define timeradd(a, b, result) \
  do { \
    (result)->tv_sec = (a)->tv_sec + (b)->tv_sec; \
    (result)->tv_usec = (a)->tv_usec + (b)->tv_usec; \
    if ((result)->tv_usec >= 1000000) { \
			++(result)->tv_sec; \
				(result)->tv_usec -= 1000000; \
		} \
	} while (0)
#endif

enum {P_HTTP};
enum {ST_NOP, ST_BAD, ST_NEW, ST_READ, ST_WRITE, ST_FINISH};

static int debug_mode = 0;
static int daemon_mode = 0;
static int master_mode = 0;
static unsigned short test_url_port = 23456;

#ifdef M_UNIX
/* Store program path and command line arguments here */
static char **prog_argv = NULL;
#endif

#ifdef M_UNIX
# define RECV recv
# define SEND send
#else
# define RECV(s,buf,len,flags) recv(s,(char *)buf,len,flags)
# define SEND(s,buf,len,flags) send(s,(const char *)buf,len,flags)
# define snprintf _snprintf
#endif

struct conn_s
{
	long recieved;
	int sockfd;
	int state;
};

struct req_s
{
	int conc_level;
	int reqs_num;
	int time_limit;
	char url[MAX_ADDR_SIZE];
};

int recv_req_s (int sockfd, struct req_s *req)
{
	static char buf[BUF_SIZE];
	static int n_bytes;

	if(RECV (sockfd, &n_bytes, sizeof(int), 0) == -1) { return -1; }
	if(RECV (sockfd, buf, n_bytes, 0) == -1) { return -1; }
	
	if(sscanf (buf, "%d;%d;%d;%s", &req->conc_level, &req->reqs_num, &req->time_limit, &req->url) != 4) {
		return -1;
	}
	return 0;
}

int send_req_s (int sockfd, struct req_s *req)
{
	static char buf[BUF_SIZE];
	static int n_bytes;

	n_bytes = snprintf (buf, BUF_SIZE, "%d;%d;%d;%s", req->conc_level, req->reqs_num, req->time_limit, req->url);

	if(SEND (sockfd, &n_bytes, sizeof(int), 0) == -1) { return -1; }
	if(SEND (sockfd, buf, n_bytes, 0) == -1) { return -1; }

	return 0;
}

struct result_s
{
	int req_num;
	int req_failed;
	struct timeval time_total;
	double time_per_req;
	double reqs_per_sec;
};

int recv_result_s (int sockfd, struct result_s *res)
{
	static char buf[BUF_SIZE];
	static int n_bytes;

	if(RECV (sockfd, &n_bytes, sizeof(int), 0) == -1) { return -1; }
	if(RECV (sockfd, buf, n_bytes, 0) == -1) { return -1; }
	
	if(sscanf (buf, "%d;%d;%ld;%ld;%lf;%lf", &res->req_num, &res->req_failed,
				&res->time_total.tv_sec, &res->time_total.tv_usec, &res->time_per_req, &res->reqs_per_sec) != 6) {
		return -1;
	}
	return 0;
}

int send_result_s (int sockfd, struct result_s *res)
{
	static char buf[BUF_SIZE];
	static int n_bytes;

	n_bytes = snprintf (buf, BUF_SIZE, "%d;%d;%ld;%ld;%lf;%lf", res->req_num, res->req_failed,
			        res->time_total.tv_sec, res->time_total.tv_usec, res->time_per_req, res->reqs_per_sec);

	if(SEND (sockfd, &n_bytes, sizeof(int), 0) == -1) { return -1; }
	if(SEND (sockfd, buf, n_bytes, 0) == -1) { return -1; }

	return 0;
}

void error(const char * fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	vfprintf(stderr, fmt, args);
	va_end(args);
	exit(-1);
}

void call_error(const char * func)
{
	if(errno != 0) {
		fprintf(stderr, "%s: %s\n", func, strerror(errno));
	}
	else fprintf(stderr, "An error has occurred in function: %s\n", func);
	exit(-1);
}

void socket_call_error(const char * func)
{
#ifdef M_WIN32

	int err = WSAGetLastError();
	error("%s failed. Error code: %d\n", func, err);

	WSACleanup();
#endif /* M_WIN32 */

	call_error(func);
}

void debug_printf(const char * fmt, ...)
{
	va_list args;

	if(!debug_mode) return;

	va_start(args, fmt);
	vfprintf(stderr, fmt, args);
	va_end(args);
}

int validate_c_level(int conc_level)
{
#ifdef M_UNIX
	struct rlimit rlim;

	if(getrlimit(RLIMIT_NOFILE, &rlim) == -1) {
		call_error("getrlimit");
	}
	if((unsigned int)conc_level > rlim.rlim_max) {
		error("Wrong concurrency level.\nMaximum allowed number of file descriptors is: %d\n", rlim.rlim_max);
	}
	// Set current allowed number of file descriptors to maximum
	if((unsigned int)conc_level > rlim.rlim_cur) {
		rlim.rlim_cur = rlim.rlim_max;
		if(setrlimit(RLIMIT_CORE, &rlim) == -1) {
			call_error("setrlimit");
		}
	}
#endif
	return conc_level;
}

int parse_url(char * url, char **hostname, char **resource, unsigned short * port, int * proto)
{
	char * tok;
	struct servent *se;
	
	tok = strtok(url, ":/");
	if(tok) {
		if(strcmp(tok, "http") == 0) {
			*proto = P_HTTP;
		}
		else {
			fprintf(stderr, "Unsupported protocol: %s\n", tok);
			goto url_parse_error;
		}
		se = getservbyname(tok, NULL);

		tok = strtok(NULL, "/");
		*resource = strtok(NULL, "");
		*hostname = strtok(tok, ":");
		tok = strtok(NULL, "");
		if(tok) {
			*port = atoi(tok);
		}
		else {
			if(!se) {
#ifdef M_UNIX
				error("Cannot determine port for this protocol\n");
#else
				socket_call_error("getservbyname");
#endif
			}
			*port = ntohs(se->s_port);
		}
		if(*hostname) {
			return 0;
		}
	}

url_parse_error:
	error("Error parsing url\n");
	return -1;
}

int open_connection(const char * hostname, unsigned short port)
{
	struct sockaddr_in sa;
	struct hostent *hp;
	int sockfd;
	int retval;

	if((sockfd = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) == -1) {
		socket_call_error("socket");
	}

	hp = gethostbyname(hostname);
	if(!hp) {
#ifdef M_UNIX
#ifdef HAVE_HSTRERROR
		error("%s: %s\n", hostname, hstrerror(h_errno));
#else
		error("%s: host resolution error\n", hostname);
#endif /* HAVE_STRERROR */
#else
		socket_call_error("gethostbyname");
#endif
	}

	memset(&sa, 0, sizeof(sa));

	sa.sin_family = hp->h_addrtype;
	sa.sin_port = htons(port);
	memcpy(&sa.sin_addr, hp->h_addr, hp->h_length);

	//debug_printf("Connecting to %s on port %d ...\n", hp->h_name, port);

	if((retval = connect(sockfd, (struct sockaddr*)&sa, sizeof(sa))) == -1) {
		socket_call_error(hostname);
	}
	return sockfd;
}

int send_request(int sockfd, int proto, const char * resource)
{
	int retval;
	int request_size = 0;
	static char buf[MAX_REQUEST_SIZE];

	switch(proto)
	{
		case P_HTTP:
			request_size = snprintf(buf, MAX_REQUEST_SIZE, "GET /%s HTTP/1.0" CRLF CRLF, (resource ? resource : ""));
			break;

		default:
			error("Unknown protocol!\n");
	}

	//debug_printf("Sending request: %s\n", buf);

	retval = SEND(sockfd, buf, request_size, MSG_DONTROUTE);
	if(retval == -1) {
		call_error("send");
	}

	return (retval > 0);
}

#ifdef M_WIN32
/* XXX Not effective function, but used only in Windows */
char * read_line(int sockfd, char * buf, int buf_size)
{
	char ch;
	int retval, i;

	for(i=0; i<buf_size-1; i++)
	{
		retval = RECV(sockfd, &ch, 1, 0);
		if(retval == 0) break;
		if(retval == -1) call_error("recv");

		buf[i] = ch;
		buf[i+1] = '\0';
		if(ch == '\n') {
			break;
		}
	}
	return (i>0 ? buf : NULL);
}
#endif /* M_WIN32 */

int read_header(int sockfd, int proto, long * content_length)
{
	static char buf[MAX_HEADER_SIZE];
	char * tok;

#ifdef M_UNIX
	FILE * sockfp;

	if((sockfp = fdopen(sockfd, "r")) == NULL) {
		call_error("fdopen");
	}
	if(setvbuf(sockfp, (char *)NULL, _IONBF, 0)) {
		call_error("setvbuf");
	}
#endif
	
	if(proto == P_HTTP)
	{

#ifdef M_UNIX
		if(fgets(buf, MAX_HEADER_SIZE, sockfp) != NULL) {
#else
		if(read_line(sockfd, buf, MAX_HEADER_SIZE) != NULL) {
#endif
			if(strstr(buf, "HTTP/1.1 200 OK") != NULL) {

#ifdef M_UNIX
				while(fgets(buf, MAX_HEADER_SIZE, sockfp) != NULL)
#else
				while(read_line(sockfd, buf, MAX_HEADER_SIZE) != NULL)
#endif
				{
					if(strcmp(buf, CRLF) == 0) {
						return 1;
					}
					if(!content_length) {
						continue;
					}
					tok = strtok(buf, ": \t");
					if(tok) {
						if(strcasecmp(buf, "Content-Length") == 0) {
							tok = strtok(NULL, "\r\n");
							if(tok) {
								*content_length = atol(tok);
							}
						}
					}
				}
			}
			else debug_printf("Bad response: %s", buf);
		}
	}
	else {
		error("Cannot read header: unsupported protocol!\n");
	}

	return 0;
}

long guess_content_length(const char * hostname, unsigned short port,
	int proto, const char * resource)
{
	int sockfd;
	long content_length = -1;
	char buf[BUF_SIZE];
	int n_read;

	sockfd = open_connection(hostname, port);

	if(send_request(sockfd, proto, resource)) {
		read_header(sockfd, proto, &content_length);

		// Did not meet the 'Content-Length' in the header, try to read whole content
		// in order to guess its length:
		if(content_length == -1) { 
			content_length = 0;
			while((n_read = RECV(sockfd, buf, BUF_SIZE, 0)) > 0) {
				content_length += n_read;
			}
			if(n_read == -1) {
				call_error("recv");
			}
		}
	}
	else {
		error("Error sending request!\n");
	}

	close(sockfd);
	return content_length;
}

void print_results (struct result_s *res)
{
	printf (
		"Number of requests:\t%d\n"
		"Failed requests:\t%d\n"
		"Total time (sec):\t%d.%.3d\n"
		"Time per request (ms):\t%.2f\n"
		"Requests per second:\t%.2f\n",
		
		res->req_num, res->req_failed,
		res->time_total.tv_sec,	res->time_total.tv_usec,
		res->time_per_req, res->reqs_per_sec
	);
}

void test_url(struct req_s *req, struct result_s *res) 
{
	char * hostname;
	char * resource;
	unsigned short port;
	int proto;

	int i;
	unsigned int sockfd, last;
	static char buf[BUF_SIZE];
	fd_set readset, writeset;
	struct timeval tv_begin, tv_end;
	struct conn_s * connections;
	struct timeval total;
	struct timeval tpr;
	long content_length;
	int state;
	int n_finished, nq_reqs, failed_reqs;

#ifdef M_WIN32
	struct _timeb timeptr;
#endif

	parse_url(req->url, &hostname, &resource, &port, &proto);

	timerclear(&total);
	timerclear(&tpr);

	if(req->time_limit > 0 && req->reqs_num < req->conc_level) {
		req->reqs_num = req->conc_level;
	}

	failed_reqs = 0;
	n_finished = 0;
	if(req->reqs_num < req->conc_level) {
		req->conc_level = req->reqs_num;
	}
	nq_reqs = req->reqs_num;

	content_length = guess_content_length(hostname, port, proto, resource);

	FD_ZERO(&readset);
	FD_ZERO(&writeset);

	connections = (struct conn_s *)malloc(sizeof(struct conn_s) * req->conc_level);
	if(!connections) {
		call_error("malloc");
	}

	for(i=0; i<req->conc_level; i++)
	{
		sockfd = open_connection(hostname, port);
		FD_SET(sockfd, &writeset);
		connections[i].sockfd = sockfd;
		connections[i].state = ST_WRITE;
		if (req->time_limit == -1) {
			nq_reqs --;
		}
	}
	last = sockfd;

	while(n_finished < req->reqs_num || req->time_limit > 0)
	{
		struct timeval timeout;
		struct timeval tdiff;
		int retval;

#ifdef M_UNIX
		if(gettimeofday(&tv_begin, NULL) == -1) {
			call_error("gettimeofday");
		}
#else  /* M_WIN32 */
		_ftime(&timeptr);
		tv_begin.tv_sec = timeptr.time;
		tv_begin.tv_usec = timeptr.millitm * 1000;
#endif /* M_UNIX */

		timerclear (&timeout);
		timeout.tv_sec = SELECT_TIMEOUT;
		retval = select(last +1, &readset, &writeset, NULL, &timeout);

		if(retval == 0 || (retval == -1 && errno != ESPIPE)) {
			call_error("select");
			break;
		}

		for(i=0; i<req->conc_level; i++) {

			if(connections[i].state == ST_NOP) {
				continue;
			}

			state = connections[i].state;
			sockfd = connections[i].sockfd;

			if(FD_ISSET(sockfd, &writeset))
			{
				if(send_request(sockfd, proto, resource)) {
					/* Set flag to -1 in order to start reading header */
					connections[i].recieved = -1; 
					state = ST_READ;
				}
				else state = ST_BAD;
			}
			else if(FD_ISSET(sockfd, &readset))
			{
				/* First we need to read the header */
				if(connections[i].recieved == -1) { 
					if(!read_header(sockfd, proto, NULL)) {
						state = ST_BAD;
					}
					else {
						/* Set flag (and total size) to 0 in order to start reading the content */
						connections[i].recieved = 0; 
						state = ST_READ;
					}
				}
				else {
					int n_read;

					/* Continue receiving from the current socket */
					n_read = RECV(sockfd, buf, BUF_SIZE, 0);
					if(n_read == -1) {
						call_error("recv");
					}
					if(n_read == 0)
					{
						if(connections[i].recieved > content_length) {
							error("Number of recieved bytes (%ld) is more than the content length (%ld)!\n",
									connections[i].recieved, content_length);
						}
						if(connections[i].recieved < content_length) {
							debug_printf("Number of recieved bytes (%ld) is less than the content length (%ld)\n",
									connections[i].recieved, content_length);
							state = ST_BAD;
						}
						else {
							debug_printf("Client #%d recieved %ld bytes\n", i+1, connections[i].recieved);
							state = ST_NEW;
						}
					}
					else {
						connections[i].recieved += n_read;
						state = ST_READ;
					}
				}
			}

			switch (state)
			{
				case ST_READ:
					FD_CLR(sockfd, &writeset);
					FD_SET(sockfd, &readset);
					break;

				case ST_WRITE:
					FD_CLR(sockfd, &readset);
					FD_SET(sockfd, &writeset);
					break;

				case ST_BAD:
					failed_reqs ++;

				case ST_NEW:
					FD_CLR(sockfd, &writeset);
					FD_CLR(sockfd, &readset);
					close(sockfd);
					n_finished ++;
					if(nq_reqs > 0) {
						sockfd = open_connection(hostname, port);
						if(sockfd > last) {
							last = sockfd;
						}
						FD_SET(sockfd, &writeset);
						state = ST_WRITE;
						connections[i].sockfd = sockfd;
						if (req->time_limit == -1) {
							nq_reqs --;
						}
					}
					else state = ST_NOP;
					break;
			}
			connections[i].state = state;
		}
		
#ifdef M_UNIX
		if(gettimeofday(&tv_end, NULL) == -1) {
			call_error("gettimeofday");
		}
#else  /* M_WIN32 */
		_ftime(&timeptr);
		tv_end.tv_sec = timeptr.time;
		tv_end.tv_usec = timeptr.millitm * 1000;
#endif /* M_UNIX */

		timersub(&tv_end, &tv_begin, &tdiff);
		timeradd(&total, &tdiff, &total);

	 	if(req->time_limit > 0 && req->time_limit <= total.tv_sec) {
			break;
		}
	}
	free(connections);

	tpr.tv_sec = total.tv_sec/n_finished;
	tpr.tv_usec = (long)total.tv_usec/n_finished + (total.tv_sec % n_finished)*(long)(1000000.0/n_finished);

	res->req_num = n_finished;
	res->req_failed = failed_reqs;
	res->time_total.tv_sec = total.tv_sec;
	res->time_total.tv_usec = total.tv_usec/1000;
	res->time_per_req = tpr.tv_sec*1000 + (float)tpr.tv_usec*0.001;
	res->reqs_per_sec = 1000.0/(tpr.tv_sec*1000 + (float)tpr.tv_usec*0.001);
}

#if defined(M_UNIX) && !defined(NOFORK)
void kill_child()
{
	int pid, status;
	while ((pid = waitpid(-1, &status, WNOHANG|WUNTRACED)) > 0) {
	}
	signal (SIGCHLD, kill_child);
}

#ifndef HAVE_DAEMON
void daemonize ()
{
	struct sigaction osa, sa;
	struct rlimit rlim;
	rlim_t i;
	int osa_ok;

	/* A SIGHUP may be thrown when the parent exits below. */
	sigemptyset(&sa.sa_mask);
	sa.sa_handler = SIG_IGN;
	sa.sa_flags = 0;
	osa_ok = sigaction( SIGHUP, &sa, &osa);

	switch (fork()) {
		case 0: break;
		case -1: call_error ("fork");
		default: _exit (0);
	}
	/* Only child can reach here */

	setsid ();

	if(osa_ok) {
		sigaction (SIGHUP, &osa, NULL); /* restore SIGHUP behaviour */
	}
	
	if(chdir("/") == -1){
		error ("Cannot go to root directory!\n");
	}

	if(getrlimit(RLIMIT_NOFILE, &rlim)==-1){
		error ("Cannot get maximal number of inodes!\n");
	}
	for(i=3; i<rlim.rlim_max; i++){
		close(i);
	}

	signal (SIGCHLD, kill_child);
	signal (SIGPIPE, SIG_IGN);
}
#endif /* HAVE_DAEMON */

void daemon_restart()
{
	execv (prog_argv[0], prog_argv);
	error ("Cannot restart daemon!\n");
}
#endif /* M_UNIX && !NOFORK */

void free_args (char **args, int args_num)
{
	int i;
	if (args ) {
		for (i=0; i<args_num; i++) {
			free (args[i]);
		}
		free (args);
	}
}

void run_slave ()
{
	int serv_sockfd, clnt_sockfd;
	struct sockaddr_in serv_sa, clnt_sa;
	int clnt_sa_sz, one = 1;
	struct req_s req;
	struct result_s res;

#if defined(M_UNIX) && !defined(NOFORK)
#if defined(HAVE_DAEMON)
	daemon (0, 1);
#else
	daemonize (); /* Use our own daemonizing function */
#endif /* HAVE_DAEMON */
#endif

	if ((serv_sockfd = socket (PF_INET, SOCK_STREAM, IPPROTO_TCP)) == -1) {
		socket_call_error("socket");
	}

#ifdef M_UNIX
	setsockopt (serv_sockfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
	setsockopt (serv_sockfd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
#else
	setsockopt (serv_sockfd, SOL_SOCKET, SO_REUSEADDR, (const char*)&one, sizeof(one));
	setsockopt (serv_sockfd, IPPROTO_TCP, TCP_NODELAY, (const char*)&one, sizeof(one));
#endif

	serv_sa.sin_family = PF_INET;
	serv_sa.sin_addr.s_addr = INADDR_ANY;
	serv_sa.sin_port = htons (test_url_port);

	if (bind (serv_sockfd, (struct sockaddr*)&serv_sa, sizeof(serv_sa)) == -1) {
		socket_call_error ("bind");
	}
	if (listen (serv_sockfd, 5) == -1) {
		socket_call_error ("listen");
	}

	while (daemon_mode) {
		clnt_sa_sz = sizeof (clnt_sa);
		if((clnt_sockfd = accept (serv_sockfd, (struct sockaddr*)&clnt_sa, &clnt_sa_sz)) == -1) {
			socket_call_error ("accept");
		}

#if defined(M_UNIX) && !defined(NOFORK)
		switch (fork()) {
			case 0:
#endif
				if(recv_req_s (clnt_sockfd, &req) == -1) {
#if defined(M_UNIX) && !defined(NOFORK)
					error ("Error receiving request\n");
#else
					printf ("Error receiving request\n");
#endif
				}

				test_url (&req, &res);

				if(send_result_s (clnt_sockfd, &res) == -1) {
#if defined(M_UNIX) && !defined(NOFORK)
					error ("Error sending result\n");
#else
					printf ("Error sending request\n");
#endif
				}
				close (clnt_sockfd);
#if defined(M_UNIX) && !defined(NOFORK)
				exit (0);

			case -1:
				call_error ("fork");

			default:
				close (clnt_sockfd);
		}
#endif
	}
}

char ** read_slaves (const char *slaves_file, int *slaves_num)
{
	char addr_buf[MAX_ADDR_SIZE], **slaves = NULL, *tok;
	FILE *sfp = fopen (slaves_file, "r");
	if (!sfp) {
		call_error (slaves_file);
	}
	
	(*slaves_num) = 0;
	while (fgets (addr_buf, MAX_ADDR_SIZE, sfp) != NULL) {
		tok = strtok (addr_buf, CRLF);
		if (strlen (tok) > 0) {
			slaves = (char **) realloc (slaves, sizeof(char *) * ((*slaves_num)+1));
			slaves[*slaves_num] = strdup(tok);
			(*slaves_num) ++;
		}
	}
	fclose (sfp);

	return slaves;
}

void run_master (const char * slaves_file, struct req_s *req, int print_average)
{
	int i, num_processed, num_failed;
	struct conn_s *connections;
	struct timeval timeout;
	unsigned int sockfd, last;
	int state;
	fd_set readset, writeset;
	int retval;
	struct result_s res_total, res_tmp;

	char **slaves;
	int slaves_num;
	
	slaves = read_slaves (slaves_file, &slaves_num);

	FD_ZERO(&readset);
	FD_ZERO(&writeset);

	connections = (struct conn_s*) malloc (sizeof(struct conn_s) * slaves_num);
	num_processed = 0;
	num_failed = 0;
	memset (&res_total, 0, sizeof(res_total));

	for (i=0; i<slaves_num; i++) {
		sockfd = open_connection (slaves[i], test_url_port);
		connections[i].sockfd = sockfd;
		connections[i].state = ST_WRITE;
		FD_SET(sockfd, &writeset);
	}
	last = sockfd;

	while (num_processed < slaves_num)
	{
		timerclear (&timeout);
		timeout.tv_sec = SELECT_TIMEOUT;
		retval = select(last +1, &readset, &writeset, NULL, &timeout);

		if(retval == 0 || (retval == -1 && errno != ESPIPE)) {
			call_error("select");
			break;
		}

		for (i=0; i<slaves_num; i++) {
			state = connections[i].state;
			sockfd = connections[i].sockfd;

			if(FD_ISSET(sockfd, &writeset)) {
				if (send_req_s (sockfd, req) == -1) {
					state = ST_BAD;
				}
				else state = ST_READ;
			}
			else if(FD_ISSET(sockfd, &readset)) {
				if(recv_result_s (sockfd, &res_tmp) == -1) {
					state = ST_BAD;
				}
				else state = ST_FINISH;
			}

			switch (state) {
				case ST_READ:
					FD_CLR(sockfd, &writeset);
					FD_SET(sockfd, &readset);
					break;

				case ST_BAD:
					FD_CLR(sockfd, &writeset);
					FD_CLR(sockfd, &readset);
					num_failed ++;
					num_processed ++;
					break;

				case ST_FINISH:
					FD_CLR(sockfd, &writeset);
					FD_CLR(sockfd, &readset);
					close(sockfd);
					num_processed ++;

					res_total.req_num += res_tmp.req_num;
					res_total.req_failed += res_tmp.req_failed;
					timeradd (&res_total.time_total, &res_tmp.time_total, &res_total.time_total);
					res_total.time_per_req += res_tmp.time_per_req;
					res_total.reqs_per_sec += res_tmp.reqs_per_sec;

					if (!print_average) {
						printf ("------------- %s ---------------\n", slaves[i]);
						print_results (&res_tmp);
					}

					state = ST_NOP;
					break;
			}
			connections[i].state = state;
		}
	}
	if (num_processed - num_failed > 0) {
		int num_good = num_processed - num_failed;
		res_total.time_total.tv_sec /= num_good;
		res_total.time_total.tv_usec /= num_good;
		res_total.time_per_req /= num_good;
		res_total.reqs_per_sec /= num_good;

		if (print_average) {
			print_results (&res_total);
		}
	}

	free (connections);
	free_args (slaves, slaves_num);
}

void help(const char * argv0, const char *error)
{
	if(error) {
		fprintf (stderr, "ERROR: %s\n\n", error);
	}
	fprintf(stderr,
			"USAGE: %s [options] url | %s -D"
			"\n\n"
			"options:\n\n"
			"-h           Show this help\n"
			"-c number    Number of concurrent clients\n"
			"-n number    Number of requests\n"
			"-t seconds   Benchmarking time limit\n"
			"-d           Debug mode\n"
			"-D           Run in daemon mode\n"
			"-M file      Run in master mode, provide file containing addresses of slaves\n"
			"-a           Print average of all slaves' results\n"
			, argv0, argv0);
}

int main(int argc, char **argv)
{
#ifdef M_WIN32
	WORD wVersionRequested;
	WSADATA wsaData;
#endif
	const char *slaves_file = NULL;
	struct req_s req;
	struct result_s res;
	int i, print_average = 0;
	static char prog_name[RESOURCE_PATH_MAX];

#ifdef M_UNIX
	prog_argv = (char **) malloc(sizeof(char *)*(argc+1));
	for (i=0; i<argc; i++) {
		prog_argv[i] = argv[i];
	}
	prog_argv[i] = NULL;

	if(argv[0][0] != '/') { /* set program name to full path */
		snprintf (prog_name, RESOURCE_PATH_MAX, "%s/%s",  getcwd(prog_argv, RESOURCE_PATH_MAX), argv[0]);
		prog_argv[0] = prog_name;
		printf ("Setting progname to: %s\n", prog_name);
	}
#endif /* M_UNIX */

	req.conc_level = 1;
	req.reqs_num = 1;
	req.time_limit = -1;
	req.url[0] = '\0';

#ifdef M_WIN32
	wVersionRequested = MAKEWORD(WINSOCK_MAJOR, WINSOCK_MINOR);
	
	if(WSAStartup(wVersionRequested, &wsaData) != 0) {
		error("Could not find a usable WinSock DLL\n");
	}
	if(LOBYTE(wsaData.wVersion) != WINSOCK_MAJOR || HIBYTE(wsaData.wVersion) != WINSOCK_MINOR) {
		error("Could not find a usable WinSock DLL\n");
		WSACleanup();
	}
#endif /* M_WIN32 */
	
	if (argc == 2 && strcmp(argv[1], "-D") == 0) {
		daemon_mode = 1;
	}

	if(daemon_mode) {
		run_slave ();
	}
	else {
		for(i=1; i<argc; i++) {
			if(!strcmp(argv[i], "-t") && i+1 < argc) { req.time_limit = atoi(argv[++i]); }
			else if(!strcmp(argv[i], "-n") && i+1 < argc) { req.reqs_num = atoi(argv[++i]); }
			else if(!strcmp(argv[i], "-c") && i+1 < argc) { req.conc_level = validate_c_level(atoi(argv[++i])); }
			else if(!strcmp(argv[i], "-M") && i+1 < argc) { master_mode = 1; slaves_file = argv[++i]; }
			else if(!strcmp(argv[i], "-a")) { print_average = 1; }
			else if(!strcmp(argv[i], "-d")) { debug_mode = 1; }
			else if(!strcmp(argv[i], "-h")) { help(argv[0], NULL); exit(0); }
			else if(req.url[0] == '\0') { strcpy (req.url, argv[i]); }
			else { help(argv[0], NULL); exit(-1); }
		}
		if(req.url[0] == '\0') { help(argv[0], NULL); exit(-1); }

		if (master_mode) {
			run_master (slaves_file, &req, print_average);
		}
		else {	
			test_url (&req, &res);
			print_results (&res);
		}
	}

#ifdef M_WIN32
	WSACleanup();
#else
	free (prog_argv);
#endif

	exit (0);
}
