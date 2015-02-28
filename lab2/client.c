#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>

// Added for sharing common ssl functions.
#include "ssl_common.h"

#define HOST "localhost"
#define PORT 8765
#define SERVER_CERT_CN "Bob's Server"
#define SERVER_CERT_EMAIL "ece568bob@ecf.utoronto.ca"

/* use these strings to tell the marker what is happening */
#define FMT_CONNECT_ERR "ECE568-CLIENT: SSL connect error\n"
#define FMT_SERVER_INFO "ECE568-CLIENT: %s %s %s\n"
#define FMT_OUTPUT "ECE568-CLIENT: %s %s\n"
#define FMT_CN_MISMATCH "ECE568-CLIENT: Server Common Name doesn't match\n"
#define FMT_EMAIL_MISMATCH "ECE568-CLIENT: Server Email doesn't match\n"
#define FMT_NO_VERIFY "ECE568-CLIENT: Certificate does not verify\n"
#define FMT_INCORRECT_CLOSE "ECE568-CLIENT: Premature close\n"

#define PWD "password"

int tcp_connect(char *host, int port) {
  int sock;
  struct sockaddr_in addr;
  struct hostent *host_entry;

  /*get ip address of the host*/
  host_entry = gethostbyname(host);

  if (!host_entry){
    fprintf(stderr,"Couldn't resolve host");
    exit(0);
  }

  memset(&addr,0,sizeof(addr));
  addr.sin_addr=*(struct in_addr *) host_entry->h_addr_list[0];
  addr.sin_family=AF_INET;
  addr.sin_port=htons(port);

  printf("Connecting to %s(%s):%d\n", host, inet_ntoa(addr.sin_addr),port);

  /*open socket*/
  if((sock=socket(AF_INET, SOCK_STREAM, IPPROTO_TCP))<0) {
    perror("socket");
    sock = 0;
  }
  if(connect(sock,(struct sockaddr *)&addr, sizeof(addr))<0) {
    perror("connect");
    sock = 0;
  }

  return sock;
}

void ssl_init() {
  //OpenSSL_add_all_algorithms();
  SSL_library_init();
  SSL_load_error_strings();
  ERR_load_BIO_strings();
  //ERR_load_crypto_strings();
}

void ssl_connect() {
  ssl_init();
}

void check_cert(SSL *ssl, char *host) {
  X509 *peer;
  char peer_CN[256];

  if (SSL_get_verify_result(ssl) != X509_V_OK) {
    printf(FMT_NO_VERIFY);
    exit(EXIT_FAILURE);
  }

  peer = SSL_get_peer_certificate(ssl);
  // TODO: continue from here
}

int main(int argc, char **argv)
{
  int len, sock, port=PORT;
  char *host=HOST;
  char buf[256];
  char *secret = "What's the question?";

  /*Parse command line arguments*/

  switch(argc){
    case 1:
      break;
    case 3:
      host = argv[1];
      port=atoi(argv[2]);
      if (port<1||port>65535){
	fprintf(stderr,"invalid port number");
	exit(0);
      }
      break;
    default:
      printf("Usage: %s server port\n", argv[0]);
      exit(0);
  }

  sock = tcp_connect(host, port);
  if (sock) {
    send(sock, secret, strlen(secret),0);
    len = recv(sock, &buf, 255, 0);
    buf[len]='\0';
  } else {
    perror("Connect failed");
    return 0;
  }

  /* this is how you output something for the marker to pick up */
  printf(FMT_OUTPUT, secret, buf);

  close(sock);
  return 1;
}
