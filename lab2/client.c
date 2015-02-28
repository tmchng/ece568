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
#define CLIENT_KEYFILE "alice.pem"
#define CLIENT_KEYFILE_PWD "password"
#define SERVER_CERT_CN "Bob's Server"
#define SERVER_CERT_EMAIL "ece568bob@ecf.utoronto.ca"
#define SSL_MAX_READ_LEN 256

/* use these strings to tell the marker what is happening */
#define FMT_CONNECT_ERR "ECE568-CLIENT: SSL connect error\n"
#define FMT_SERVER_INFO "ECE568-CLIENT: %s %s %s\n"
#define FMT_OUTPUT "ECE568-CLIENT: %s %s\n"
#define FMT_CN_MISMATCH "ECE568-CLIENT: Server Common Name doesn't match\n"
#define FMT_EMAIL_MISMATCH "ECE568-CLIENT: Server Email doesn't match\n"
#define FMT_NO_VERIFY "ECE568-CLIENT: Certificate does not verify\n"
#define FMT_INCORRECT_CLOSE "ECE568-CLIENT: Premature close\n"


// Structure for packaging things needed to open/close connection
struct SSL_PKG {
  int tcp_socket;
  SSL *ssl;
  SSL_CTX *ssl_ctx;
};


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


SSL_CTX *init_ctx(char *keyfile, char *password, int ctx_opts) {
  const SSL_METHOD *method;
  SSL_CTX *ctx;

  method = SSLv23_method();
  ctx = SSL_CTX_new(method);

  // Option flags can be used to disable SSLv2
  SSL_CTX_set_options(ctx, ctx_opts);

  // Load keys and certificates
  if (!SSL_CTX_use_certificate_chain_file(ctx, keyfile)) {
    printf(FMT_CONNECT_ERR);
    ERR_print_errors(bio_err);
    printf("Cannot read certificate file\n");
    exit(EXIT_FAILURE);
  }

  // Set password used to decrypt private key
  SSL_CTX_set_default_passwd_cb_userdata(ctx, password);

  // Read private key
  if (!SSL_CTX_use_PrivateKey_file(ctx, keyfile, SSL_FILETYPE_PEM)) {
    printf(FMT_CONNECT_ERR);
    ERR_print_errors(bio_err);
    printf("Cannot read key file\n");
    exit(EXIT_FAILURE);
  }

  // Load trusted CA
  if (!SSL_CTX_load_verify_locations(ctx, TRUSTED_CA, 0)) {
    printf(FMT_CONNECT_ERR);
    ERR_print_errors(bio_err);
    printf("Cannot read CA\n");
    exit(EXIT_FAILURE);
  }

  return ctx;
}


void check_cert(SSL *ssl, char *correct_CN, char *correct_email) {
  const int STR_LEN = 256;
  X509 *peer;
  X509_NAME *peer_subject_name;
  char peer_CN[STR_LEN];
  char peer_email[STR_LEN];
  char issuer_name[STR_LEN];
  int error = 0;

  if (SSL_get_verify_result(ssl) != X509_V_OK) {
    printf(FMT_NO_VERIFY);
    ERR_print_errors(bio_err);
    exit(EXIT_FAILURE);
  }

  // Obtain CN and email address
  peer = SSL_get_peer_certificate(ssl);
  if (!peer) {
    printf(FMT_CONNECT_ERR);
    exit(EXIT_FAILURE);
  }
  peer_subject_name = X509_get_subject_name(peer);
  X509_NAME_get_text_by_NID(peer_subject_name, NID_commonName, peer_CN, STR_LEN);
  X509_NAME_get_text_by_NID(peer_subject_name, OBJ_txt2nid("emailAddress"), peer_email, STR_LEN);
  X509_NAME_oneline(X509_get_issuer_name(peer), issuer_name, STR_LEN);

  // Check CN
  if (strcasecmp(peer_CN, correct_CN)) {
    printf(FMT_CN_MISMATCH);
    ERR_print_errors(bio_err);
    error = 1;
  }
  // Check email
  if (strcasecmp(peer_email, correct_email)) {
    printf(FMT_EMAIL_MISMATCH);
    ERR_print_errors(bio_err);
    error = 1;
  }

  if (error) {
    exit(EXIT_FAILURE);
  }

  // Print verified server info
  printf(FMT_SERVER_INFO, peer_CN, peer_email, issuer_name);
}


void ssl_init() {
  if (!bio_err) {
    // Init things necessary to make SSL work
    //OpenSSL_add_all_algorithms();
    SSL_library_init();
    SSL_load_error_strings();
    ERR_load_BIO_strings();
    //ERR_load_crypto_strings();
    bio_err = BIO_new_fp(stdout, BIO_NOCLOSE);
  }
}


struct SSL_PKG* ssl_connect(char* host, int port, char *keyfile, char *password) {
  SSL_CTX *ctx;
  SSL *ssl;
  int tcp_socket;

  // Create tcp connection
  tcp_socket = tcp_connect(host, port);

  if (tcp_socket == 0) {
    exit(EXIT_FAILURE);
  }

  // Init things necessary to run ssl
  ssl_init();

  ctx = init_ctx(CLIENT_KEYFILE, CLIENT_KEYFILE_PWD, SSL_OP_NO_SSLv2);
  ssl = SSL_new(ctx);

  if (!SSL_set_fd(ssl, tcp_socket)) {
    printf(FMT_CONNECT_ERR);
    ERR_print_errors(bio_err);
    printf("Cannot join ssl and tcp handle\n");
    exit(EXIT_FAILURE);
  }

  // Initiate SSL handshake
  if (SSL_connect(ssl) <= 0) {
    printf(FMT_CONNECT_ERR);
    ERR_print_errors(bio_err);
    printf("SSL_connect function error\n");
    exit(EXIT_FAILURE);
  }

  // Check certificate
  check_cert(ssl, SERVER_CERT_CN, SERVER_CERT_EMAIL);

  // Return the connection objects as a package
  struct SSL_PKG *pkg = malloc(sizeof(struct SSL_PKG));
  pkg->ssl = ssl;
  pkg->tcp_socket = tcp_socket;
  pkg->ssl_ctx = ctx;
  return pkg;
}


void ssl_disconnect(struct SSL_PKG *pkg) {
  int result;

  if (pkg->ssl) {
    result = SSL_shutdown(pkg->ssl);
    if (!result) {
      /*
       * If we called SSL_shutdown() first then
       * we always get return value of ’0’. In this case,
       * try again, but first send a TCP FIN to trigger the
       * other side’s close_notify
       */
      shutdown(pkg->tcp_socket, 1);
      result = SSL_shutdown(pkg->ssl);
    }

    switch(result) {
      case 1:
        // SSL shutdown properly
        break;
      case 0:
      case -1:
      default:
        printf(FMT_INCORRECT_CLOSE);
        break;
    }
  }

  if (pkg->tcp_socket) {
    close(pkg->tcp_socket);
  }

  if (pkg->ssl_ctx) {
    SSL_CTX_free(pkg->ssl_ctx);
  }

  free(pkg);
}


void ssl_write(struct SSL_PKG *pkg, char *msg) {
  int result;
  if (pkg && pkg->ssl) {
    result = SSL_write(pkg->ssl, msg, strlen(msg));
    switch(SSL_get_error(pkg->ssl, result)) {
      case SSL_ERROR_NONE:
        if (strlen(msg) != result) {
          printf("Incomplete write\n");
          exit(EXIT_FAILURE);
        }
        break;
      default:
        printf("SSL write problem\n");
        ERR_print_errors(bio_err);
        exit(EXIT_FAILURE);
    }
  }
}


void ssl_read(struct SSL_PKG *pkg, char *buf, const int read_len) {
  int result;
  if (pkg && pkg->ssl) {
    result = SSL_read(pkg->ssl, buf, read_len);

    switch(SSL_get_error(pkg->ssl, result)) {
      case SSL_ERROR_SYSCALL:
        // Premature close according to the pdf
        printf(FMT_INCORRECT_CLOSE);
        break;
      case SSL_ERROR_NONE:
      case SSL_ERROR_ZERO_RETURN:
      default:
        printf("SSL read problem\n");
        ERR_print_errors(bio_err);
        exit(EXIT_FAILURE);
    }
  }
}


void test_tcp(char *host, int port) {
  // The original code for connecting to the server
  int len, sock;
  char buf[256];
  char *secret = "What's the question?";
  sock = tcp_connect(host, port);
  if (sock) {
    send(sock, secret, strlen(secret),0);
    len = recv(sock, &buf, 255, 0);
    buf[len]='\0';
  } else {
    perror("Connect failed");
    exit(EXIT_FAILURE);
  }

  /* this is how you output something for the marker to pick up */
  printf(FMT_OUTPUT, secret, buf);

  close(sock);
}


int main(int argc, char **argv)
{
  int port=PORT;
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

  // Original code
  //test_tcp(host, port);

  // Lab2
  struct SSL_PKG *pkg = ssl_connect(host, port, CLIENT_KEYFILE, CLIENT_KEYFILE_PWD);
  ssl_write(pkg, secret);
  ssl_read(pkg, buf, SSL_MAX_READ_LEN);
  printf(FMT_OUTPUT, secret, buf);

  return 1;
}
