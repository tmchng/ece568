#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "ssl_common.h"

#define HOST "localhost"
#define PORT 8765
#define EMAIL "ece568bob@ecf.utoronto.ca"
#define KEY_FILE "alice.pem"
#define SERVER "Bob's Server"

/* use these strings to tell the marker what is happening */
#define FMT_CONNECT_ERR "ECE568-CLIENT: SSL connect error\n"
#define FMT_SERVER_INFO "ECE568-CLIENT: %s %s %s\n"
#define FMT_OUTPUT "ECE568-CLIENT: %s %s\n"
#define FMT_CN_MISMATCH "ECE568-CLIENT: Server Common Name doesn't match\n"
#define FMT_EMAIL_MISMATCH "ECE568-CLIENT: Server Email doesn't match\n"
#define FMT_NO_VERIFY "ECE568-CLIENT: Certificate does not verify\n"
#define FMT_INCORRECT_CLOSE "ECE568-CLIENT: Premature close\n"

int tcp_connect(host,port)
char *host;
int port;
{
    struct hostent *hp;
    struct sockaddr_in addr;
    int sock;
    
    if(!(hp=gethostbyname(host)))
        berr_exit("Client Couldn't resolve host");
    memset(&addr,0,sizeof(addr));
    addr.sin_addr=*(struct in_addr*)
    hp->h_addr_list[0];
    addr.sin_family=AF_INET;
    addr.sin_port=htons(port);
    
    if((sock=socket(AF_INET,SOCK_STREAM,IPPROTO_TCP))<0)
        err_exit("Client Couldn't create socket");
        
    if(connect(sock,(struct sockaddr *)&addr,sizeof(addr))<0)
        err_exit("Client Couldn't connect socket");
        
    return sock;
}

int check_cert(ssl)
SSL *ssl;
{
  printf("in check cert\n");
  X509 *peer;
  char peer_CN[256];
  char peer_Email[256];
  char cert_Issuer[256];

  printf("result is %d\n",SSL_get_verify_result(ssl));
  printf("v ok is %d\n",X509_V_OK);
  if(SSL_get_verify_result(ssl)!=X509_V_OK)
  {
    berr_exit(FMT_NO_VERIFY);
    return 0;
  }

  /*Check if the common name macthes*/
  peer=SSL_get_peer_certificate(ssl);
  X509_NAME_get_text_by_NID(X509_get_subject_name(peer),NID_commonName, peer_CN, 256);
  if(strcasecmp(peer_CN,SERVER))
  {
    berr_exit(FMT_CN_MISMATCH);
    //err_exit(FMT_CN_MISMATCH);
    return 0;
  }
  
  /*check if the email matches*/
  X509_NAME_get_text_by_NID(X509_get_subject_name(peer),NID_pkcs9_emailAddress, peer_Email, 256);
  if(strcasecmp(peer_Email,EMAIL))
  {
    berr_exit(FMT_EMAIL_MISMATCH);
    //err_exit(FMT_EMAIL_MISMATCH);
    return 0;
  }
 
  X509_NAME_get_text_by_NID (X509_get_issuer_name(peer),NID_commonName,cert_Issuer,256);
    
  printf(FMT_SERVER_INFO,peer_CN,peer_Email,cert_Issuer);
  return 1;
}

static int http_request(ssl,host,port,request)
  SSL *ssl;
  char *host;
  int port;
  char *request;
{
    //char *request=0;
    //char buf[256];
    char buf[256]; 
    int r;
    int request_len;
    request_len=strlen(request);
    
    /* Now construct our HTTP request */
    r=SSL_write(ssl,request,request_len);

    switch(SSL_get_error(ssl,r)){      
      case SSL_ERROR_NONE:
        if(request_len!=r)
        {
            //printf("incomplete write");
            err_exit("Incomplete write!");
        }
        break;
      case SSL_ERROR_SYSCALL:
        printf("incorrect close\n");
        berr_exit(FMT_INCORRECT_CLOSE);
        goto done;
      default:
        //printf("SSL write problem\n");
        berr_exit("SSL write problem");
    }

    /* Now read the server's response, assuming
       that it's terminated by a close */
    while(1){
      r=SSL_read(ssl,buf,256);
      buf[r]='\0';
      printf("r is %d\n",r);
      switch(SSL_get_error(ssl,r)){
        case SSL_ERROR_NONE:
          printf("buf is %s\n", buf);
          printf(FMT_OUTPUT, request, buf);
          return 1;
        case SSL_ERROR_WANT_READ:
          continue;
        case SSL_ERROR_ZERO_RETURN:
          goto shutdown;
        case SSL_ERROR_SYSCALL:
          berr_exit(FMT_INCORRECT_CLOSE);
          goto done;
        default:
          //printf("SSL read problem");
          berr_exit("SSL read problem");
      }
    }
    
  shutdown:
    printf("shutting down\n");
    r=SSL_shutdown(ssl);
    switch(r){
      case 1:
        break; /* Success */
      case 0:
      case -1:
      default:
        berr_exit("Shutdown failed");
    }
    
  done:
    SSL_free(ssl);
    //free(request);
    return(0);
}

int main(int argc, char **argv)
{
  int len, sock, port=PORT;
  char *host=HOST;
  struct sockaddr_in addr;
  struct hostent *host_entry;
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
  
  if((sock=socket(AF_INET, SOCK_STREAM, IPPROTO_TCP))<0)
    perror("socket");
  if(connect(sock,(struct sockaddr *)&addr, sizeof(addr))<0)
    perror("connect");
  
  /*Initialize bio context and so on*/
  SSL_CTX *ctx;
  SSL *ssl;
  BIO *sbio;
  
  ctx = initialize_ctx(KEY_FILE, "password");
  SSL_CTX_set_options(ctx,SSL_OP_NO_SSLv2);
  SSL_CTX_set_cipher_list(ctx,"SHA1");
  
  /*connect to the tcp socket*/
  /* dont need tcp connect? */
  //sock=tcp_connect(host,port);
  /*connect to the ssl socket*/
  ssl=SSL_new(ctx);
  sbio=BIO_new_socket(sock,BIO_NOCLOSE);
  SSL_set_bio(ssl,sbio,sbio);
  
  /* ssl hand shaking*/
  int returnVal=SSL_connect(ssl);
  printf("return val is %d\n",returnVal);
  if(returnVal<=0)
  {
    printf(FMT_CONNECT_ERR);
    ERR_print_errors_fp(stdout);
    destroy_ctx(ctx);
    close(sock);
    return 1;
  }
  
  //printf("check ssl cert");
  int flag=1;
  if(check_cert(ssl))
  {
    flag=http_request(ssl,host,port,secret);
  }
 
  printf("Closing ssl connection\n");
  if(flag)
  {
      destroy_ctx(ctx);
      close(sock);
      return 1;
  }
  return 0;
}
