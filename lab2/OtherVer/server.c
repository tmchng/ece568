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

#define PORT 8765

/* use these strings to tell the marker what is happening */
#define FMT_ACCEPT_ERR "ECE568-SERVER: SSL accept error\n"
#define FMT_CLIENT_INFO "ECE568-SERVER: %s %s\n"
#define FMT_OUTPUT "ECE568-SERVER: %s %s\n"
#define FMT_INCOMPLETE_CLOSE "ECE568-SERVER: Incomplete shutdown\n"

void print_cert(ssl)
SSL *ssl;
{
    printf("in print cert\n");
    X509 *peer;
    char peer_CN[256];
    char peer_Email[256];
    
    if(SSL_get_verify_result(ssl)!=X509_V_OK)
    {
        berr_exit(FMT_ACCEPT_ERR);
        ERR_print_errors_fp(stdout);
    }
        
    //peer=SSL_get_peer_certificate(ssl);
    
     /*Check if the common name macthes*/
    peer=SSL_get_peer_certificate(ssl);
    X509_NAME_get_text_by_NID(X509_get_subject_name(peer),NID_commonName, peer_CN, 256);
 
      /*check if the email matches*/
    X509_NAME_get_text_by_NID(X509_get_subject_name(peer),NID_pkcs9_emailAddress, peer_Email, 256);
         
    printf(FMT_CLIENT_INFO, peer_CN, peer_Email);   
}



int main(int argc, char **argv)
{
  int s, sock, port=PORT;
  struct sockaddr_in sin;
  int val=1;
  pid_t pid;
  
  /* new varaibles for ssl*/
  SSL_CTX *ctx;
  SSL *ssl;
  BIO *sbio;
  int r;
  /*Parse command line arguments*/
  
  switch(argc){
    case 1:
      break;
    case 2:
      port=atoi(argv[1]);
      if (port<1||port>65535){
	fprintf(stderr,"invalid port number");
	exit(0);
      }
      break;
    default:
      printf("Usage: %s port\n", argv[0]);
      exit(0);
  }

  if((sock=socket(AF_INET,SOCK_STREAM,0))<0){
    perror("socket");
    close(sock);
    exit(0);
  }
  
  memset(&sin,0,sizeof(sin));
  sin.sin_addr.s_addr=INADDR_ANY;
  sin.sin_family=AF_INET;
  sin.sin_port=htons(port);
  
  setsockopt(sock,SOL_SOCKET,SO_REUSEADDR, &val,sizeof(val));
    
  if(bind(sock,(struct sockaddr *)&sin, sizeof(sin))<0){
    perror("bind");
    close(sock);
    exit (0);
  }
  
  if(listen(sock,5)<0){
    perror("listen");
    close(sock);
    exit (0);
  } 
  
  while(1){
    
    if((s=accept(sock, NULL, 0))<0){
      perror("accept");
      close(sock);
      close(s);
      exit (0);
    }
    printf("got the connection tryinbg to fork a child\n");
    /*fork a child to handle the connection*/
    
    if((pid=fork())){
      close(s);
    }
    else {
      /*Child code*/
      int len;
      char buf[256];
      char *answer = "42";
      ctx=initialize_ctx("bob.pem","password");
      SSL_CTX_set_cipher_list(ctx, "SSLv2:SSLv3:TLSv1");
      //SSL_CTX_set_cipher_list(ctx, "ALL:!SHA1");
      SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, 0);
      //SSL_set_cipher_list(ssl, "MD5");
      
      sbio=BIO_new_socket(s,BIO_NOCLOSE);
      ssl=SSL_new(ctx);
      SSL_set_bio(ssl,sbio,sbio);
      int answerLen=strlen(answer);
      
      printf("try to accept\n");
      r=SSL_accept(ssl);
      if(r<=0)
      {
        //printf("r<0\n");
        printf(FMT_ACCEPT_ERR);
        ERR_print_errors_fp(stdout);
        close(s);
        exit (0); 
      }
      print_cert(ssl);
      //printf("after print\n");
      /*connected*/
      r=SSL_read(ssl,buf,256);
      buf[r]='\0';
      switch(SSL_get_error(ssl,r)){
        case SSL_ERROR_NONE:
          printf("anwser is %s\n", answer);
          printf("buf is %s\n", buf);
          printf(FMT_OUTPUT, buf, answer);
          break;
        case SSL_ERROR_WANT_READ:
          continue;
        case SSL_ERROR_ZERO_RETURN:
          goto shutdown;
        case SSL_ERROR_SYSCALL:
          printf(FMT_INCOMPLETE_CLOSE);
          goto done;
        default:
          berr_exit("SSL read problem");
      }
      //printf(FMT_OUTPUT,buf,answer);
      
      printf("writing anwser%s\n",answer);
      r=SSL_write(ssl,answer,strlen(answer));
      switch(SSL_get_error(ssl,r)){      
        case SSL_ERROR_NONE:
          if(answerLen!=r)
          {
              printf("incomplete write");
              err_exit("Incomplete write!");
          }
          destroy_ctx(ctx);
          close(sock);
          return 1;
        case SSL_ERROR_SYSCALL:
          printf(FMT_INCOMPLETE_CLOSE);
          goto done;
        default:
              berr_exit("SSL write problem");
      }
      
      shutdown:
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
        close(s);
        return(0);
      
      /*
      len = recv(s, &buf, 255, 0);
      buf[len]= '\0';
      printf(FMT_OUTPUT, buf, answer);
      send(s, answer, strlen(answer), 0);
      close(sock);
      close(s);
      return 0;
      */
      
    }
  }
  destroy_ctx(ctx);
  close(sock);
  return 1;
}
