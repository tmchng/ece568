/**
 * This file is here because I'm anticipating that the server and the
 * client will be sharing some common SSL code (ie. loading certificates)
 */
#ifndef _ssl_common_h
#define _ssl_common_h

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <fcntl.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>

#include <openssl/ssl.h>

#define CA_LIST "568ca.pem"
#define HOST	"localhost"
#define RANDOM  "random.pem"
#define PORT	8765
#define BUFSIZZ 256

extern BIO *bio_err;
int berr_exit (char *string);
int err_exit(char *string);

SSL_CTX *initialize_ctx(char *keyfile, char *password);
void destroy_ctx(SSL_CTX *ctx);

#ifndef ALLOW_OLD_VERSIONS
#if (OPENSSL_VERSION_NUMBER < 0x00905100L)
#error "Must use OpenSSL 0.9.6 or later"
#endif
#endif

#endif
