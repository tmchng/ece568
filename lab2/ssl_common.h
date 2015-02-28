/**
 * This file is here because I'm anticipating that the server and the
 * client will be sharing some common SSL code (ie. loading certificates)
 */
#ifndef _ssl_common_h
#define _ssl_common_h

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/evp.h>

#define TRUSTED_CA "568ca.pem"

// The BIO object for printing error.
extern BIO *bio_err;

#endif
