/*******************************************************************
 * Secure Chat Application
 *
 * These functions are common to both the client and the server.
 * Do not modify any of these functions.
 *
 *******************************************************************/

#include <iostream>
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <unistd.h>
#include <arpa/inet.h>

#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#include "common.h"
#include "common-ws.h"

using namespace std;

/*******************************************************************/
// Generate <num> bytes of crytographically strong
//   random bytes and store in <buffer>
//
// Returns 0/1 for failure/success

int GetRandomBytes(byte *buffer, int num) {
    return RAND_bytes(buffer, num);
}

/*******************************************************************/
// Initialize OpenSSL
//   from: https://wiki.openssl.org/index.php/Libcrypto_API

void OpenSSLInit() {
    // load the human readable error strings for libcrypto 
    ERR_load_crypto_strings();

    // load all digest and cipher algorithms 
    OpenSSL_add_all_algorithms();

    // load config file, and other important initialisation 
    OPENSSL_config(NULL);

    // seed random number generator
    int rc = RAND_load_file("/dev/random", 32);
    if(rc != 32) {
        cout << "[PRNG seeding failed]" << endl;
        exit(1);
    }
}

/*******************************************************************/
// Cleanup OpenSSL
//   from: https://wiki.openssl.org/index.php/Libcrypto_API

void OpenSSLCleanup() {
    // removes all digests and ciphers
    EVP_cleanup();

    // if you omit the next, a small leak may be left when you make 
    // use of the BIO (low level API) for e.g. base64 transformations 
    CRYPTO_cleanup_all_ex_data();

    // remove error strings 
    ERR_free_strings();
}

/*******************************************************************/
// Send a message into <msg> of length <len> using socket <dest>
// 
// Returns number of bytes sent, or -1 on error

ssize_t SendAMessage(int dest, byte *msg, int len) {
    ssize_t ret = send(dest, msg, len, MSG_NOSIGNAL);
    return ret;
}

/*******************************************************************/
// Receive a message into <buffer> of max length <buffer_size>
//   using socket <src>
//
// Returns number of bytes read, or -1 on error

ssize_t ReceiveAMessage(int src, byte *buffer, int buffer_size) {
    ssize_t ret = recv(src,buffer, buffer_size, 0);
    return ret;
}

/*******************************************************************/
// Send a byte array <b> using socket <dest>
//   first the length b->len is sent and then the array
//   b->value is sent
//
// Returns SUCCESS or FAILURE

int SendBytes(int dest, bytes_t *b) {
    ssize_t sent;

    sent = SendAMessage(dest, (byte *)&b->len, sizeof(unsigned int));

    if (sent != sizeof(unsigned int)) return FAILURE;

    if (b->value && b->len!=0) {
        sent = SendAMessage(dest, b->value, b->len);
        if (sent != b->len) return FAILURE;
    }

    return SUCCESS;
}

/*******************************************************************/
// Receive a byte array  into <b> using socket <src>
//   b->value will be allocated as per received b->len
//
// Returns SUCCESS or FAILURE

int ReceiveBytes(int src, bytes_t *b) {
    ssize_t recv;

    recv = ReceiveAMessage(src, (byte *)&b->len, sizeof(unsigned int));

    if (recv != sizeof(unsigned int)) return FAILURE;

    if (b->len != 0) {
        b->value = new byte[b->len];
        recv = ReceiveAMessage(src,b->value,b->len);
        if (recv != b->len) {
            delete(b->value);
            return FAILURE;
        }
    }

    return SUCCESS;
}

/*******************************************************************/
// Prints <buff> of length <len> preceeded by <label>

void PrintBytes(const char *label, byte *buff, int len) {
    if (label) cout << label;
    for (int i=0; i<len; i++)
        printf("%02X",buff[i]);

    cout << endl;
}

/*******************************************************************/
// Encrypt <plaintext> of length <plaintext_len> using <key> 
//   and <iv> and place in <ciphertext>; AES-128-CBC is used for
//   encryption
//
// Returns FAILURE or length of encrypted ciphertext

int EncryptMessage(byte *plaintext, int plaintext_len, byte *key,
                   byte *iv, byte *ciphertext)  {
  
    int ret = FAILURE;

    EVP_CIPHER_CTX *ctx = NULL;
 
    int len;
    int ciphertext_len;

    // create and initialise the context 
    if(!(ctx = EVP_CIPHER_CTX_new())) return FAILURE;

    // initialize the encryption operation. IMPORTANT - ensure you use a key
    // and IV size appropriate for your cipher
    // we will use AES-128-CBS with 128 bit key and IV
    if(1 != EVP_EncryptInit(ctx, EVP_aes_128_cbc(), key, iv)) goto done;

    // provide the message to be encrypted, and obtain the encrypted output
    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len)) 
        goto done;

    ciphertext_len = len;

    // finalize the encryption
    if(1 != EVP_EncryptFinal(ctx, ciphertext + len, &len)) 
        goto done;

    ciphertext_len += len;
    ret = ciphertext_len;

    done:

    // clean up
    EVP_CIPHER_CTX_free(ctx);

    return ret;
}

/*******************************************************************/
// Decrypt <ciphertext> of length <ciphertext_len> using <key> 
//   and <iv> and place in <plaintext>; AES-128-CBC is used for
//   decryption
//
// Returns FAILURE or length of plaintext

int DecryptMessage(byte *ciphertext, int ciphertext_len, byte *key,
                   byte *iv, byte *plaintext)  {
  
    int ret = FAILURE;

    EVP_CIPHER_CTX *ctx;

    int len;
    int plaintext_len;

    // create and initialise the context 
    if(!(ctx = EVP_CIPHER_CTX_new())) return FAILURE;

    // initialize the decryption operation. IMPORTANT - ensure you use a key
    // and IV size appropriate for your cipher
    // we will use AES-128 with 128 bit key and IV
    if(1 != EVP_DecryptInit(ctx, EVP_aes_128_cbc(), key, iv)) goto done;

    // provide the message to be decrypted, and obtain the plaintext output
    if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)) 
        goto done;

    plaintext_len = len;

    // finalize the encryption
    if(1 != EVP_DecryptFinal(ctx, plaintext + len, &len)) goto done;
    
    plaintext_len += len;
    ret = plaintext_len;

    done:

    // clean up
    EVP_CIPHER_CTX_free(ctx);

    return ret;
}

/*******************************************************************/
// Compute SHA256 HMAC of <message> using key <key> and store it 
//   in <digest>; the length of the message is in <message_len>;
//   the length of the key is in <key_len>; digest length will be 
//   written to <digest_len>
//
// Memory will be allocated for <digest>
//
// Returns SUCCESS or FAILURE


int HMACMessage(byte *message, size_t message_len, byte *key, int key_len, 
                byte **digest, unsigned int *digest_len) {

    EVP_MD_CTX *mdctx;
    const EVP_MD* md;
    EVP_PKEY *pkey;

    int ret = FAILURE;

    if((mdctx = EVP_MD_CTX_create()) == NULL)
	goto done;

    if ((md = EVP_get_digestbyname("SHA256")) == NULL)
        goto done;

   if(!(pkey = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, NULL, key, key_len)))
        goto done;

    if(1 != EVP_DigestSignInit(mdctx, NULL, md, NULL, pkey))
        goto done;

    if(1 != EVP_DigestSignUpdate(mdctx, message, message_len))
        goto done;

    if(1 != EVP_DigestSignFinal(mdctx, NULL, digest_len))
        goto done;

    if((*digest = (unsigned char *)OPENSSL_malloc(*digest_len)) == NULL)
        goto done;

    if(1 != EVP_DigestSignFinal(mdctx, *digest, digest_len))
        goto done;

    ret =  SUCCESS;

    done:

    // clean up
    EVP_PKEY_free(pkey);
    EVP_MD_CTX_destroy(mdctx);
    if (*digest && ret==FAILURE) OPENSSL_free(*digest);

    return ret;
}

/*******************************************************************/
// Compute digest of <message> using method <algo> and store it in
//   <digest>; the length of the message is in <message_len>;
//   digest length will be written to <digest_len>
//
// Memory will be allocated for <digest>
//
// Example <algo>: EVP_md5(), EVP_sha256()
//
// Returns SUCCESS or FAILURE 

int DigestMessage(byte *message, size_t message_len, const EVP_MD *algo, 
                  byte **digest, unsigned int *digest_len) {
    EVP_MD_CTX *mdctx;

    int ret = FAILURE;

    if((mdctx = EVP_MD_CTX_create()) == NULL)
	goto done;

    if(1 != EVP_DigestInit_ex(mdctx, algo, NULL))
        goto done;

    if(1 != EVP_DigestUpdate(mdctx, message, message_len))
        goto done;

    if((*digest = (unsigned char *)OPENSSL_malloc(EVP_MD_size(algo))) == NULL)
        goto done;

    if(1 != EVP_DigestFinal_ex(mdctx, *digest, digest_len))
        goto done;

    ret = SUCCESS;

    done:

    // clean up
    if (*digest && ret == FAILURE) OPENSSL_free(*digest);
    EVP_MD_CTX_destroy(mdctx);

    return ret;
}

