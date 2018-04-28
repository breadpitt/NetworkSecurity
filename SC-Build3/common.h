/*******************************************************************
 * Header file common to both client and server
 *******************************************************************/
#include <openssl/evp.h>

//*** Defines

#define NONCE_SIZE		17 // number of bytes in nonce

#define SUCCESS			1 // common success return value
#define FAILURE			0 // common failure return value

//*** Typedefs

typedef unsigned char byte;

typedef struct {         // a byte array structure
    unsigned int len;    // number of bytes
    byte *value = NULL;  // the byte array
} bytes_t;

//*** Function prototypes

// Random bytes generation
int GetRandomBytes(byte *buffer, int num);

// OpenSSL setup/cleanup
void OpenSSLInit();
void OpenSSLCleanup();
void ReadRSAKeys(const char* peer_keyfile, const char *self_keyfile,
                 EVP_PKEY **pub_key, EVP_PKEY **pubpri_key);

// send/receive buffer
ssize_t SendAMessage(int dest, byte *msg, int len);
ssize_t ReceiveAMessage(int src, byte *buffer, int buffer_size);

// send/receive/print bytes_t
int SendBytes(int dest, bytes_t *b);
int ReceiveBytes(int src, bytes_t *b);
void PrintBytes(const char *label, byte *buff, int len);

// asymmetric (envelope-basded) encrypt/decrypt message
int EnvelopeEncryptMessage(EVP_PKEY **pub_key, byte *plaintext, int plaintext_len, 
                           byte **encrypted_key, int *encryted_key_len,
                           byte *iv, byte *ciphertext);
int EnvelopeDecryptMessage(EVP_PKEY *pri_key, byte *ciphertext, int ciphertext_len, 
                           byte *encrypted_key, int encrypted_key_len,
                           byte *iv, byte *plaintext);

// message digest computation
int DigestMessage(byte *message, size_t message_len, const EVP_MD *algo, 
                byte **digest, unsigned int *digest_len);



