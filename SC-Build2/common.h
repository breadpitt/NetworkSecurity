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

//*** Preshared keys

const byte shared_key[] = {0x15, 0xd4, 0x35, 0xa8,
                           0x23, 0xfb, 0xc2, 0x90,
                           0x57, 0xda, 0xee, 0x06,
                           0xce, 0x72, 0xf2, 0x49}; // pre-shared AES-128 key

const byte hmac_key[] = {0xd1, 0x09, 0x54, 0xf2,
                         0xcc, 0x80, 0x7a, 0x38, 
                         0x8c, 0x75, 0xbc, 0x90,
                         0x1b, 0x8c, 0x40, 0x1f}; // pre-shared hmac key

//*** Function prototypes

// Random bytes generation
int GetRandomBytes(byte *buffer, int num);

// OpenSSL setup/cleanup
void OpenSSLInit();
void OpenSSLCleanup();

// send/receive buffer
ssize_t SendAMessage(int dest, byte *msg, int len);
ssize_t ReceiveAMessage(int src, byte *buffer, int buffer_size);

// send/receive/print bytes_t
int SendBytes(int dest, bytes_t *b);
int ReceiveBytes(int src, bytes_t *b);
void PrintBytes(const char *label, byte *buff, int len);

// symmetric encrypt/decrypt message
int EncryptMessage(byte *plaintext, int plaintext_len, byte *key,
                   byte *iv, byte *ciphertext);
int DecryptMessage(byte *ciphertext, int ciphertext_len, byte *key,
                   byte *iv, byte *plaintext);

// message digest computation
int HMACMessage(byte *message, size_t message_len, byte *key, int key_len, 
                byte **digest, unsigned int *digest_len);
int DigestMessage(byte *message, size_t message_len, const EVP_MD *algo, 
                byte **digest, unsigned int *digest_len);


