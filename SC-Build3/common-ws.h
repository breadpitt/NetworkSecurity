/*******************************************************************
 * Header file for common-ws.h
 *******************************************************************/

#include <openssl/evp.h>

#define CIPHER_BLOCK_SIZE	16 // AES-128

// Reading PEM key files
void ReadRSAKeys(const char* peer_keyfile, const char *self_keyfile,
                 EVP_PKEY **pub_key, EVP_PKEY **pubpri_key);

// asymmetric encrypt/decrypt message with send/receive
int EnvelopeEncryptAndSendMessage(int dest, EVP_PKEY *pub_key, byte *msg, int len);
int ReceiveAndEnvelopeDecryptMessage(int src, EVP_PKEY *pri_key, byte *buffer, int buffer_size);

