/*******************************************************************
 * Header file for common-ws.h
 *******************************************************************/

#include <openssl/evp.h>

// DHE 
bytes_t *GetBytesFromPublicKey(EVP_PKEY *key);
EVP_PKEY *GetPublicKeyFromBytes(bytes_t keydata);
int GenerateKeysWithDHE(int peer, byte *s_key, byte *h_key);
