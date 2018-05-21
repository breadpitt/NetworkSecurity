/*******************************************************************
 * Header file for common-ws.h
 *******************************************************************/

#include <openssl/evp.h>

#define DHE_FAIL		0 // unable to complete DHE
#define DHE_SUCCESS		1 // DHE complete (with authentication)
#define DHE_SUCCESS_NO_AUTH	2 // DHE complete (without authentication)

// signing on DHE keys
int GetBytesAndSignatureFromPublicKey(EVP_PKEY *key, EVP_PKEY *pri_key, 
                                      bytes_t **pkey, bytes_t *pkey_sign);
int VerifyAndGetPublicKeyFromBytes(bytes_t keydata, bytes_t signature,
                                    EVP_PKEY *pub_key, EVP_PKEY **key);
int GenerateVerifiedKeysWithDHE(int peer, byte *s_key, byte *h_key,
                                EVP_PKEY *self_key, EVP_PKEY *peer_key);
