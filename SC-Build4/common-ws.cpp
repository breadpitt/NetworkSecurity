/*******************************************************************
 * This is your workspace to modify common functions of the 
 * application.
 *
 * This is the ONLY common file you will modify in the assignment,
 * but can call any other function in common.cpp.
 *
 * You should not modify common.cpp in the application.
 *
 * Only implement the TODO blocks.
 * Do not uncomment statements unless explicitly mentioned.
 *
 * To create the server executable:
 *   chmod u+x makeserver    [needed only once]
 *   ./makeserver
 *
 * To create the client executable:
 *   chmod u+x makeclient    [needed only once]
 *   ./makeclient
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
#include <openssl/pem.h>
#include <openssl/bio.h>

#include "common.h"
#include "common-ws.h"

using namespace std;

/*******************************************************************/
//  Extract the public key from keypair <key> and
//   return as a bytes_t structure
//
//  Returns NULL on error

bytes_t *GetBytesFromPublicKey(EVP_PKEY *key)
{
    bytes_t *pkey = NULL;

    // set up OpenSSL memory buffer I/O
    BUF_MEM *bptr;
    BIO *bio = BIO_new(BIO_s_mem());

    if (1 != PEM_write_bio_PUBKEY(bio, key))
    { // write public key to buffer
        BIO_free(bio);
        return pkey;
    }

    // get pointer to data in buffer
    BIO_get_mem_ptr(bio, &bptr);

    pkey = (bytes_t *)malloc(sizeof(bytes_t));
    pkey->len = (unsigned int)bptr->length;                 // set data length
    pkey->value = (byte *)malloc(sizeof(byte) * pkey->len); // allocate
    memcpy(pkey->value, bptr->data, bptr->length);          // copy data

    BIO_free(bio); // free memory

    return pkey;
}

/*******************************************************************/
// Create a EVP_PKEY from <keydata>
//
// Return NULL on error

EVP_PKEY *GetPublicKeyFromBytes(bytes_t keydata)
{
    EVP_PKEY *peerkey = NULL;

    // copy received data to OpenSSL memory buffer
    BUF_MEM *bptr = BUF_MEM_new();
    BUF_MEM_grow(bptr, keydata.len);                // set size of buffer
    memcpy(bptr->data, keydata.value, keydata.len); // copy

    BIO *bio = BIO_new(BIO_s_mem());         // set up for OpenSSL buffer I/O
    BIO_set_mem_buf(bio, bptr, BIO_NOCLOSE); // this BIO is now using the BUF_MEM above

    // read public key from OpenSSL buffer
    if ((peerkey = EVP_PKEY_new()) == NULL)
        goto done;

    PEM_read_bio_PUBKEY(bio, &peerkey, NULL, NULL);

done:

    // clean up
    BUF_MEM_free(bptr);
    BIO_free(bio);

    return peerkey;
}

/********************************************************************/
// Compute a shared secret from a key pair and a peer public key

// Return 0 on error

byte* ComputeSecret(EVP_PKEY *peerkey, EVP_PKEY_CTX *kctx, bytes_t ss)
{   
    int ret = 0;
    ret = EVP_PKEY_derive_init(kctx);
    if (ret <=0){
        std::cout << "Error deriving public key\n";
    }
    EVP_PKEY_derive_set_peer(kctx, peerkey); // associate peer public key with our public key
    if (ret <= 0)
    {
        std::cout << "Error associating public keys\n";
    }

    EVP_PKEY_derive(kctx, NULL, &ss.len);
    if (ret <= 0)
    {
        std::cout << "Error retrieving key length\n";
    }

    ss.value = (byte *)malloc(ss.len); // cast and allocate memory

    if (!ss.len)
    {
        std::cout << "Malloc error\n";
    }

    ret = EVP_PKEY_derive(kctx, ss.value, &ss.len);
    if (ret <= 0)
    { // shared secret is ss.len bytes written to buffer ss.value
        std::cout << "Error deriving shared secret key\n";
    }

    if (ret <= 0){
        ss.value == NULL;
    }

    return ss.value;
}

/*******************************************************************/
// Generate symmetric key and HMAC key using DHE with <peer>;
//   the syymetric key is written to s_key
//   the HMAC key is written to h_key
//   both buffers should have been pre-allocated
//
// DHE is first used to generate a shared secret; the SHA256 hash
//   of the secret is split to use create the two keys
//
// Returns SUCCESS or FAILURE
//
// Read assignment description for more information

int GenerateKeysWithDHE(int peer, byte *s_key, byte *h_key)
{

    EVP_PKEY *params = NULL, *dhkey = NULL;
    EVP_PKEY_CTX *kctx = NULL;

    bytes_t *pkey = NULL; // the bytes array corresponding to the
                          // generated DHE public key

    EVP_PKEY *peerkey = NULL; // the DHE public key of the peer

    bytes_t ss; // the shared secret

    size_t ssLen;

    bytes_t ss_digest; // the SHA256 digest of the secret

    bytes_t recvPKeyBytes;

    int ret = FAILURE;

    //*** Generate public/private key pair for DHE ****************

    // using IETF RFC 5114 parameters
    if (NULL == (params = EVP_PKEY_new()))
        goto done;
    if (1 != EVP_PKEY_set1_DH(params, DH_get_2048_256()))
        goto done;

    // create context for the key generation
    if (!(kctx = EVP_PKEY_CTX_new(params, NULL)))
        goto done;

    // generate a new key pair
    if (1 != EVP_PKEY_keygen_init(kctx))
        goto done;
    if (NULL == (dhkey = EVP_PKEY_new()))
        goto done;
    if (1 != EVP_PKEY_keygen(kctx, &dhkey)) // dhkey is now the keypair
        goto done;
    
    // TODO: *** Send DHE public key to peer *******************
    //       store the key in pkey
    pkey = GetBytesFromPublicKey(dhkey);
    if (pkey == NULL)
    {
        std::cout << "Error getting bytes from public key\n";
        ret = FAILURE;
        goto done;
    }

    ret = SendBytes(peer, pkey);

    if (ret <= 0)
    {
        std::cout << "Error sending public key bytes\n";
        ret = FAILURE;
        goto done;
    }

    // TODO: *** Get peer's DHE public key *********************
    //       store the key in peerkey

    ret = ReceiveBytes(peer, &recvPKeyBytes);
    if (ret <= 0)
    {
        std::cout << "Error receiving public key bytes\n";
        ret = FAILURE;
        goto done;
    }

    peerkey = GetPublicKeyFromBytes(recvPKeyBytes);
    if (peerkey == NULL)
    {
        std::cout << "Error converting public key from bytes\n";
        ret = FAILURE;
        goto done;
    }

    // TODO: *** Compute shared secret **************************
    //       store the shared secret in ss

    //*** Compute symmetric key and HMAC key *********************

    // TODO: compute SHA256 digest of shared secret
    //       store digest in ss_digest

    ret = DigestMessage(ss.value, ss.len, EVP_sha256(), &ss_digest.value, &ss_digest.len);
    if (ret != 1)
    {
        std::cout << "Error in hashin the shared secret\n";
        ret = FAILURE;
        goto done;
    }

    if (SYM_KEY_SIZE + HMAC_KEY_SIZE > ss_digest.len)
    { // make sure we have enough bytes
        cout << "[Digest length insufficient for symmetric key and HMAC key]" << endl;
        goto done;
    }

    // use first half of digest as shared key
    memcpy(s_key, ss_digest.value, SYM_KEY_SIZE);
    // use the second half as HMAC key
    memcpy(h_key, ss_digest.value + SYM_KEY_SIZE, HMAC_KEY_SIZE);

    // TODO: set ret to SUCCESS

    ret = SUCCESS;

done:

    // TODO: clean up
    EVP_PKEY_CTX_free(kctx);
    EVP_PKEY_free(params);
    EVP_PKEY_free(dhkey);

    if (pkey)
    {
        delete (pkey->value);
        delete (pkey);
    }

    EVP_PKEY_free(peerkey);
    OPENSSL_free(ss.value);
    if (ss_digest.value)
        delete (ss_digest.value);

    return ret;
}
