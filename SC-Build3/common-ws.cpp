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
#include <openssl/pem.h>
#include <openssl/bio.h>

#include "common.h"
#include "common-ws.h"

using namespace std;

/*******************************************************************/
// Read RSA keys:
//      1) peer's public key from <peer_keyfile> into <pub_key>
//      2) keypair of self from <self_keyfile> into <pubpri_key>
//
// Loading is skipped when the associated filename is NULL
// Exits on error

void ReadRSAKeys(const char* peer_keyfile, const char *self_keyfile,
                 EVP_PKEY **pub_key, EVP_PKEY **pubpri_key) {

    FILE *fp;

    // load peer's public key
    if (peer_keyfile != NULL) {
        fp = fopen(peer_keyfile,"r");
        if (fp==NULL) {
            cout << "[" << peer_keyfile << " public key file not found]" << endl;
            exit(1);
        }
        if (PEM_read_PUBKEY(fp, pub_key, NULL, NULL)==NULL) {
            cout << "[Error reading peer public key]" << endl;
            exit(1);
        }
        fclose(fp);
    }

    // load self public/private key
    if (self_keyfile != NULL) {
        fp = fopen(self_keyfile,"r");
        if (fp==NULL) {
            cout << "[" << self_keyfile << " key file not found]" << endl;
            exit(1);
        }
        if (PEM_read_PrivateKey(fp, pubpri_key, NULL, NULL)==NULL) {
	    cout << "[Error reading self public/private key]" << endl;
            exit(1);
        }
        fclose(fp);
    }
}

/*******************************************************************/
// Envelope encrypt message <msg> of length <len> using public
//   key <pub_key>; then send encrypted symmetric key, IV, 
//   and ciphertext using socket <dest>
//  
// Data is sent in bytes_t format
//
// Returns FAILURE or length of sent ciphertext
//
// Read assignment description for more information

int EnvelopeEncryptAndSendMessage(int dest, EVP_PKEY *pub_key, byte *msg, int len) {
    bytes_t ciphertext, AES_iv, encrypted_key;
    int ret = FAILURE;

    ciphertext.len = len + CIPHER_BLOCK_SIZE - 1; // maximum ciphertext size
    ciphertext.value = new byte[ciphertext.len];

    AES_iv.len = 16;
    AES_iv.value[AES_iv.len];

    encrypted_key.len = EVP_PKEY_size(pub_key);
    cout << "key size: " << encrypted_key.len << endl;
    if (encrypted_key.len == 0){
        cout << "Key size error\n";
    }
    encrypted_key.value = new byte[encrypted_key.len];

    // TODO: encrypt the message

    ret = EnvelopeEncryptMessage(&pub_key, msg, sizeof(msg), &encrypted_key.value, (int*)&encrypted_key.len, AES_iv.value, ciphertext.value); 
        if (ret == FAILURE){
             cout << "[Envelope encryption failed]" << endl;
             goto done;
        }
    
    // TODO: send the encrypted key, IV, and ciphertext
    
    SendBytes(dest, &encrypted_key);
    SendBytes(dest, &AES_iv);
    SendBytes(dest, &ciphertext);

    // TODO: set return value

    done:

    // TODO: cleanup
    delete(ciphertext.value);

    return ret;
}

/*******************************************************************/
// Receive message into <buffer> of max length <buffer_size>
//   from socket <src>; the encrypted key is decrypted using 
//   private key <pri_key> and then used for message decryption
//
// Data is received in bytes_t format
// Decrypted messages longer than <buffer_size> are truncated
//
// Returns FAILURE or length of message in <buffer>
//
// Read assignment description for more information

int ReceiveAndEnvelopeDecryptMessage(int src, EVP_PKEY *pri_key, byte *buffer, int buffer_size) {
    bytes_t iv, encrypted_key, ciphertext;
    int ret = FAILURE;

    byte *plaintext = NULL;
    int plaintext_len;

    // receive encrypted key, IV, and message
    if (ReceiveBytes(src, &encrypted_key)==FAILURE) goto done;
    if (ReceiveBytes(src, &iv)==FAILURE) goto done;
    if (ReceiveBytes(src, &ciphertext)==FAILURE) goto done;

    // TODO: decrypt message
    plaintext = new byte[ciphertext.len + CIPHER_BLOCK_SIZE];

    ret = EnvelopeDecryptMessage(pri_key, ciphertext.value, ciphertext.len, encrypted_key.value, encrypted_key.len, iv.value, plaintext);

        if (ret == FAILURE){
             cout << "[Envelope decryption failed]" << endl;
             goto done;
        }
        
    // TODO: copy plaintext to buffer
    //       you should copy as many bytes as the length of the plaintext
    //         but never more than buffer_size bytes
    if (ciphertext.len + CIPHER_BLOCK_SIZE <= buffer_size){
            memcpy(buffer, plaintext, (ciphertext.len + CIPHER_BLOCK_SIZE));
    } else {
        cout << "Buffer sizing error\n";
    }

    // TODO: set return value

    done:

    // cleanup
    if (plaintext) delete(plaintext);
    if (encrypted_key.value) delete(encrypted_key.value);
    if (ciphertext.value) delete(ciphertext.value);
    if (iv.value) delete(iv.value);

    return ret;
}


