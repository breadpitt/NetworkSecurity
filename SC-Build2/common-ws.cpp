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

#include "common.h"
#include "common-ws.h"

#include <string.h>

using namespace std;

unsigned long long next_seq_no;		// sequence number in next send
unsigned long long expected_next_seq_no; // sequence number expected in next receive

/*******************************************************************/
// Reset sequence numbers to zero

void InitSequenceNumbers() {
    next_seq_no = 0;
    expected_next_seq_no = 0;
}

/*******************************************************************/
// Encrypt message <msg> of length <len> using symmetric key
//   <s_key> and sign using <h_key>; then send IV, ciphertext and
//   the MAC using socket <dest> 
//
// Data is sent in bytes_t format
//
// MAC is computed as SHA256(h_key, Seq.No.||IV||ciphertext)
//
// Returns FAILURE or length of sent ciphertext
//
// Read assignment description for more information

int EncryptAndSendMessage(int dest, byte *s_key, byte *h_key, byte *msg, int len) {
    bytes_t ciphertext, iv, send_hdigest, hmac_input, next_seq_buf, plaintext;
    
    int ret = FAILURE; // FAILURE
    //byte *plaintext = new byte[len];
    plaintext.len = len;
    plaintext.value = msg;
    ciphertext.len = len + CIPHER_BLOCK_SIZE - 1; // max possible ciphetext size
    ciphertext.value = new byte[ciphertext.len];

    iv.len = CIPHER_BLOCK_SIZE;
    iv.value = new byte[iv.len];

    // TODO: generate random IV
    int riv = GetRandomBytes(iv.value, iv.len); // return iv 
    if(riv != 1) {
            cout << "[IV generation failed]" << endl;
        goto done;
        }

    // TODO: encrypt the message
    cout << "SIZE: " << plaintext.len << endl;

    ret = EncryptMessage(plaintext.value, plaintext.len, s_key, iv.value, ciphertext.value);
    if (ret == FAILURE) {
        cout << "[Message Encryption Failure]" << endl;
        goto done;
    }
    cout << "Bytes encrypted: " << ret << endl;
    // TODO: compute HMAC
    send_hdigest.value = NULL;

    hmac_input.len = SEQ_NO_SIZE + iv.len + ciphertext.len;
    hmac_input.value = new byte[hmac_input.len]; 
    //cout << "TEST\n";
    memcpy(hmac_input.value, &next_seq_no, SEQ_NO_SIZE); // NOT WORKING HERE
    //cout << "TEST2\n";
	memcpy(hmac_input.value + SEQ_NO_SIZE, iv.value, iv.len);
    //cout << "TEST3\n";
	memcpy(hmac_input.value + SEQ_NO_SIZE + iv.len, ciphertext.value, ciphertext.len);
    //cout << "TEST4\n";
    ret = HMACMessage(hmac_input.value, hmac_input.len, h_key, HMAC_KEY_SIZE, &send_hdigest.value, &send_hdigest.len);
    
    if (ret == FAILURE){
        cout << "HMAC Function Failure" << endl;
        goto done;
    }

    // TODO: send the next_seq_no, IV, ciphertext, and MAC
    next_seq_buf.len = SEQ_NO_SIZE;
    next_seq_buf.value = new byte[next_seq_buf.len];
    cout << "TEST\n";
    memcpy(next_seq_buf.value, &next_seq_no, SEQ_NO_SIZE);
    ret = SendBytes(dest, &next_seq_buf);
        if (ret == FAILURE){
            cout << "Sequence Number Failure" << endl;
            goto done;
        }
        cout << "TEST2\n";
    ret = SendBytes(dest, &iv);
        if (ret == FAILURE){
            cout << "IV Send Failure" << endl;
            goto done;
        }
    ret = SendBytes(dest, &ciphertext);
        if (ret == FAILURE){
            cout << "Ciphertext Send Failure" << endl;
            goto done;
        }
    ret = SendBytes(dest, &send_hdigest);
        if (ret == FAILURE) {
            cout << "HMAC Send Failure" << endl;
            goto done;
        }

	
	

    // TODO: increment next_seq_no and set return value
    next_seq_no++;



    done:

    // TODO: cleanup
    if (iv.value) delete (iv.value);
    if (ciphertext.value) delete(ciphertext.value);
    if (send_hdigest.value){ 
        OPENSSL_free(send_hdigest.value);  
        delete (hmac_input.value);
    }
    return ret;
}

/*******************************************************************/
// Receive message into <buffer> of max length <buffer_size>
//   from socket <src>; messages are decrypted using symmetric
//   key <s_key> and verifed using HMAC key <h_key>
//
// Data is received in bytes_t format
// A (!) is printed if received signature does not match
// Decrypted messages longer than <buffer_size> are truncated
// MAC is computed as SHA256(h_key, Seq.No.||IV||ciphertext)
//
// Returns FAILURE or length of message in <buffer>
//
// Read assignment description for more information

int ReceiveAndDecryptMessage(int src, byte *s_key, byte *h_key, byte *buffer, int buffer_size) {
    bytes_t iv, ciphertext, digest, hmac_input, rec_hdigest, next_seq_buf;
    unsigned long long seq_no;
    int ret = FAILURE;

    next_seq_buf.len = SEQ_NO_SIZE;
    next_seq_buf.value = new byte[next_seq_buf.len];

    iv.len = CIPHER_BLOCK_SIZE;
    iv.value = new byte[iv.len];

    byte *plaintext = NULL;
    int plaintext_len;
    byte *plaintext_buf = NULL;


    // receive sequence number, IV, message, MAC
    ret = ReceiveBytes(src, &next_seq_buf);
    cout << "RETURN: " << ret << "\n";
        if (ret ==FAILURE){
            cout << "Sequence Number Reception Failure\n";
            goto done;
        }
    ret = ReceiveBytes(src, &iv);
    if (ret ==FAILURE){
            cout << "IV Reception Failure\n";
            goto done;
        }
    ret = ReceiveBytes(src, &ciphertext);
     if (ret ==FAILURE){
            cout << "Ciphertext Reception Failure\n";
            goto done;
        }
    ret = ReceiveBytes(src, &digest);
     if (ret ==FAILURE){
            cout << "Digest Reception Failure\n";
            goto done;
        }

    // discard message if seq_no is invalid
    if (seq_no < expected_next_seq_no) {
        cout << "\n[Message is a duplicate]" << endl;
        goto done;
    }

    // TODO: decrypt message
    plaintext = new byte[ciphertext.len + CIPHER_BLOCK_SIZE];
    ret = DecryptMessage(ciphertext.value, ciphertext.len, s_key, iv.value, plaintext);
    
    if (ret == FAILURE) {
        cout << "[Message Decryption Failure]" << endl;
        goto done;
    }


    // TODO: locally compute MAC
    rec_hdigest.value = NULL;
    hmac_input.len = SEQ_NO_SIZE + iv.len + ciphertext.len;
    hmac_input.value = new byte[hmac_input.len]; 

    memcpy(hmac_input.value, (const void*)next_seq_no, SEQ_NO_SIZE);
	memcpy(hmac_input.value + SEQ_NO_SIZE, iv.value, iv.len);
	memcpy(hmac_input.value + SEQ_NO_SIZE + iv.len, ciphertext.value, ciphertext.len);

    ret = HMACMessage(hmac_input.value, hmac_input.len, h_key, HMAC_KEY_SIZE, &rec_hdigest.value, &rec_hdigest.len);

    if (ret == FAILURE){
        cout << "HMAC Function Failure" << endl;
        goto done;
    }


    // TODO: print (!) if local and received hashes do not match 
    // Compare digests: 1 = match 0 = different
	if (CRYPTO_memcmp(rec_hdigest.value, digest.value, rec_hdigest.len) == 0)  { // memcmp returns 0 if no differences are found
		ret = SUCCESS;
	} else {
		ret = FAILURE;
        cout << "!";
        goto done;   
	}
        


    // TODO: copy plaintext to buffer
    //       you should copy as many bytes as the length of the plaintext
    //         but never more than buffer_size bytes
    plaintext_buf = new byte[sizeof(plaintext)];
     if (sizeof(plaintext_buf) >= sizeof(plaintext)){
        memcpy(plaintext_buf, plaintext, sizeof(plaintext));
    } else {
        cout << "Buffer Size Error\n";
        goto done;
    }
   // TODO: set expected_next_seq_no and return value
   

    done:

    // TODO: cleanup
    if (plaintext) delete(plaintext);
    if (ciphertext.value) delete(ciphertext.value);
    if (iv.value) delete(iv.value);
    if (rec_hdigest.value) delete(rec_hdigest.value);
    if (digest.value) delete(digest.value);

    return ret;
}

