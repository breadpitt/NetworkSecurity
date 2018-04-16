/*******************************************************************
 * Header file for common-ws.h
 *******************************************************************/

//*** Defines

#define CIPHER_BLOCK_SIZE	16 // AES-128
#define SYM_KEY_SIZE		16 // 128 bit keys
#define HMAC_KEY_SIZE		16 // HMAC SHA256

#define SEQ_NO_SIZE		sizeof(unsigned long long)

//*** Function prototypes

// Sequence numbers
void InitSequenceNumbers();

// symmetric encrypt/decrypt message with send/receive
int EncryptAndSendMessage(int dest, byte *s_key, byte *h_key, byte *msg, int len);
int ReceiveAndDecryptMessage(int src, byte *s_key, byte *h_key, byte *buffer, int buffer_size);
