/* Reference implementation of ACE-128 AEAD
 Written by:
 Kalikinkar Mandal <kmandal@uwaterloo.ca>
 */

//typedef unsigned long long u64;


int encrypt_aes_ocb(unsigned char *plaintext, unsigned long long plaintext_len, unsigned char *aad,
            unsigned long long aad_len, unsigned char *key, unsigned char *iv,
            unsigned char *ciphertext, unsigned char *tag);

int decrypt_aes_ocb(unsigned char *ciphertext, unsigned long long ciphertext_len, unsigned char *aad,
            unsigned long long aad_len, unsigned char *tag, unsigned char *key, unsigned char *iv,
            unsigned char *plaintext);