#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/err.h>
#include <string.h>   


void handleErrors(void)
{
    unsigned long errCode;

    printf("An error occurred\n");
    while(errCode = ERR_get_error())
    {
        char *err = ERR_error_string(errCode, NULL);
        printf("%s\n", err);
    }
    abort();
}

int encrypt_aes_ocb(unsigned char *plaintext, unsigned long long plaintext_len, unsigned char *aad,
            unsigned long long aad_len, unsigned char *key, unsigned char *iv,
            unsigned char *ciphertext, unsigned char *tag)
{
    EVP_CIPHER_CTX *ctx = NULL;
    int len = 0, ciphertext_len = 0;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

    /* Initialise the encryption operation. */
    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_ocb(), NULL, NULL, NULL))
	    
        handleErrors();

    /* Set IV length if default 12 bytes (96 bits) is not appropriate */
    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, 14, NULL))
        handleErrors();

    /* Initialise key and IV */
    if(1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv)) handleErrors();

    /* Provide any AAD data. This can be called zero or more times as
     * required
     */
    if(aad && aad_len > 0)
    {
        if(1 != EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len))
            handleErrors();
    }

    /* Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
    if(plaintext)
    {
        if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
            handleErrors();

        ciphertext_len = len;
    }

    /* Finalise the encryption. Normally ciphertext bytes may be written at
     * this stage, but this does not occur in GCM mode
     */
    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) handleErrors();
    ciphertext_len += len;

    /* Get the tag */
    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 14, tag))
        handleErrors();

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

int decrypt_aes_ocb(unsigned char *ciphertext, unsigned long long ciphertext_len, unsigned char *aad,
            unsigned long long aad_len, unsigned char *tag, unsigned char *key, unsigned char *iv,
            unsigned char *plaintext)
{
    EVP_CIPHER_CTX *ctx = NULL;
    int len = 0, plaintext_len = 0, ret;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

    /* Initialise the decryption operation. */
    if(!EVP_DecryptInit_ex(ctx, EVP_aes_128_ocb(), NULL, NULL, NULL))
        handleErrors();

    /* Set IV length. Not necessary if this is 12 bytes (96 bits) */
    if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, 14, NULL))
        handleErrors();

    /* Initialise key and IV */
    if(!EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv)) handleErrors();

    /* Provide any AAD data. This can be called zero or more times as
     * required
     */
    if(aad && aad_len > 0)
    {
        if(!EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len))
            handleErrors();
    }

    /* Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary
     */
    if(ciphertext)
    {
        if(!EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
            handleErrors();

        plaintext_len = len;
    }

    /* Set expected tag value. Works in OpenSSL 1.0.1d and later */
    if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 14, tag))
        handleErrors();

    /* Finalise the decryption. A positive return value indicates success,
     * anything else is a failure - the plaintext is not trustworthy.
     */
    ret = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    if(ret > 0)
    {
        /* Success */
        plaintext_len += len;
        return plaintext_len;
    }
    else
    {
        /* Verify failed */
        return -1;
    }
}
