#include "file_crypt.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

void file_crypt(const char *src_fname, const char *dest_fname, const unsigned char *key, const unsigned char *iv, Operation op)
{
  FILE *src = fopen(src_fname, "rb");
  FILE *dest = fopen(dest_fname, "wb");

  if (!src || !dest)
  {
    fprintf(stderr, "Error: Open file: %s \n", src_fname);
    return;
  }

  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  if (!ctx)
  {
    fprintf(stderr, "Error: EVP_CIPHER_CTX_new \n");

    fclose(src);
    fclose(dest);

    return;
  }

  if (1 != EVP_CipherInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL, op == ENC ? 1 : 0))
  {
    fprintf(stderr, "Error: EVP_CipherInit_ex: EVP_aes_256_gcm \n");

    EVP_CIPHER_CTX_free(ctx);
    fclose(src);
    fclose(dest);

    return;
  }

  if (1 != EVP_CipherInit_ex(ctx, NULL, NULL, key, iv, op == ENC ? 1 : 0))
  {
    fprintf(stderr, "Error: Cipher IV \n");

    EVP_CIPHER_CTX_free(ctx);
    fclose(src);
    fclose(dest);

    return;
  }

  unsigned char buff[BUFFER_SIZE];
  unsigned char output[BUFFER_SIZE + EVP_CIPHER_block_size(EVP_aes_256_gcm())];
  int len, output_len;

  while ((len = fread(buff, 1, BUFFER_SIZE, src)) > 0)
  {
    if (1 != EVP_CipherUpdate(ctx, output, &output_len, buff, len))
    {
      fprintf(stderr, "Error: EVP_CipherUpdate \n");

      EVP_CIPHER_CTX_free(ctx);
      fclose(src);
      fclose(dest);

      return;
    }

    fwrite(output, 1, output_len, dest);
  }

  if (1 != EVP_CipherFinal_ex(ctx, output, &output_len))
  {
    fprintf(stderr, "Error: EVP_CipherFinal_ex \n");

    EVP_CIPHER_CTX_free(ctx);
    fclose(src);
    fclose(dest);

    return;
  }

  fwrite(output, 1, output_len, dest);

  EVP_CIPHER_CTX_free(ctx);
  fclose(src);
  fclose(dest);
}
