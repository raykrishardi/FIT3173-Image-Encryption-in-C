#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

// Represent the size of the BMP header (54 bytes)
#define BMP_HEADER_SIZE 54

void handleErrors() {
   printf("Wrong encryption progress\n");
}

// Function that performs encryption using 128 bit AES and the specified mode of operation (i.e. ECB or CBC)
int encrypt_aes_128(char *mode, unsigned char *plaintext, int plaintext_len, unsigned char *key,
  unsigned char *iv, unsigned char *ciphertext) {
    EVP_CIPHER_CTX *ctx;

    int len;

    int ciphertext_len;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

    /* Check the specified mode of operation (i.e. ECB or CBC)
     * then initialise the encryption operation based on the mode of operation.
     * IMPORTANT - ensure you use a key and IV size appropriate for your cipher
     * In this example we are using 128 bit AES (i.e. a 128 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits */
    if (strcmp(mode, "ecb") == 0) {
      if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, iv))
        handleErrors();
    } else if (strcmp(mode, "cbc") == 0) {
      if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv))
        handleErrors();
    }

    /* Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
      handleErrors();
    ciphertext_len = len;

    /* Finalise the encryption. Further ciphertext bytes may be written at
     * this stage.
     */
    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) handleErrors();
    ciphertext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

// Function that writes the BMP header and ciphertext to the output BMP file
void writeToFile(char *header, char *ciphertext, int ciphertext_len, char *outfileName) {
  // Represent the output BMP file
  FILE *outfile;

  // Create the output BMP file and write to the output BMP file in binary mode
  outfile = fopen(outfileName, "wb");

  // Write the BMP header and ciphertext to the output BMP file
  fwrite(header, BMP_HEADER_SIZE, 1, outfile);
  fwrite(ciphertext, ciphertext_len, 1, outfile);
}

// Function that encrypts the original BMP image using 128 bit AES in ECB and CBC mode of operation
// and output the encrypted BMP image (ecb.bmp and cbc.bmp)
void encryptAndOutputImage(char *fileName, unsigned char *key, unsigned char *iv) {
  FILE *infile; // Represent the original BMP image
  char bmp_header[BMP_HEADER_SIZE]; // Represent the BMP header
  long plaintext_size; // Represent the size of the BMP data
  unsigned char *plaintext; // Represent the BMP data
  unsigned char *ciphertext_ecb; // Represent the encrypted BMP data in ECB mode
  int ciphertext_ecb_len; // Represent the size of the encrypted BMP data in ECB mode
  unsigned char *ciphertext_cbc; // Represent the encrypted BMP data in CBC mode
  int ciphertext_cbc_len; // Represent the size of the encrypted BMP data in CBC mode

  // Read the original BMP image file in binary mode
  infile = fopen(fileName, "rb");

  // Extract BMP Header
  fread(bmp_header, BMP_HEADER_SIZE, sizeof(char), infile);

  // Calculate the size of the BMP data
  fseek(infile, BMP_HEADER_SIZE, SEEK_END);
  plaintext_size = ftell(infile);

  // Extract and store BMP data in heap
  fseek(infile, BMP_HEADER_SIZE, SEEK_SET);
  plaintext = malloc(plaintext_size);
  fread(plaintext, plaintext_size, sizeof(char), infile);

  // Allocate memory in heap for the encrypted BMP data in ECB and CBC mode
  ciphertext_ecb = malloc(plaintext_size);
  ciphertext_cbc = malloc(plaintext_size);

  // Close the original BMP image file
  fclose(infile);

  // Encrypt the BMP data using 128 bit AES in ECB and CBC mode
  // and store the ciphertext and its size for each mode in the appropriate variables
  ciphertext_ecb_len = encrypt_aes_128("ecb", plaintext, plaintext_size, key, iv,
                            ciphertext_ecb);
  ciphertext_cbc_len = encrypt_aes_128("cbc", plaintext, plaintext_size, key, iv,
                            ciphertext_cbc);

  // Write the BMP header and ciphertext to the output BMP file (i.e. ecb.bmp and cbc.bmp)
  writeToFile(bmp_header, ciphertext_ecb, ciphertext_ecb_len, "ecb.bmp");
  writeToFile(bmp_header, ciphertext_cbc, ciphertext_cbc_len, "cbc.bmp");

  // Display appropriate feedback about the output BMP file name
  printf("ECB BMP file: ecb.bmp\n");
  printf("CBC BMP file: cbc.bmp\n");

  // Free resources in heap
  free(plaintext);
  free(ciphertext_ecb);
  free(ciphertext_cbc);
}

int main(int argc, char **argv) {
  // Represent the original BMP image file name
  char *fileName = "pic_original.bmp";

  // Represent the 128 bit secret key for the AES encryption
  // Note: Key will be automatically get padded to 128 bit
  unsigned char *key = (unsigned char *)"26445549";

  // Represent the 128 bit initialization vector (IV) for the AES encryption
  // Note: The IV size for "most" modes is the same as the block size (i.e. AES128 uses 128 bit IV)
  unsigned char *iv = (unsigned char *)"1234567898765432";

  // Encrypt the original BMP image using 128 bit AES in ECB and CBC mode of operation
  // and output the encrypted BMP image (ecb.bmp and cbc.bmp)
  encryptAndOutputImage(fileName, key, iv);

  return 1;
}