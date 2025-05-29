
#include <stdint.h>
#include <stddef.h>

#define SHA256_BLOCK_SIZE_BYTES 64
#define SHA256_DIGEST_LENGTH 32  

typedef struct {
    uint8_t  buffer[SHA256_BLOCK_SIZE_BYTES];
    uint32_t buffer_len;                     
    uint64_t total_bit_len;                  
    uint32_t state[8];                      
} SHA256_CTX;

void sha256_init(SHA256_CTX *ctx);
void sha256_update(SHA256_CTX *ctx, const uint8_t *message_array, size_t len);
void sha256_final(SHA256_CTX *ctx, uint8_t digest[SHA256_DIGEST_LENGTH]);
