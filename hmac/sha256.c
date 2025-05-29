#include "sha256.h" 
#include <string.h> 

static const uint32_t SHA256_K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

static const uint32_t SHA256_Initial_Hash_Values[8] = {
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
};

#define RIGHT_ROTATE(x, n) (((x) >> (n)) | ((x) << (32-(n))))
#define CH(x, y, z)  (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define SIGMA0(x)    (RIGHT_ROTATE(x, 2) ^ RIGHT_ROTATE(x, 13) ^ RIGHT_ROTATE(x, 22))
#define SIGMA1(x)    (RIGHT_ROTATE(x, 6) ^ RIGHT_ROTATE(x, 11) ^ RIGHT_ROTATE(x, 25))
#define GAMMA0(x)    (RIGHT_ROTATE(x, 7) ^ RIGHT_ROTATE(x, 18) ^ ((x) >> 3))
#define GAMMA1(x)    (RIGHT_ROTATE(x, 17) ^ RIGHT_ROTATE(x, 19) ^ ((x) >> 10))

static void sha256_transform(SHA256_CTX *ctx, const uint8_t *block_data) {
    uint32_t w[64];
    uint32_t a, b, c, d, e, f, g, h;
    uint32_t t1, t2;
    int i, j;
    
    for (i = 0, j = 0; i < 16; ++i, j += 4) {
        w[i] = ((uint32_t)block_data[j] << 24) |
               ((uint32_t)block_data[j + 1] << 16) |
               ((uint32_t)block_data[j + 2] << 8) |
               ((uint32_t)block_data[j + 3]);
    }
    for (i = 16; i < 64; ++i) {
        w[i] = GAMMA1(w[i - 2]) + w[i - 7] + GAMMA0(w[i - 15]) + w[i - 16];
    }
    
    a = ctx->state[0];
    b = ctx->state[1];
    c = ctx->state[2];
    d = ctx->state[3];
    e = ctx->state[4];
    f = ctx->state[5];
    g = ctx->state[6];
    h = ctx->state[7];
    
    for (i = 0; i < 64; ++i) {
        t1 = h + SIGMA1(e) + CH(e, f, g) + SHA256_K[i] + w[i];
        t2 = SIGMA0(a) + MAJ(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }    
    ctx->state[0] += a;
    ctx->state[1] += b;
    ctx->state[2] += c;
    ctx->state[3] += d;
    ctx->state[4] += e;
    ctx->state[5] += f;
    ctx->state[6] += g;
    ctx->state[7] += h;
}

void sha256_init(SHA256_CTX *ctx) {
    ctx->buffer_len = 0;
    ctx->total_bit_len = 0;
    
    memcpy(ctx->state, SHA256_Initial_Hash_Values, sizeof(SHA256_Initial_Hash_Values));
}

void sha256_update(SHA256_CTX *ctx, const uint8_t *message_array, size_t len) {
    size_t i;
    for (i = 0; i < len; ++i) {
        ctx->buffer[ctx->buffer_len] = message_array[i];
        ctx->buffer_len++;
        if (ctx->buffer_len == SHA256_BLOCK_SIZE_BYTES) {
            sha256_transform(ctx, ctx->buffer);
            ctx->total_bit_len += SHA256_BLOCK_SIZE_BYTES * 8; 
            ctx->buffer_len = 0; 
        }
    }
}

void sha256_final(SHA256_CTX *ctx, uint8_t digest[SHA256_DIGEST_LENGTH]) {
    uint32_t i;
    uint64_t original_bit_len;
    uint8_t  padding_len_byte_pos;

    original_bit_len = ctx->total_bit_len + (ctx->buffer_len * 8);    
    ctx->buffer[ctx->buffer_len++] = 0x80;
    
    if (ctx->buffer_len > SHA256_BLOCK_SIZE_BYTES - 8) { 
        
        memset(ctx->buffer + ctx->buffer_len, 0, SHA256_BLOCK_SIZE_BYTES - ctx->buffer_len);
        sha256_transform(ctx, ctx->buffer);
        ctx->buffer_len = 0; 
    }

    memset(ctx->buffer + ctx->buffer_len, 0, SHA256_BLOCK_SIZE_BYTES - 8 - ctx->buffer_len);
    
    padding_len_byte_pos = SHA256_BLOCK_SIZE_BYTES - 8; 
    for (i = 0; i < 8; ++i) {
        ctx->buffer[padding_len_byte_pos + i] = (uint8_t)(original_bit_len >> (56 - i * 8));
    }
    
    sha256_transform(ctx, ctx->buffer);
    
    for (i = 0; i < SHA256_DIGEST_LENGTH / 4; ++i) { 
        digest[i * 4 + 0] = (uint8_t)(ctx->state[i] >> 24);
        digest[i * 4 + 1] = (uint8_t)(ctx->state[i] >> 16);
        digest[i * 4 + 2] = (uint8_t)(ctx->state[i] >> 8);
        digest[i * 4 + 3] = (uint8_t)(ctx->state[i]);
    }
}