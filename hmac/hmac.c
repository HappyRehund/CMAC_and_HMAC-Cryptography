#include "sha256.h" 
#include <stdio.h>
#include <string.h>
#include <stdlib.h> 
#include <stdint.h> 

void print_hex(char* label, uint8_t *data, int len) {
    printf("%s: ", label);
    for (int i = 0; i < len; ++i) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

void hmac_sha256(uint8_t *key, size_t key_len, uint8_t *message, size_t message_len, uint8_t *mac_digest) {

    uint8_t K_plus[SHA256_BLOCK_SIZE_BYTES];
    uint8_t temp_key_hash[SHA256_DIGEST_LENGTH];

    if (key_len > SHA256_BLOCK_SIZE_BYTES) {
        SHA256_CTX key_ctx;
        sha256_init(&key_ctx); 
        sha256_update(&key_ctx, key, key_len);
        sha256_final(&key_ctx, temp_key_hash);

        memcpy(K_plus, temp_key_hash, SHA256_DIGEST_LENGTH);
        memset(K_plus + SHA256_DIGEST_LENGTH, 0, SHA256_BLOCK_SIZE_BYTES - SHA256_DIGEST_LENGTH);
    } else {
        memcpy(K_plus, key, key_len);
        memset(K_plus + key_len, 0, SHA256_BLOCK_SIZE_BYTES - key_len);
    }

    uint8_t o_key_pad[SHA256_BLOCK_SIZE_BYTES];
    uint8_t i_key_pad[SHA256_BLOCK_SIZE_BYTES];

    for (int i = 0; i < SHA256_BLOCK_SIZE_BYTES; ++i) {
        i_key_pad[i] = K_plus[i] ^ 0x36;
        o_key_pad[i] = K_plus[i] ^ 0x5C;
    }

    SHA256_CTX ctx; 
    uint8_t inner_hash_result[SHA256_DIGEST_LENGTH];

    sha256_init(&ctx);
    sha256_update(&ctx, i_key_pad, SHA256_BLOCK_SIZE_BYTES);
    sha256_update(&ctx, message, message_len);
    sha256_final(&ctx, inner_hash_result);

    sha256_init(&ctx);
    sha256_update(&ctx, o_key_pad, SHA256_BLOCK_SIZE_BYTES);
    sha256_update(&ctx, inner_hash_result, SHA256_DIGEST_LENGTH);
    sha256_final(&ctx, mac_digest);
}


int main() {
    
    uint8_t secret_key[] = "kunciRahasiaSuperAman123";
    uint8_t original_message[] = "Ini adalah pesan rahasia.";
    uint8_t hmac_digest[SHA256_DIGEST_LENGTH];

    hmac_sha256(secret_key, strlen((char*)secret_key),
                original_message, strlen((char*)original_message),
                hmac_digest);
    printf("\n----- SISI PENGIRIM ----- \n");
    printf("Pesan Original: %s\n", original_message);
    print_hex("HMAC yang dihasilkan", hmac_digest, SHA256_DIGEST_LENGTH);

    
    printf("\n\n----- INTERSEPSI & SERANGAN MITM (tanpa kunci) ----- \n");
    char modification[] = "{{Pesan ini diubah oleh MITM}}";
    uint8_t intercepted_message[256]; 
    strcpy((char*)intercepted_message, (const char*)original_message);
    strcat((char*)intercepted_message, modification);
    printf("Pesan diubah menjadi: %s\n", intercepted_message);

    uint8_t mitm_digest[SHA256_DIGEST_LENGTH];
    SHA256_CTX mitm_sha_ctx;
    sha256_init(&mitm_sha_ctx);
    sha256_update(&mitm_sha_ctx, intercepted_message, strlen((char*)intercepted_message));
    sha256_final(&mitm_sha_ctx, mitm_digest);
    print_hex("Digest dari MITM", mitm_digest, SHA256_DIGEST_LENGTH);

    printf("\n\n----- SISI PENERIMA ----- \n");
    uint8_t calculated_hmac_on_received[SHA256_DIGEST_LENGTH];
    hmac_sha256(secret_key, strlen((char*)secret_key), intercepted_message,
                            strlen((char*)intercepted_message), calculated_hmac_on_received);
    print_hex("HMAC yang dihitung penerima", calculated_hmac_on_received, SHA256_DIGEST_LENGTH);

    if (memcmp(mitm_digest, calculated_hmac_on_received, SHA256_DIGEST_LENGTH) == 0) {
        printf("\nVERIFIKASI: Pesan otentik dan tidak dimodifikasi (digest cocok).\n");
    } else {
        printf("\nVERIFIKASI: Pesan terindikasi telah dipalsukan karena digest yang berbeda.\n");
    }

    return 0;
}