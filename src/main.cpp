#include <Arduino.h>
#include "mbedtls/ecdsa.h"
#include "mbedtls/sha256.h"
#include "mbedtls/pk.h"
#include "mbedtls/ecp.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#include "mbedtls/error.h"

void print_error(int ret) {
    char error_buf[100];
    mbedtls_strerror(ret, error_buf, 100);
    Serial.print("Error: ");
    Serial.println(error_buf);
}

void setup() {
    Serial.begin(115200);

    const char *message = "Hello, Digital Signature!";
    unsigned char hash[32];
    unsigned char signature[64];
    size_t sig_len;
    int ret;

    // Compute SHA-256 hash of the message
    mbedtls_sha256_context sha_ctx;
    mbedtls_sha256_init(&sha_ctx);
    mbedtls_sha256_starts_ret(&sha_ctx, 0);
    mbedtls_sha256_update_ret(&sha_ctx, (const unsigned char *)message, strlen(message));
    mbedtls_sha256_finish_ret(&sha_ctx, hash);
    mbedtls_sha256_free(&sha_ctx);

    // Initialize entropy and CTR_DRBG
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    const char *pers = "ecdsa_genkey";

    ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                (const unsigned char *)pers, strlen(pers));
    if (ret != 0) {
        print_error(ret);
        return;
    }

    // Generate key pair
    mbedtls_ecdsa_context ecdsa_ctx;
    mbedtls_ecdsa_init(&ecdsa_ctx);
    ret = mbedtls_ecdsa_genkey(&ecdsa_ctx, MBEDTLS_ECP_DP_SECP256R1, mbedtls_ctr_drbg_random, &ctr_drbg);
    if (ret != 0) {
        print_error(ret);
        return;
    }

    // Sign the hash
    ret = mbedtls_ecdsa_write_signature(&ecdsa_ctx, MBEDTLS_MD_SHA256, hash, sizeof(hash),
                                        signature, &sig_len, mbedtls_ctr_drbg_random, &ctr_drbg);
    if (ret != 0) {
        print_error(ret);
        return;
    }

    Serial.println("Signature:");
    for (size_t i = 0; i < sig_len; i++) {
        Serial.printf("%02x", signature[i]);
    }
    Serial.println();

    // Verify the signature
    ret = mbedtls_ecdsa_read_signature(&ecdsa_ctx, hash, sizeof(hash), signature, sig_len);
    if (ret == 0) {
        Serial.println("Signature verified successfully!");
    } else {
        print_error(ret);
    }

    mbedtls_ecdsa_free(&ecdsa_ctx);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
}

void loop() {
    // put your main code here, to run repeatedly:
}
