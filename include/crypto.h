/*
 * CNSA 2.0 Compliant Cryptography
 * Post-Quantum Crypto: ML-KEM-1024, ML-DSA-87, SHA-384
 */

#ifndef CRYPTO_H
#define CRYPTO_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <time.h>

/* CNSA 2.0 Algorithm Parameters */
#define MLKEM_1024_PUBLIC_KEY_BYTES     1568
#define MLKEM_1024_SECRET_KEY_BYTES     3168
#define MLKEM_1024_CIPHERTEXT_BYTES     1568
#define MLKEM_1024_SHARED_SECRET_BYTES  32

#define MLDSA_87_PUBLIC_KEY_BYTES       2592
#define MLDSA_87_SECRET_KEY_BYTES       4896
#define MLDSA_87_SIGNATURE_BYTES        4627

#define SHA384_DIGEST_BYTES             48

#define CRYPTO_SESSION_ID_BYTES         32
#define CRYPTO_TOKEN_BYTES              64

/* Key pair structures */
typedef struct {
    uint8_t public_key[MLKEM_1024_PUBLIC_KEY_BYTES];
    uint8_t secret_key[MLKEM_1024_SECRET_KEY_BYTES];
} mlkem_keypair_t;

typedef struct {
    uint8_t public_key[MLDSA_87_PUBLIC_KEY_BYTES];
    uint8_t secret_key[MLDSA_87_SECRET_KEY_BYTES];
} mldsa_keypair_t;

/* Session structure */
typedef struct {
    uint8_t session_id[CRYPTO_SESSION_ID_BYTES];
    uint8_t shared_secret[MLKEM_1024_SHARED_SECRET_BYTES];
    time_t created;
    time_t expires;
    bool valid;
} crypto_session_t;

/* Authentication token */
typedef struct {
    uint8_t token[CRYPTO_TOKEN_BYTES];
    uint8_t signature[MLDSA_87_SIGNATURE_BYTES];
    time_t issued;
    time_t expires;
} crypto_token_t;

/* Initialization and cleanup */
int crypto_init(void);
void crypto_cleanup(void);

/* Key generation */
int crypto_mlkem_keygen(mlkem_keypair_t *keypair);
int crypto_mldsa_keygen(mldsa_keypair_t *keypair);

/* ML-KEM-1024 operations (key encapsulation) */
int crypto_mlkem_encapsulate(const uint8_t *public_key,
                             uint8_t *ciphertext,
                             uint8_t *shared_secret);
int crypto_mlkem_decapsulate(const uint8_t *secret_key,
                             const uint8_t *ciphertext,
                             uint8_t *shared_secret);

/* ML-DSA-87 operations (digital signatures) */
int crypto_mldsa_sign(const uint8_t *secret_key,
                     const uint8_t *message,
                     size_t message_len,
                     uint8_t *signature);
int crypto_mldsa_verify(const uint8_t *public_key,
                       const uint8_t *message,
                       size_t message_len,
                       const uint8_t *signature);

/* SHA-384 hashing */
int crypto_sha384(const uint8_t *data, size_t len, uint8_t *hash);

/* Session management */
int crypto_create_session(const uint8_t *shared_secret, crypto_session_t *session);
int crypto_validate_session(const crypto_session_t *session);
void crypto_destroy_session(crypto_session_t *session);

/* Token management */
int crypto_create_token(const mldsa_keypair_t *keypair, crypto_token_t *token);
int crypto_verify_token(const uint8_t *public_key, const crypto_token_t *token);

/* Secure communication */
int crypto_encrypt_message(const uint8_t *shared_secret,
                          const uint8_t *plaintext,
                          size_t plaintext_len,
                          uint8_t *ciphertext,
                          size_t *ciphertext_len);
int crypto_decrypt_message(const uint8_t *shared_secret,
                          const uint8_t *ciphertext,
                          size_t ciphertext_len,
                          uint8_t *plaintext,
                          size_t *plaintext_len);

/* Key storage */
int crypto_save_keys(const char *path,
                    const mlkem_keypair_t *kem_keys,
                    const mldsa_keypair_t *dsa_keys);
int crypto_load_keys(const char *path,
                    mlkem_keypair_t *kem_keys,
                    mldsa_keypair_t *dsa_keys);

/* Secure random */
int crypto_random_bytes(uint8_t *buf, size_t len);

#endif /* CRYPTO_H */
