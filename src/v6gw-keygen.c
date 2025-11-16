/*
 * v6gw-keygen - CNSA 2.0 Key Generation Utility
 * Generates ML-KEM-1024 and ML-DSA-87 keypairs for v6-gatewayd
 */

#include "crypto.h"
#include "log.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <unistd.h>

static void print_usage(const char *progname) {
    printf("v6gw-keygen - CNSA 2.0 Key Generation Utility\n\n");
    printf("Usage: %s [options]\n\n", progname);
    printf("Options:\n");
    printf("  -o, --output FILE   Output key file (default: /var/lib/v6-gatewayd/keys.bin)\n");
    printf("  -f, --force         Overwrite existing key file\n");
    printf("  -v, --verbose       Verbose output\n");
    printf("  -h, --help          Show this help message\n");
    printf("\n");
    printf("Generates post-quantum cryptographic keys:\n");
    printf("  - ML-KEM-1024 (key encapsulation)\n");
    printf("  - ML-DSA-87 (digital signatures)\n");
    printf("  - CNSA 2.0 compliant\n");
}

int main(int argc, char *argv[]) {
    const char *output_file = "/var/lib/v6-gatewayd/keys.bin";
    bool force = false;
    bool verbose = false;

    static struct option long_options[] = {
        {"output",  required_argument, 0, 'o'},
        {"force",   no_argument,       0, 'f'},
        {"verbose", no_argument,       0, 'v'},
        {"help",    no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "o:fvh", long_options, NULL)) != -1) {
        switch (opt) {
            case 'o':
                output_file = optarg;
                break;
            case 'f':
                force = true;
                break;
            case 'v':
                verbose = true;
                break;
            case 'h':
                print_usage(argv[0]);
                return 0;
            default:
                print_usage(argv[0]);
                return 1;
        }
    }

    /* Initialize logging */
    log_init(verbose ? "debug" : "info");

    /* Check if file exists */
    if (!force && access(output_file, F_OK) == 0) {
        fprintf(stderr, "Error: Key file already exists: %s\n", output_file);
        fprintf(stderr, "Use --force to overwrite\n");
        return 1;
    }

    printf("Generating CNSA 2.0 post-quantum cryptographic keys...\n");

    /* Initialize crypto */
    if (crypto_init() != 0) {
        fprintf(stderr, "Error: Failed to initialize cryptography\n");
        return 1;
    }

    /* Generate ML-KEM-1024 keypair */
    printf("Generating ML-KEM-1024 keypair (key encapsulation)...\n");
    mlkem_keypair_t kem_keys;
    if (crypto_mlkem_keygen(&kem_keys) != 0) {
        fprintf(stderr, "Error: Failed to generate ML-KEM-1024 keypair\n");
        crypto_cleanup();
        return 1;
    }
    printf("  Public key:  %lu bytes\n", sizeof(kem_keys.public_key));
    printf("  Secret key:  %lu bytes\n", sizeof(kem_keys.secret_key));

    /* Generate ML-DSA-87 keypair */
    printf("Generating ML-DSA-87 keypair (digital signatures)...\n");
    mldsa_keypair_t dsa_keys;
    if (crypto_mldsa_keygen(&dsa_keys) != 0) {
        fprintf(stderr, "Error: Failed to generate ML-DSA-87 keypair\n");
        crypto_cleanup();
        return 1;
    }
    printf("  Public key:  %lu bytes\n", sizeof(dsa_keys.public_key));
    printf("  Secret key:  %lu bytes\n", sizeof(dsa_keys.secret_key));

    /* Save keys to file */
    printf("Saving keys to: %s\n", output_file);
    if (crypto_save_keys(output_file, &kem_keys, &dsa_keys) != 0) {
        fprintf(stderr, "Error: Failed to save keys\n");
        crypto_cleanup();
        return 1;
    }

    printf("\nKey generation complete!\n");
    printf("Key file: %s (permissions: 0600)\n", output_file);
    printf("\nIMPORTANT:\n");
    printf("  - Keep this file secure and backed up\n");
    printf("  - Loss of keys will require regeneration\n");
    printf("  - Public keys can be distributed to clients\n");
    printf("\nTo use with v6-gatewayd, add to config:\n");
    printf("  crypto_enabled = true\n");
    printf("  crypto_keyfile = %s\n", output_file);

    /* Cleanup */
    memset(&kem_keys, 0, sizeof(kem_keys));
    memset(&dsa_keys, 0, sizeof(dsa_keys));
    crypto_cleanup();

    return 0;
}
