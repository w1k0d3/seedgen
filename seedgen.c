#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>

#define ENTROPY_SIZE 16     // 128-bit entropy for 12 words
#define MNEMONIC_WORDS 12
#define WORDLIST_SIZE 2048
#define CHECKSUM_BITS (ENTROPY_SIZE / 4) // 4 bits for 128-bit entropy

// Global wordlist array
char *wordlist[WORDLIST_SIZE];

// Load wordlist from file
void load_wordlist() {
    FILE *file = fopen("bip39_english.txt", "r");
    if (!file) {
        perror("Failed to open wordlist");
        exit(1);
    }

    char word[20];
    int index = 0;
    while (fgets(word, sizeof(word), file) && index < WORDLIST_SIZE) {
        word[strcspn(word, "\n")] = 0; // Remove newline character
        wordlist[index] = strdup(word); // Allocate and copy word
        index++;
    }
    fclose(file);

    if (index != WORDLIST_SIZE) {
        fprintf(stderr, "Error: Wordlist should have %d words but loaded %d\n", WORDLIST_SIZE, index);
        exit(1);
    }
}

// Generate random entropy (16 bytes for 12 words)
void generate_entropy(unsigned char *entropy) {
    FILE *f = fopen("/dev/urandom", "rb");
    if (!f) {
        perror("Failed to open /dev/urandom");
        exit(1);
    }
    fread(entropy, 1, ENTROPY_SIZE, f);
    fclose(f);
}

// Generate checksum (first SHA-256 bits of entropy)
unsigned char generate_checksum(unsigned char *entropy) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(entropy, ENTROPY_SIZE, hash);
    return hash[0] >> (8 - CHECKSUM_BITS); // Take first 4 bits
}

// Convert entropy to mnemonic
void entropy_to_mnemonic(unsigned char *entropy) {
    unsigned char full_entropy[ENTROPY_SIZE + 1];
    memcpy(full_entropy, entropy, ENTROPY_SIZE);
    full_entropy[ENTROPY_SIZE] = generate_checksum(entropy); // Append checksum

    // Convert entropy+checksum to 12 words (each word is 11 bits)
    unsigned int bit_array = 0;
    int bit_count = 0;

    for (int i = 0; i < MNEMONIC_WORDS; i++) {
        while (bit_count < 11) {
            bit_array = (bit_array << 8) | full_entropy[i * 11 / 8];
            bit_count += 8;
        }
        bit_count -= 11;
        int index = (bit_array >> bit_count) & 0x7FF; // Extract 11 bits

        if (index >= WORDLIST_SIZE) { // Ensure index is within range
            fprintf(stderr, "Error: Invalid word index %d\n", index);
            exit(1);
        }

        printf("%s", wordlist[index]);
        if (i < MNEMONIC_WORDS - 1) printf(" ");
    }
    printf("\n");
}

int main() {
    unsigned char entropy[ENTROPY_SIZE];

    load_wordlist(); // Load BIP-39 wordlist

    while (1) {
        generate_entropy(entropy);
        entropy_to_mnemonic(entropy);
    }

    return 0;
}

