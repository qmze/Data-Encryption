#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>

#define MAX_BUFFER_SIZE 1024

void hash_password(const char *password, char *hashed_password) {
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, password, strlen(password));
    SHA256_Final((unsigned char *)hashed_password, &sha256);
}
void xor_encrypt_decrypt(char *input, char *key) {
    int len = strlen(input);
    int key_len = strlen(key);

    for (int i = 0; i < len; i++) {
        input[i] = input[i] ^ key[i % key_len];
    }
}

int main() {
    char plaintext[MAX_BUFFER_SIZE];
    char key[MAX_BUFFER_SIZE];
    char hashed_password[SHA256_DIGEST_LENGTH * 2 + 1];

    char username[MAX_BUFFER_SIZE];
    char password[MAX_BUFFER_SIZE];

    printf("Enter username: ");
    fgets(username, sizeof(username), stdin);

    printf("Enter password: ");
    fgets(password, sizeof(password), stdin);

    strtok(username, "\n");
    strtok(password, "\n");

    hash_password(password, hashed_password);

    if (strcmp(username, "admin") != 0 || strcmp(hashed_password, "hashed_password_here") != 0) {
        printf("Authentication failed. Exiting.\n");
        return 1;
    }

    FILE *inputFile = fopen("input.txt", "r");
    if (inputFile == NULL) {
        perror("Error opening file");
        return 1;
    }

    fgets(plaintext, sizeof(plaintext), inputFile);
    fclose(inputFile);

    printf("Enter encryption key: ");
    fgets(key, sizeof(key), stdin);

    strtok(key, "\n");

    xor_encrypt_decrypt(plaintext, key);

    FILE *outputFile = fopen("encrypted_output.txt", "w");
    if (outputFile == NULL) {
        perror("Error opening file");
        return 1;
    }

    fputs(plaintext, outputFile);
    fclose(outputFile);

    FILE *readFile = fopen("encrypted_output.txt", "r");
    if (readFile == NULL) {
        perror("Error opening file");
        return 1;
    }

    fgets(plaintext, sizeof(plaintext), readFile);
    fclose(readFile);

    xor_encrypt_decrypt(plaintext, key);

    printf("Decrypted: %s\n", plaintext);

    return 0;
}
#define MAX_BUFFER_SIZE 1024

void hash_password(const char *password, char *hashed_password) {
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, password, strlen(password));
    SHA256_Final((unsigned char *)hashed_password, &sha256);
}
void xor_encrypt_decrypt(char *input, char *key) {
    int len = strlen(input);
    int key_len = strlen(key);

    for (int i = 0; i < len; i++) {
        input[i] = input[i] ^ key[i % key_len];
    }
}

int main() {
    char plaintext[MAX_BUFFER_SIZE];
    char key[MAX_BUFFER_SIZE];
    char hashed_password[SHA256_DIGEST_LENGTH * 2 + 1];

    char username[MAX_BUFFER_SIZE];
    char password[MAX_BUFFER_SIZE];

    printf("Enter username: ");
    fgets(username, sizeof(username), stdin);

    printf("Enter password: ");
    fgets(password, sizeof(password), stdin);

    strtok(username, "\n");
    strtok(password, "\n");

    hash_password(password, hashed_password);

    if (strcmp(username, "admin") != 0 || strcmp(hashed_password, "hashed_password_here") != 0) {
        printf("Authentication failed. Exiting.\n");
        return 1;
    }

    FILE *inputFile = fopen("input.txt", "r");
    if (inputFile == NULL) {
        perror("Error opening file");
        return 1;
    }

    fgets(plaintext, sizeof(plaintext), inputFile);
    fclose(inputFile);

    printf("Enter encryption key: ");
    fgets(key, sizeof(key), stdin);

    strtok(key, "\n");

    xor_encrypt_decrypt(plaintext, key);

    FILE *outputFile = fopen("encrypted_output.txt", "w");
    if (outputFile == NULL) {
        perror("Error opening file");
        return 1;
    }

    fputs(plaintext, outputFile);
    fclose(outputFile);

    FILE *readFile = fopen("encrypted_output.txt", "r");
    if (readFile == NULL) {
        perror("Error opening file");
        return 1;
    }

    fgets(plaintext, sizeof(plaintext), readFile);
    fclose(readFile);

    xor_encrypt_decrypt(plaintext, key);

    printf("Decrypted: %s\n", plaintext);

    return 0;
}
