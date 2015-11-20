// Data Encryption Standard
// Sean T Fitzgerald

/*
INPUT:
 1. plaintextInput: The input string to the algorithm. Max length if 8 bytes (64 bits)
 2. key: The encryption key for the DES scheme
OUTPUT:
 Ciphertext string resulting from encrypting argument #1 with DES using argument #2 as the key
*/
char[8] encryptDES(char[8] plaintextInput, char[8] key);