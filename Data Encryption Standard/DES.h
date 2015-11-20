// Data Encryption Standard
// Sean T Fitzgerald

/*
Input:
 1. dataInput: The input char array to the algorithm. Max length if 8 bytes (64 bits)
 2. key: The encryption key for the DES scheme
Output:
 8-character (64-bit) ciphertext char array (on the stack) resulting from encrypting argument #1 with DES using argument #2 as the key
*/
char *encryptDES(char[8] dataInput, char[8] key);
