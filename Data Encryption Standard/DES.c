// Data Encryption Standard
// Sean T Fitzgerald

/*
INTERFACE
*/

/*
PUBLIC
*/

/*
Input:
 1. dataInput: The input char array to the algorithm,
 2. key: The encryption key for the DES scheme
Output:
 Ciphertext char array resulting from encrypting argument #1 with DES using argument #2 as the key
*/
char *encryptDES(const char[8] dataInput, const char[8] key);

/*
PRIVATE
*/

/*
Input:
 1. key: The encryption key for the DES scheme
Output:
 0 implies key parity is incorrect. Otherwise, key parity is correct.
*/
int checkKeyParityBits(const char[8] key);

/*
Input:
 1. key: The encryption key for the DES scheme
Output:
 Array of 16 per-round keys of length 6 bytes (48 bits)
*/
char **generatePerRoundKeys(const char[8] key);

/*
Input:
 1. dataInput: The input char array to the algorithm
Output:
 Result of initial permutation of the dataInput. Same size char array returned.
*/

char *generateInitialPermutation(const char[8] dataInput);

/*
Input:
 1. dataInput: The input char array to the round
 2. roundKey: the key associated with this round
Output:
 Result of one DES encryption round with argument #1. Same size char array returned.
*/

char *generateNewRound(const char[8] dataInput, const char[6] ruondKey);

/*
Input:
 1. dataInput: The input char array to the function
Output:
 Result of swapping left and right halves of argument #1. Same size char array returned.
*/

 char *swapHalves(const char[8] dataInput);

 /*
Input:
 1. dataInput: The input char array to the function
Output:
 Result of the final permutation of argument #1. Same size char array returned.
*/

char *generateFinalPermutation(const char[8] dataInput);

/*
IMPLEMENTATION
*/