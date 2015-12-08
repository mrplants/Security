// Data Encryption Standard
// Sean T Fitzgerald

#include "DES.h"

/*
INTERFACE
*/

/*
Input:
 1. inputData: The input char array.
 2. outputData: The output char array.
 3. key: The encryption key
 4. flag for decryption (0 for encryption, 1 for decryption)
Output:
 Success of the algorithm (0 is unsuccessful, otherwise successful)
Notes:
 The only difference between encryption and decryption is the order of the keys. Use this function for both and use argument #4 to differentiate
*/
int performDES(const char inputData[8], char outputData[8], const char key[8], const int decrypt);

/*
Input:
 1. inputData: The input char array to the function
 2. outputData: The output char array to the function post-encryption rounds
 3. roundKeys: The keys with which to perform the DES encryption rounds
*/
void performEcryptionRounds(const char inputData[8], char outputData[8], const char roundKeys[16][6]);

/*
Input:
 1. key: The encryption key
 2. resultantKeys: The per round keys based on argument #1
 3. backward: Flag for generating decryption keys (0 for forward/encrypt, 1 for backward/decrypt)
*/
void generatePerRoundKeys(const char key[8], char resultantKeys[16][6], int backward);

/*
Input:
 1. inputData: The input char array to the algorithm
*/
void generateInitialPermutation(const char inputData[8], char postPermutation[8]);

/*
Input:
 1. inputData: The input char array for the round
 2. roundResult: The char array result of the round
 3. roundKey: The key associated with this round
*/
void generateNewRound(const char inputData[8], char roundResult[8], const char roundKey[6]);

/*
Input:
 1. inputData: The input char array to the function
 2. outputData: The output char array with the left/right halves swapped.
*/
void swapHalves(const char inputData[8], char outputData[8]);

/*
Input:
 1. inputData: The input char array to the function
 2. postPermutation: the result of the halves swapped
*/
void generateFinalPermutation(const char inputData[8], char postPermutation[8]);

/*
Input:
 1. sourceKey: The key that will be copied
 2. destinationKey: The key which will be overwritten with argument #1
*/
void keyCopy(const char sourceKey[8], char destinationKey[8]);

/*
IMPLEMENTATION
*/

int encryptDES(const char inputData[8], char outputData[8], const char key[8])
{
	return performDES(inputData, outputData, key, 0);
}

int decryptDES(const char inputData[8], char outputData[8], const char key[8])
{
	return performDES(inputData, outputData, key, 1);
}

int encrypt3DES(const char inputData[8], char outputData[8], const char key[8])
{
	return perform3DES(inputData, outputData, key, 0);
}

int decrypt3DES(const char inputData[8], char outputData[8], const char key[8])
{
	return perform3DES(inputData, outputData, key, 1);
}

int perform3DES(const char inputData[8], char outputData[8], const char key[8], const int decrypt)
{
	int result1 = 1; // Bias toward success
	int result2 = 1;
	int result3 = 1;

	// For storing the result of meta-encryption steps
	char tempData[8];
	keyCopy(inputData, tempData);

	result1 = performDES(tempData, outputData, key, decrypt);
	keyCopy(outputData, tempData);

	result2 = performDES(tempData, outputData, key, !decrypt);
	keyCopy(outputData, tempData);

	result3 = performDES(tempData, outputData, key, decrypt);

	return (result1 && result2 && result3);
}

int performDES(const char inputData[8], char outputData[8], const char key[8], const int decrypt)
{
	/* Function temporary variables: */
	int successValue = 1; // Bias toward success
	char tempData[8]; // Temporary data buffer for in-between encryption steps
	char roundKeys[16][6]; // To store the round keys

	// First check the prity bit of the key to ensure that it was (1:256 chance) created and shared correctly (not super necessary, but might as well use the bits if we have them)
	if (checkKeyParityBits(key) == 0) // 0 means incorrect  parity bits
	{
		successValue = 0; // 0 means unsuccessful algorithm. Still attempt encryption with non-parity key
	}

	keyCopy(inputData, tempData); // Initialize the tempData with the initial data
	
	// Perform the initial permutation
	generateInitialPermutation(tempData, outputData);
	keyCopy(outputData, tempData);

	// Create the keys for each round & run the rounds
	generatePerRoundKeys(key, roundKeys, decrypt);
	performEcryptionRounds(tempData, outputData, roundKeys);
	keyCopy(outputData, tempData);

	// Swap the halves of the data
	swapHalves(tempData, outputData);
	keyCopy(outputData, tempData);

	// Perform the final reverse permutation
	generateFinalPermutation(tempData, outputData);

	// Return the result
	return successValue;
}

void performEcryptionRounds(const char inputData[8], char outputData[8], const char roundKeys[16][6])
{
	char tempData[8]; // Temporary data buffer for in-between encryption steps

	// Initialize tempData with inputData before key rounds
	keyCopy(inputData, tempData);

	// Run the 16 rounds
	for (int i = 0; i < 16; ++i)
	{
		generateNewRound(tempData, outputData, roundKeys[i]); // Run the round
		keyCopy(outputData, tempData); // Save the result for the next round
	}
}