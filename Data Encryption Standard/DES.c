// Data Encryption Standard
// Sean T Fitzgerald

#include "DES.h"

/*
INTERFACE
*/

/*
Input:
 1. key: The encryption key
 2. resultantKeys:the per round keys based on argument #1
*/
void generatePerRoundKeys(const char[8] key, char[16][6] resultantKeys);

/*
Input:
 1. inputData: The input char array to the algorithm
*/
void generateInitialPermutation(const char[8] inputData, char[8] postPermutation);

/*
Input:
 1. inputData: The input char array for the round
 2. roundResult: The char array result of the round
 3. roundKey: The key associated with this round
*/
void generateNewRound(const char[8] inputData, char[8] roundResult, const char[6] ruondKey);

/*
Input:
 1. inputData: The input char array to the function
 2. outputData: The output char array with teh left/right halves swapped.
*/
 void swapHalves(const char[8] inputData, char[8] outputData);

/*
Input:
 1. inputData: The input char array to the function
 2. postPermutation: the result of the halves swapped
*/
void generateFinalPermutation(const char[8] inputData, char[8] postPermutation);

/*
Input:
 1. sourceKey: The key that will be copied
 2. destinationKey: The key which will be overwritten with argument #1
*/
void keyCopy(const char[8] sourceKey, char[8] destinationKey);

/*
IMPLEMENTATION
*/

int encryptDES(const char[8] inputData, char[8] outputData, const char[8] key);
{
	/* Function temporary variables: */
	int successValue = 1; // Bias toward success
	char[8] tempData; // Temporary data buffer for in-between encryption steps
	char[16][6] roundKeys; // To store the round keys

	// First check the prity bit of the key to ensure that it was (1:256 chance) created and shared correctly (not super necessary, but might as well use the bits if we have them)
	if (checkKeyParityBits(key) == 0) // 0 means incorrect  parity bits
	{
		successValue = 0; // 0 means unsuccessful algorithm. Still attempt encryption with non-parity key
	}
	
	// Perform the initial permutation
	generateInitialPermutation(inputData, tempData);

	// Create the keys for each round
	generatePerRoundKeys(key, roundKeys);

	// Initialize tempData with inputData before key rounds
	keyCopy(inputData, tempData);

	// Run the 16 rounds
	for (int i = 0; i < 16; ++i)
	{
		generateNewRound(tempData, outputData, roundKeys[i]); // Run the round
		keyCopy(outputData, tempData); // Save the result for the next round
	}

	// Swap the halves of the data
	swapHalves(tempData, outputData);
	keyCopy(outputData, tempData);

	// Perform the final reverse permutation
	generateFinalPermutation(tempData, outputData);

	// Return the result
	return successValue;
}