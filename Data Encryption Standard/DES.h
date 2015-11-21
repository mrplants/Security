// Data Encryption Standard
// Sean T Fitzgerald

/*
Input:
 1. inputData: The input char array.
 2. outputData: The output char array.
 3. key: The encryption key
Output:
 Success of the algorithm (0 is unsuccessful, otherwise successful)
Notes:
 Function will attempt to encrypt even if key parity is incorrect (Output will be 0, however)
*/
int encryptDES(const char[8] inputData, char[8] outputData, const char[8] key);

/*
Input:
 1. inputData: The input char array.
 2. outputData: The output char array.
 3. key: The encryption key
Output:
 Success of the algorithm (0 is unsuccessful, otherwise successful)
Notes:
 Function will attempt to decrypt even if key parity is incorrect (Output will be 0, however)
*/
int decryptDES(const char[8] inputData, char[8] outputData, const char[8] key);

/*
Input:
 1. key: The encryption key
Output:
 0 implies key parity is incorrect. Otherwise correct
*/
int checkKeyParityBits(const char[8] key);
