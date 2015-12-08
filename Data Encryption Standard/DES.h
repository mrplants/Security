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
int encryptDES(const char inputData[8], char outputData[8], const char key[8]);

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
int decryptDES(const char inputData[8], char outputData[8], const char key[8]);

/*
Input:
 1. inputData: The input char array.
 2. outputData: The output char array.
 3. key: The encryption key
Output:
 Success of the algorithm (0 is unsuccessful, otherwise successful)
Notes:
 3DES - Performs DES-Encrypt, DES-Decrypt, DES-Encrypt. Used as a more secure version of DES.
 Function will attempt to encrypt even if key parity is incorrect (Output will be 0, however)
*/
int encrypt3DES(const char inputData[8], char outputData[8], const char key[8]);

/*
Input:
 1. inputData: The input char array.
 2. outputData: The output char array.
 3. key: The encryption key
Output:
 Success of the algorithm (0 is unsuccessful, otherwise successful)
Notes:
 3DES - Performs DES-Decrypt, DES-Encrypt, DES-Decrypt. Used as a more secure version of DES.
 Function will attempt to decrypt even if key parity is incorrect (Output will be 0, however)
*/
int decrypt3DES(const char inputData[8], char outputData[8], const char key[8]);

/*
Input:
 1. key: The encryption key
Output:
 0 implies key parity is incorrect. Otherwise correct
*/
int checkKeyParityBits(const char key[8]);