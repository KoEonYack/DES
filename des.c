/*
*		HW1 Implement DES algorithm using C  (ver 1.01 1810051638)
*		213000035 KoEonYack
* 		
*		Sbox from WiKi
*
*		Test Case
*		input : 123456abcd132536 
*		key   :  aabb09182736ccdd
*		result : c0b7a8d05f3a829c
*/

#include <stdio.h>
#include <stdlib.h>

#define CYPERER 0
#define DECYPER 1

// For visual  
// #pragma warning(disable:4996) 

unsigned long long des(unsigned long long plainTxt, unsigned long long key, int mode);

static unsigned char parity_drop[56] =
{ 
	57, 49, 41, 33, 25, 17, 9, 
	1, 58, 50, 42, 34, 26, 18,
	10, 2, 59, 51, 43, 35, 27,
	19, 11, 3, 60, 52, 44, 36,
	63, 55, 47, 39, 31, 23, 15,
	7, 62, 54, 46, 38, 30, 22,
	14, 6, 61, 53, 45, 37, 29,
	21, 13, 5, 28, 20, 12, 4 
};

static unsigned char compression_table[48] =
{ 
	14, 17, 11, 24, 1, 5,   
	3, 28, 15, 6, 21, 10,
	23, 19, 12, 4, 26, 8,
	16, 7, 27, 20, 13, 2,
	41, 52, 31, 37, 47, 55,
	30, 40, 51, 45, 33, 48,
	44, 49, 39, 56, 34, 53,
	46, 42, 50, 36, 29, 32 
};

static unsigned char initial_permutation[64] =
{  
	58, 50, 42, 34, 26, 18, 10, 2,
	60, 52, 44, 36, 28, 20, 12, 4,
	62, 54, 46, 38, 30, 22, 14, 6,
	64, 56, 48, 40, 32, 24, 16, 8,
	57, 49, 41, 33, 25, 17, 9, 1,
	59, 51, 43, 35, 27, 19, 11, 3,
	61, 53, 45, 37, 29, 21, 13, 5,
	63, 55, 47, 39, 31, 23, 15, 7 
};

static unsigned char expansion_pbox[48] =
{ 
	32, 1, 2, 3, 4, 5, 
	4, 5, 6, 7, 8, 9,
	8, 9, 10, 11, 12, 13,
	12, 13, 14, 15, 16, 17,
	16, 17, 18, 19, 20, 21,
	20, 21, 22, 23, 24, 25,
	24, 25, 26, 27, 28, 29,
	28, 29, 30, 31, 32, 1 
};

// sbox - from Wiki
static unsigned char sbox[8][4][16] = 
{ 
	{ { 14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7, },
	{ 0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8, },
	{ 4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0, },
	{ 15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13, }, },
	{ { 15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10, },
	{ 3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5, },
	{ 0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15, },
	{ 13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9, }, },
	{ { 10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8, },
	{ 13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1, },
	{ 13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7, },
	{ 1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12, }, },
	{ { 7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15, },
	{ 13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9, },
	{ 10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4, },
	{ 3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14, }, },
	{ { 2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9, },
	{ 14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6, },
	{ 4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14, },
	{ 11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3, }, },
	{ { 12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11, },
	{ 10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8, },
	{ 9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6, },
	{ 4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13, }, },
	{ { 4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1, },
	{ 13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6, },
	{ 1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2, },
	{ 6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12, }, },
	{ { 13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7, },
	{ 1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2, },
	{ 7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8, },
	{ 2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11 } } };

static unsigned char straight_pbox[32] = {
	16, 7, 20, 21, 
	29, 12, 28, 17,
	1, 15, 23, 26,
	5, 18, 31, 10,
	2, 8, 24, 14,
	32, 27, 3, 9,
	19, 13, 30, 6,
	22, 11, 4, 25 
};

static unsigned char final_permutation[64] = {
	40, 8, 48, 16, 56, 24, 64, 32, 
	39, 7, 47, 15, 55, 23, 63, 31,
	38, 6, 46, 14, 54, 22, 62, 30,
	37, 5, 45, 13, 53, 21, 61, 29,
	36, 4, 44, 12, 52, 20, 60, 28,
	35, 3, 43, 11, 51, 19, 59, 27,
	34, 2, 42, 10, 50, 18, 58, 26,
	33, 1, 41, 9, 49, 17, 57, 25 
};

int main() {
	unsigned long long painTxt, key, result;
	
	printf("Input 64bit plain text (in Hex) : ");
	scanf("%llx", &painTxt);

	printf("Input 64bit key (in Hex) : ");
	scanf("%llx", &key);

	result = des(painTxt, key, CYPERER);

	printf("Encryption Result :: %llx \n", result);
	printf("Decryption Result :: %llx \n", des(result, key, DECYPER));

	return 0;
}

unsigned long long des(unsigned long long plainTxt, unsigned long long key, int mode) {
	unsigned long long roundKey[16];
	unsigned long long cd = 0;
	unsigned long long temp = 0;
	unsigned long long result = 0;
	unsigned long long epOutput48 = 0;
	unsigned int sboxOutput32 = 0, pboxOut32 = 0;

	unsigned int l = 0, r = 0;
	unsigned int c = 0, d = 0;

	unsigned char sdata = 0, row = 0, col = 0;
	int  j = 0, i = 0, round = 0;

	for (i = 1; i <= 16; i++) { // initialize round key
		roundKey[i - 1] = 0;
	}

	// [Key Generation]
	for (j = 27; j >= 0; j--) {									// Parity drop
		c = c ^ (((key >> (64 - parity_drop[(27 - j)])) & 0x1) << j);
		d = d ^ (((key >> (64 - parity_drop[(55 - j)])) & 0x1) << j);
	}

	// [Shifting]
	for (i = 1; i <= 16; i++) {
		if ((i == 1) | (i == 2) | (i == 9) | (i == 16)) {		// One bit shift left
			c = ((c << 1) | (c >> 27)) & 0x0FFFFFFF;
			d = ((d << 1) | (d >> 27)) & 0x0FFFFFFF;
		}
		else {														// Two bit shift left
			c = ((c << 2) | (c >> 26)) & 0x0FFFFFFF;
			d = ((d << 2) | (d >> 26)) & 0x0FFFFFFF;
		}
		cd = 0;  // initiallizing for new value
		cd = ((cd ^ c) << 28) ^ d;

		for (j = 47; j >= 0; j--) {								// compression_table
			roundKey[i - 1] = roundKey[i - 1] ^ (((cd >> (56 - compression_table[(47 - j)])) & 0x1) << j);
		}
	}

	// Initial Permutation
	for (j = 31; j >= 0; j--) {
		l = l ^ (((plainTxt >> (64 - initial_permutation[(31 - j)])) & 0x1) << j);
		r = r ^ (((plainTxt >> (64 - initial_permutation[(63 - j)])) & 0x1) << j);
	}

	// 16 Rounds
	for (round = 0; round<16; round++)
	{
		// Expansion Permutation
		epOutput48 = 0;
		for (j = 47; j >= 0; j--) {
			epOutput48 = epOutput48 ^ ((long long)((r >> (32 - expansion_pbox[(47 - j)])) & 0x1) << j);
		}

		if (mode == CYPERER) {
			epOutput48 = epOutput48 ^ roundKey[round];        // [Encryption] Round Key xor for cipher
		}
		if (mode == DECYPER) {
			epOutput48 = epOutput48 ^ roundKey[15 - round];  // [Decryption] Round Key xor for decipher
		}

		// S Box Reduction
		sboxOutput32 = 0;
		for (i = 7; i >= 0; i--) {
			row = 0;
			col = 0;
			sdata = 0;
			sdata = (epOutput48 >> (i * 6)) & 0x3F;
			//accessing 6 bits at a time starting from MSB
			row = row ^ (sdata & 0x1);
			row = row ^ (((sdata >> 5) & 0x1) << 1);
			col = (sdata >> 1) & 0x0F;
			sboxOutput32 = sboxOutput32 ^ ((int)(sbox[7 - i][row][col] << (4 * i)));
		}

		// Permutation
		pboxOut32 = 0;
		for (j = 31; j >= 0; j--) {
			pboxOut32 = pboxOut32 ^ (((sboxOutput32 >> (32 - straight_pbox[(31 - j)])) & 0x1) << j);
		}
		pboxOut32 = pboxOut32 ^ l;

		// xor left half
		l = r;
		r = pboxOut32;
	}

	temp = 0;
	temp = ((temp ^ r) << 32) ^ l;  // 16 Round 32 bits SWAP

									// Final permutation
	result = 0;
	for (j = 63; j >= 0; j--) {
		result = result ^ (((temp >> (64 - final_permutation[(63 - j)])) & 0x1) << j);
	}

	return result;
}