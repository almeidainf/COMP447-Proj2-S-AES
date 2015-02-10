/*
 * LOYOLA UNIVERSITY CHICAGO
 * COMP 447-001 - INTRUSION DETECTION - FALL 2014
 *
 * Tiago de Almeida - tdealmeida@luc.edu
 * 1394611
 *
 * Graduate Project 2
 * Programming
 *
 * Simplified AES Implementation
 */

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>

#include "almeidamacros.h"
#include "galois.h"

#define BUFFER_LENGTH (4*1024*1024)

#define ENCRYPT 0
#define DECRYPT 1

uint8_t Sbox[16] = { 0x9, 0x4, 0xA, 0xB, 0xD, 0x1, 0x8, 0x5, 0x6, 0x2, 0x0, 0x3, 0xC, 0xE, 0xF, 0x7};
uint8_t inverse_Sbox[16] = { 0xA, 0x5, 0x9, 0xB, 0x1, 0x7, 0x8, 0xF, 0x6, 0x0, 0x2, 0x3, 0xC, 0x4, 0xD, 0xE};

// SAES functions:
// Encryption
void block_encrypt(uint8_t *block, uint8_t *key);
void nibble_substitution(uint8_t *state);
void shift_row(uint8_t *state);
void mix_column(uint8_t *state);
// Decryption
void block_decrypt(uint8_t *block, uint8_t *key);
void inverse_nibble_substitution(uint8_t *state);
void inverse_shift_row(uint8_t *state);
void inverse_mix_column(uint8_t *state);
// General
void _nibble_substitution(uint8_t *state, uint8_t *box);
void add_key(uint8_t *state, uint8_t *key);
// Key Management
void key_expansion(uint8_t *key, uint8_t *expanded_key);
uint8_t RotNib(uint8_t key);
uint8_t SubNib(uint8_t key);


int main(int argc, char **argv){

	if(argc < 4){
		verbose("Usage: ./saes encrypt/decrypt input_file key");
		exit(EXIT_FAILURE);
	}

// Obtaining and veryfing input parameters
	char *input_file = argv[2];
	char *key = argv[3];
	int operation;
	if(!strncmp(argv[1], "encrypt", 7))
		operation = ENCRYPT;
	else if(!strncmp(argv[1], "decrypt", 7))
		operation = DECRYPT;
	else{
		error("Operation not identified.");
		verbose("Usage: ./saes encrypt/decrypt input_file key");
		exit(EXIT_FAILURE);
	}

// Variables
	// Key
	uint8_t *expanded_key;
	int expanded_key_length;
	// Input and Output
	uint8_t buffer[BUFFER_LENGTH];
	long int read_ret, write_ret, bindex;
	int input, output, kindex;
	char *output_file;

// Presentation
	printf(" SIMPLIFIED AES\n");
	verbose("Input file: %s", argv[2]);
	verbose("Key: %s", argv[3]);

// Expanding key
	expanded_key_length = strlen(key) * 3;
	expanded_key = talloc(uint8_t, expanded_key_length);
	key_expansion(key, expanded_key);

// Opening input file
	input = open(input_file, O_RDONLY);
	if(input < 0){
		perror("Error opening input file");
		exit(EXIT_FAILURE);
	}

// Naming output file
	output_file = talloc(char, strlen(input_file) + 9);
	if(operation == ENCRYPT)
		sprintf(output_file, "%s.encrypted", input_file);
	else
		sprintf(output_file, "%s.decrypted", input_file);
	verbose("Output file: %s", output_file);

// Opening output file
	output = open(output_file, O_WRONLY | O_CREAT | O_EXCL, 0777);
	if(output < 0){
		perror("Error opening output file");
		exit(EXIT_FAILURE);
	}

// Read, Encrypt/Decrypt, Write
	while(1){
		
		// Reading input file
		read_ret = read(input, buffer, BUFFER_LENGTH);
		if(read_ret == 0){ 
			break;
		}
		if(read_ret < 0){
			perror("Error reading input file");
			exit(EXIT_FAILURE);
		}

		// Encryption and Decryption
		if(operation == ENCRYPT) // Encryption
			for(bindex = 0, kindex = 0; bindex < (read_ret-1); bindex += 2, kindex += 6){
				if(kindex > expanded_key_length){
					kindex = 0;
//					printf(".");
				}
				block_encrypt(&buffer[bindex], &key[kindex]);
			}
		else // Decryption
			for(bindex = 0, kindex = 0; bindex < (read_ret-1); bindex += 2, kindex += 6){
				if(kindex > expanded_key_length){
					kindex = 0;
//					printf(".");
				}
				block_decrypt(&buffer[bindex], &key[kindex]);
			}
		
		// Writing to output file
		if(write(output, buffer, read_ret) < 0){
			perror("Error writing output file");
			exit(EXIT_FAILURE);
		}
	}

// Closing files
	if(close(input) < 0)
		perror("Error closing input file");
	if(close(output) < 0)
		perror("Error closing output file");
	
	return EXIT_SUCCESS;
}


void block_encrypt(uint8_t *block, uint8_t *key){
// Round 0
	add_key(block, &key[0]);
// Round 1
	nibble_substitution(block);
	shift_row(block);
	mix_column(block);
	add_key(block, &key[2]);
// Round 3
	nibble_substitution(block);
	shift_row(block);
	add_key(block, &key[4]);
}

void block_decrypt(uint8_t *block, uint8_t *key){
// Round 0
	add_key(block, &key[4]);
// Round 1
	inverse_shift_row(block);
	inverse_nibble_substitution(block);
	add_key(block, &key[2]);
	inverse_mix_column(block);
// Round 2
	inverse_shift_row(block);
	inverse_nibble_substitution(block);
	add_key(block, &key[0]);
}

void add_key(uint8_t *state, uint8_t *key){
// Works as the inverse add_key as well;
	state[0] ^= key[0];
	state[1] ^= key[1];
}

void nibble_substitution(uint8_t *state){
	 _nibble_substitution(state, Sbox);
}

void inverse_nibble_substitution(uint8_t *state){
	 _nibble_substitution(state, inverse_Sbox);
}

void _nibble_substitution(uint8_t *state, uint8_t *box){
	
	uint8_t new_state[2];

	new_state[0] = box[state[0] >> 4] << 4;
	new_state[0] |= box[state[0] & 0xF];
	new_state[1] = box[state[1] >> 4] << 4;
	new_state[1] |= box[state[1] & 0xF];

	state[0] = new_state[0];
	state[1] = new_state[1];
}

void shift_row(uint8_t *state){
// Works as the inverse shift_row as well;
	uint8_t new_state[2];

	new_state[0] = (state[0] & 0xF0) | (state[1] & 0xF);
	new_state[1] = (state[1] & 0xF0) | (state[0] & 0xF);

	state[0] = new_state[0];
	state[1] = new_state[1];
}

void inverse_shift_row(uint8_t *state){
	shift_row(state);
}

void mix_column(uint8_t *state){

	uint8_t new_state[2];

	new_state[0] = ((state[0] >> 4) ^ galois_single_multiply(4, state[0] & 0xF, 4)) << 4;
	new_state[0] |= (galois_single_multiply(4, state[0] >> 4, 4) ^ (state[0] & 0xF)) & 0xF;
	new_state[1] = ((state[1] >> 4) ^ galois_single_multiply(4, state[1] & 0xF, 4)) << 4;
	new_state[1] |= (galois_single_multiply(4, state[1] >> 4, 4) ^ (state[1] & 0xF)) & 0xF;

	state[0] = new_state[0];
	state[1] = new_state[1];
}

void inverse_mix_column(uint8_t *state){

	uint8_t new_state[2];

	new_state[0] = (galois_single_multiply(9, state[0] >> 4, 4) ^ galois_single_multiply(2, state[0] & 0xF, 4)) << 4;
	new_state[0] |= (galois_single_multiply(2, state[0] >> 4, 4) ^ galois_single_multiply(9, state[0] & 0xF, 4)) & 0xF;
	new_state[1] = (galois_single_multiply(9, state[1] >> 4, 4) ^ galois_single_multiply(2, state[1] & 0xF, 4)) << 4;
	new_state[1] |= (galois_single_multiply(2, state[1] >> 4, 4) ^ galois_single_multiply(9, state[1] & 0xF, 4)) & 0xF;

	state[0] = new_state[0];
	state[1] = new_state[1];
}

void key_expansion(uint8_t *key, uint8_t *expanded_key){
	
	expanded_key[0] = key[0];
	expanded_key[1] = key[1];
	expanded_key[2] = key[0] ^ 0x80 ^ SubNib(RotNib(key[1]));
	expanded_key[3] = expanded_key[2] ^ key[1];
	expanded_key[4] = expanded_key[2] ^ 0x30 ^ SubNib(RotNib(expanded_key[3]));
	expanded_key[5] = expanded_key[4] ^ expanded_key[3];
}

uint8_t RotNib(uint8_t key){
	
	uint8_t temp = (key & 0xF) << 4;
	key >>= 4;
	key |= temp;

	return key;
}

uint8_t SubNib(uint8_t key){
	
	uint8_t saved_key = key;

	key = Sbox[saved_key >> 4] << 4;
	key |= Sbox[saved_key & 0xF];

	return key;
}
