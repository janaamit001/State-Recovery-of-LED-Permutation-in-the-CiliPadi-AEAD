/*
 * cilipadi.h
 *
 *  Created on: 25 Feb 2019
 *      Author: mrz
 */

#ifndef CILIPADI128V1_REF_CILIPADI_H_
#define CILIPADI128V1_REF_CILIPADI_H_

#define BYTERATE 8 // bitrate in bytes
#define AROUNDS 18 // number of rounds for P_{a,n}
#define BROUNDS 16 // number of rounds for P_{b,n}
#define STATELEN 32 // state size in bytes
//#define DEBUG

int permutation_256(unsigned char *state, int rounds);
int permutation_384(unsigned char *state, int rounds);
int f_function(unsigned char *x, int l, int pround);
int xor_bytes(unsigned char *x, const unsigned char *y, int len);

int fault_on_permutation_256(unsigned char *state, int rounds, unsigned char diff);
int fault_on_f_function(unsigned char *x, int l, int pround, unsigned char diff);







int f_function_final_phase(unsigned char *x, int l, int pround);
int fault_on_f_function_final_phase(unsigned char *x, int l, int pround, unsigned char diff, unsigned char pos);
int fault_on_permutation_256_final_phase(unsigned char *state, int rounds, unsigned char diff, unsigned char pos);
int permutation_256_final_phase(unsigned char *state, int rounds);
void printstate256(unsigned char x1[8], unsigned char x2[8], unsigned char x3[8], unsigned char x4[8]);





#endif /* CILIPADI128V1_REF_CILIPADI_H_ */
