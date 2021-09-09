#ifdef _MSC_VER
#define _CRT_SECURE_NO_WARNINGS
#endif

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <time.h>

#include "crypto_aead.h"
#include "api.h"
#include "led.h"

#define KAT_SUCCESS          0
#define KAT_FILE_OPEN_ERROR -1
#define KAT_DATA_ERROR      -3
#define KAT_CRYPTO_FAILURE  -4

#define MAX_FILE_NAME				256
#define MAX_MESSAGE_LENGTH			32
#define MAX_ASSOCIATED_DATA_LENGTH	32
#define sboxSize 16

#define number 6


extern unsigned char Rstate[ 8 ], Rstate1[ 8 ], st[ 4 ][ 4 ];
//const unsigned char inv_s[16] = {5, 14, 15, 8, 12, 1, 2, 13, 11, 4, 6, 3, 0, 7, 9, 10};
unsigned char s[16] = {12, 5, 6, 11, 9, 0, 10, 13, 3, 14, 15, 8, 4, 7, 1, 2};


void init_buffer(unsigned char *buffer, unsigned long long numbytes) {

	for (unsigned long long i = 0; i < numbytes; i++)
		buffer[i] = (unsigned char)i;
	
	return;
}


void init_buffer_rand(unsigned char *buffer, unsigned long long numbytes) {

	time_t t;
	
	srand( (unsigned) time( &t ) );

	for (unsigned long long i = 0; i < numbytes; i++)
		buffer[i] = rand()%256;
	
	return;
}


void printDDT( unsigned char **ptr ) {


	for( int i = 0; i < 16; ++i ) {

		for( int j = 0; j < 16; ++j ) {

			printf("%d ", ptr[ i ][ j ]);
		}
		printf("\n");
	}

	return;
}


unsigned char **diffDistribution(unsigned char s[sboxSize]) {

	int i; 
	int x, y, delta, delta1;
	
	unsigned char** count = malloc(sboxSize*sizeof(int *));
	
	for(i = 0; i < sboxSize; ++i) {
		
		count[i] = malloc(sboxSize*sizeof(int));
		memset(count[i],0,sboxSize*sizeof(int));
	}
		
	for(y = 0; y < sboxSize; ++y) {
		
		for(x = 0; x < sboxSize; ++x) {
			
			delta = y^x;
			delta1 = s[x]^s[y];
			count[delta][delta1]++;
		}		
	}
	
	return count;
}



void print( unsigned char *m ) {

	printf("Ciphertext::\n");
	for( short i = 0; i < 32; ++i )
		printf("%x ", m[ i ]);
		
	printf("\n\n");
	
	printf("Tag::\n");
	for( short i = 32; i < 40; ++i )
		printf("%02x ", m[ i ]);
		
	printf("\n\n");

	return;
}


/*void forgery( unsigned char *m,
	unsigned long long *mlen,
	unsigned char *nsec,
	const unsigned char *c,
	unsigned long long clen,
	const unsigned char *ad,
	unsigned long long adlen,
	const unsigned char *npub,
	const unsigned char *k ) {
	
	
	
	
}*/


void copy_ciphertext( unsigned char ct1[], unsigned char ct[] ) {

	for( short i = 0; i < 40; ++i )
		ct1[ i ] = ct[ i ];

	return;
}

void xor_of_diff_tag( unsigned char state[4][4], unsigned char ct1[] ) {

	unsigned char byte[ 8 ];
	short i, j, counter = 0;
	
	for( i = 0; i < 4; ++i ) {
	
		for( j = 0; j < 2; ++j ) {
		
			//byte[ counter ] = (( state[ i ][ j ] << 4 ) & 0xf0 ) ^ ( state[ i ][ j + 1 ] & 0x0f );
			byte[i*2+j]  = state[i][j*2  ] << 4;
			byte[i*2+j] |= state[i][j*2+1];
		}
	}
	
	counter = 0;
	for( i = 32; i < 40; ++i ) {
	
		ct1[ i ] ^= byte[ counter ];
		++counter;
	}

	return;
}


void print_state( unsigned char state[ 4 ][ 4 ] ) {

	for( short i = 0; i < 4; ++i ) {
	
		for( short j = 0; j < 4; ++j ) 
			printf("%x ", state[ i ][ j ] );
		
		printf("\n");
	}
	
	printf("\n");

	return;
}


void extract_tags( unsigned char ct[ ], unsigned char ct1[ ], unsigned char tag[ ], unsigned char ftag[ ] ) {

	for( short i = 32, j = 0; i < 40; ++i, ++j ) {
	
		tag[ j ] = ct[ i ];
		ftag[ j ] = ct1[ i ]; 
	}


	return;
}

void print_tags( unsigned char tag[], unsigned char ftag[] ) {

	printf("fresh tag!!\n");
	for( short i = 0; i < 8; ++i )
		printf("%02x ", tag[ i ]);
	printf("\n");
	
	printf("faulty tag!!\n");
	for( short i = 0; i < 8; ++i )
		printf("%02x ", ftag[ i ]);
	printf("\n");
	
	return;
}


void fprint_bstr(FILE *fp, const char *label, const unsigned char *data, unsigned long long length)
{    
    fprintf(fp, "%s", label);
        
	for (unsigned long long i = 0; i < length; i++)
		fprintf(fp, "%x", data[i]);
	    
    //fprintf(fp, "\n");
}

void Recover_state_columnwise( unsigned char tag[], unsigned char ftag[], unsigned char pos, unsigned char count, unsigned char **ptr ) {

	unsigned char state[ 4 ][ 4 ], fstate[ 4 ][ 4 ], temp[ 4 ][ 4 ], col[ 4 ][ 4 ];
	FILE *f0, *f1, *f2, *f3;;
	unsigned char diff[ 4 ], diff1[ 4 ], delta, filename[ 24 ];
	unsigned char i, j;
	time_t t;

	srand( (unsigned) time( &t ) );

	for (i = 0; i < 16; ++i) {
	
		if( i%2 ) {
		
			state[i/4][i%4] = tag[i>>1] & 0xF;
			fstate[i/4][i%4] = ftag[i>>1] & 0xF;
		}
		else {
		
			state[i/4][i%4] = (tag[i>>1] >> 4) & 0xF;
			fstate[i/4][i%4] = (ftag[i>>1] >> 4) & 0xF;
		}
	}
	
	for( i = 0; i < 4; ++i ) {
	
		for( j = 0; j < 4; ++j ) 
			temp[ i ][ j ] = state[ i ][ j ] ^ fstate[ i ][ j ];
	}
	
	invMixColumn( temp );
	print_state( temp );
	invShiftRow( temp );
	print_state( temp );
	
	printf("Right hand diff:\n");
	for( i = 0; i < 4; ++i ) {
	
		diff[ i ] = temp[ i ][ pos ];
		printf("%x ", diff[ i ]);
	}
		
	printf("\n");
		
	sprintf(filename, "key_column%d%d0.txt", pos, count);
	if ((f0 = fopen(filename, "w")) == NULL) {
		fprintf(stderr, "Couldn't open <%s> for write\n", filename);
		exit(1);
	}
	
	sprintf(filename, "key_column%d%d1.txt", pos, count);
	if ((f1 = fopen(filename, "w")) == NULL) {
		fprintf(stderr, "Couldn't open <%s> for write\n", filename);
		exit(1);
	}
	
	sprintf(filename, "key_column%d%d2.txt", pos, count);
	if ((f2 = fopen(filename, "w")) == NULL) {
		fprintf(stderr, "Couldn't open <%s> for write\n", filename);
		exit(1);
	}
	
	sprintf(filename, "key_column%d%d3.txt", pos, count);
	if ((f3 = fopen(filename, "w")) == NULL) {
		fprintf(stderr, "Couldn't open <%s> for write\n", filename);
		exit(1);
	}
	
	//printf("diff[100] = %x\n", diff[100]);
	
	while( 1 ) {

	//for( i = 0; i < 16; ++i ) {
	
		delta = rand() & 0xf;
		diff1[ 0 ] = FieldMult( 0x4, delta );
		diff1[ 1 ] = FieldMult( 0x8, delta );
		diff1[ 2 ] = FieldMult( 0xb, delta );
		diff1[ 3 ] = FieldMult( 0x2, delta );

		printf("i = %d, check!!!\n", i);
		
		if( ( ptr[diff1[0]][diff[0]] > 0 ) && ( ptr[diff1[1]][diff[1]] > 0 ) && ( ptr[diff1[2]][diff[2]] > 0 ) && ( ptr[diff1[3]][diff[3]] > 0 ) ) {
		
			printf("..........delta = %x\n", delta);
			printf("Left hand diff:\n");
			for( j = 0; j < 4; ++j )
				printf("%x ", diff1[ j ]);
			printf("\n");
			break;
			//i = 15;
		}
	}	
	
	printf("%x, %x, %x, %x, %x, %x, %x, %x\n", diff[0], diff[1], diff[2], diff[3], diff1[0], diff1[1], diff1[2], diff1[3]);
	for( i = 0; i < 16; ++i ) {
	
		
		//printf("0-> %x %x %x\n", i, s[ i ] ^ s[ i ^ diff1[ 0 ] ], diff[ 0 ]);
		if( ( s[ i ] ^ s[ i ^ diff1[ 0 ] ] ) == diff[ 0 ] ) {
			
			printf("i = %x, diff = %x\n", i, diff[ 0 ]);
			fprint_bstr(f0, "", &i, 1);
		}
		
		//printf("1-> %x %x %x\n", i, s[ i ] ^ s[ i ^ diff1[ 1 ] ], diff[ 1 ]);		
		if( ( s[ i ] ^ s[ i ^ diff1[ 1 ] ] ) == diff[ 1 ] ) {
			
			printf("i = %x, diff = %x\n", i, diff[ 1 ]);
			fprint_bstr(f1, "", &i, 1);
		}
		
		//printf("2-> %x %x %x\n", i, s[ i ] ^ s[ i ^ diff1[ 2 ] ], diff[ 2 ]);		
		if( ( s[ i ] ^ s[ i ^ diff1[ 2 ] ] ) == diff[ 2 ] ) {
			
			printf("i = %x, diff = %x\n", i, diff[ 2 ]);
			fprint_bstr(f2, "", &i, 1);
		}
		
		//printf("3-> %x %x %x\n", i, s[ i ] ^ s[ i ^ diff1[ 3 ] ], diff[ 3 ]);		
		if( ( s[ i ] ^ s[ i ^ diff1[ 3 ] ] ) == diff[ 3 ] ) {
			
			printf("i = %x, diff = %x\n", i, diff[ 3 ]);
			fprint_bstr(f3, "", &i, 1);
		}
	}
	
	fclose( f0 );
	fclose( f1 );
	fclose( f2 );
	fclose( f3 );
		
	printf("\n***************************************************\n");
	return;
}

unsigned short findMax( unsigned short arr[] ) {

	unsigned short max = 0;

	for( unsigned char i = 0; i < 16; ++i ) {
	
		if( max < arr[ i ] )
			max = arr[ i ];
	}

	return( max );
}

void state_column0( ) {

	FILE *fp1; 
	unsigned char val[1];
	unsigned short max, arr[ 16 ] = {0};
	unsigned short num = 0, count1 = 0;
	unsigned char filename[ 24 ];

	printf("First Column::\n");
	
	for( unsigned char col= 0; col < 4; ++col ) {
	
		for( unsigned char count = 0; count < number; ++count ) {
		
			sprintf(filename, "key_column0%d%d.txt", count, col);
			if ((fp1 = fopen(filename, "r")) == NULL) {
				fprintf(stderr, "Couldn't open <%s> for read\n", filename);
				exit(1);
			}
			
			while(fread(val, 1, 1, fp1)) {
			

				
				if( ( val[0] == 'a' ) || ( val[0] == 'b' ) || ( val[0] == 'c' ) || ( val[0] == 'd' ) || ( val[0] == 'e' ) || ( val[0] == 'f' ) )
					val[0] = val[0] - 97 + 10;
				else 
					val[0] = val[0] - 48;
					
				//printf ("val = %x\n", val[0]);
				arr[ val[0] ] += 1;
			}
			
			fclose( fp1 );
		}

		printf("{ ");

		max = findMax( arr );
		printf("max = %d:: ", max);
		for( unsigned char i = 0; i < 16; ++i ) {
	
			if( arr[ i ] == max ) {
			
				printf("%x ", i );
				//printf("1st column = %04x\n", i);
				//++count1;
			}
		}
		printf("}");
		//printf("\n............\n");
		for( unsigned char i = 0; i < 16; ++i )
			arr[ i ] = 0;	
	}
	printf("\n");
}


void state_column1( ) {

	FILE *fp1; 
	unsigned char val[1];
	unsigned short max, arr[ 16 ] = {0};
	unsigned short num = 0, count1 = 0;
	unsigned char filename[ 24 ];

	printf("Second Column::\n");
	
	for( unsigned char col = 0; col < 4; ++col ) {
	
		for( unsigned char count = 0; count < number; ++count ) {
		
			sprintf(filename, "key_column1%d%d.txt", count, col);
			if ((fp1 = fopen(filename, "r")) == NULL) {
				fprintf(stderr, "Couldn't open <%s> for read\n", filename);
				exit(1);
			}
			
			while(fread(val, 1, 1, fp1)) {
			

				
				if( ( val[0] == 'a' ) || ( val[0] == 'b' ) || ( val[0] == 'c' ) || ( val[0] == 'd' ) || ( val[0] == 'e' ) || ( val[0] == 'f' ) )
					val[0] = val[0] - 97 + 10;
				else 
					val[0] = val[0] - 48;
					
				//printf ("val = %x\n", val[0]);
				arr[ val[0] ] += 1;
			}
			
			fclose( fp1 );
		}

		printf("{ ");
		max = findMax( arr );
		printf("max = %d:: ", max);
		for( unsigned char i = 0; i < 16; ++i ) {
	
			if( arr[ i ] == max ) {
			
				printf("%x ", i );
				//printf("1st column = %04x\n", i);
				//++count1;
			}
		}
		printf("}");
		//printf("\n............\n");
		for( unsigned char i = 0; i < 16; ++i )
			arr[ i ] = 0;	
	}
	printf("\n");
}


void state_column2( ) {

	FILE *fp1; 
	unsigned char val[1];
	unsigned short max, arr[ 16 ] = {0};
	unsigned short num = 0, count1 = 0;
	unsigned char filename[ 24 ];

	printf("Third Column::\n");
	
	for( unsigned char col = 0; col < 4; ++col ) {
	
		for( unsigned char count = 0; count < number; ++count ) {
		
			sprintf(filename, "key_column2%d%d.txt", count, col);
			if ((fp1 = fopen(filename, "r")) == NULL) {
				fprintf(stderr, "Couldn't open <%s> for read\n", filename);
				exit(1);
			}
			
			while(fread(val, 1, 1, fp1)) {
			

				
				if( ( val[0] == 'a' ) || ( val[0] == 'b' ) || ( val[0] == 'c' ) || ( val[0] == 'd' ) || ( val[0] == 'e' ) || ( val[0] == 'f' ) )
					val[0] = val[0] - 97 + 10;
				else 
					val[0] = val[0] - 48;
					
				//printf ("val = %x\n", val[0]);
				arr[ val[0] ] += 1;
			}
			
			fclose( fp1 );
		}

		printf("{ ");
		max = findMax( arr );
		printf("max = %d:: ", max);
		for( unsigned char i = 0; i < 16; ++i ) {
	
			if( arr[ i ] == max ) {
			
				printf("%x ", i );
				//i = 15;
				//printf("1st column = %04x\n", i);
				//++count1;
			}
		}
		printf("}");
		//printf("\n............\n");
		for( unsigned char i = 0; i < 16; ++i )
			arr[ i ] = 0;	
	}
	printf("\n");
}


void state_column3( ) {

	FILE *fp1; 
	unsigned char val[1];
	unsigned short max, arr[ 16 ] = {0};
	unsigned short num = 0, count1 = 0;
	unsigned char filename[ 24 ];

	printf("Fourth Column::\n");
	
	for( unsigned char col = 0; col < 4; ++col ) {
	
		for( unsigned char count = 0; count < number; ++count ) {
		
			sprintf(filename, "key_column3%d%d.txt", count, col);
			if ((fp1 = fopen(filename, "r")) == NULL) {
				fprintf(stderr, "Couldn't open <%s> for read\n", filename);
				exit(1);
			}
			
			while(fread(val, 1, 1, fp1)) {
			

				
				if( ( val[0] == 'a' ) || ( val[0] == 'b' ) || ( val[0] == 'c' ) || ( val[0] == 'd' ) || ( val[0] == 'e' ) || ( val[0] == 'f' ) )
					val[0] = val[0] - 97 + 10;
				else 
					val[0] = val[0] - 48;
					
				//printf ("val = %x\n", val[0]);
				arr[ val[0] ] += 1;
			}
			
			fclose( fp1 );
		}

		printf("{ ");
		max = findMax( arr );
		printf("max = %d:: ", max);
		for( unsigned char i = 0; i < 16; ++i ) {
	
			if( arr[ i ] == max ) {
			
				printf("%x ", i );
				//printf("1st column = %04x\n", i);
				//++count1;
			}
		}
		printf("}");
		//printf("\n............\n");
		for( unsigned char i = 0; i < 16; ++i )
			arr[ i ] = 0;	
	}
	printf("\n");
}



int main() {
	
	FILE                *fp;
	char                fileName[MAX_FILE_NAME];
	unsigned char       key[CRYPTO_KEYBYTES] = {0x10, 0x20, 0x30, 0x10, 0x20, 0x30, 0x10, 0x20, 0x30, 0x10, 0x20, 0x30, 0x10, 0x20, 0x30, 0xf1};
	unsigned char	    nonce[CRYPTO_NPUBBYTES];
	unsigned char       msg[MAX_MESSAGE_LENGTH];
	unsigned char       msg2[MAX_MESSAGE_LENGTH];
	unsigned char		ad[MAX_ASSOCIATED_DATA_LENGTH];
	unsigned char		ct[MAX_MESSAGE_LENGTH + CRYPTO_ABYTES];
	unsigned char ct1[ MAX_MESSAGE_LENGTH + CRYPTO_ABYTES ];
	//unsigned long long  clen, mlen2;
	int                  i, j;
	int                 func_ret, ret_val = KAT_SUCCESS;
	unsigned long long mlen, mlen2, clen, adlen;
	unsigned char diff, diff1, diff2, diff3, diff4, state[ 4 ][ 4 ];
	unsigned char tag[ 8 ], ftag[ 8 ];
	unsigned char count = 0, pos = 0;
	unsigned char **ddt = diffDistribution(s);
	time_t t;
	
	srand( (unsigned) time( &t ) );
	
	//init_buffer_rand(key, sizeof(key));
	init_buffer_rand(nonce, sizeof(nonce));
	init_buffer_rand(msg, sizeof(msg));
	init_buffer(ad, sizeof(ad));
	
	mlen = adlen = mlen2 = 32;
	clen = 48;

	printDDT( &ddt[ 0 ] );
	
	printf("....................................\n");
	if ( crypto_aead_encrypt(ct, &clen, msg, mlen, ad, adlen, NULL, nonce, key) == 0)
		;//print(ct);
		
	if ( crypto_aead_decrypt(msg2, &mlen2, NULL, ct, clen, ad, adlen, nonce, key) == 0) {
	
		print(ct);
		printf("Tag Compare is successful!!\n\n\n");
	}
	else
		printf("Not successful!!\n\n\n");	
	
	
	for( pos = 0; pos < 4; ++pos ) {
	
		printf("faulty forgery by injecting fault at the nibble position (0,%d)\n\n", pos);	
		for( diff1 = 0; diff1 < 32; ++diff1 ) {
		
			for( diff2 = 0; diff2 < 16; ++diff2 ) {
		
				for( diff3 = 0; diff3 < 16; ++diff3 ) {
		
					for( diff4 = 0; diff4 < 16; ++diff4 ) {
						
						
						for( i = 0; i < 4; ++i ) {
		
							for( j = 0; j < 4; ++j )
								state[ i ][ j ] = 0;
						}
						
						diff1 = rand() & 0xf;
						if( diff1 == 0 )
							diff1 = rand() & 0xf;
						state[ 0 ][ pos ] = diff1;
						
						diff2 = rand() & 0xf;
						if( diff2 == 0 )
							diff2 = rand() & 0xf;
						state[ 1 ][ pos ] = diff2;
						
						diff3 = rand() & 0xf;
						if( diff3 == 0 )
							diff3 = rand() & 0xf;
						state[ 2 ][ pos ] = diff3;
						
						diff4 = rand() & 0xf;
						if( diff4 == 0 )
							diff4 = rand() & 0xf;
						state[ 3 ][ pos ] = diff4;
						//printf("state difference before sr and mc:\n");
						//print_state( state );
						ShiftRow(state);
						MixColumn( state );
						//printf("state difference after sr and mc:\n");
						//print_state( state );
						copy_ciphertext( ct1, ct );
						xor_of_diff_tag( state, ct1 );
						
						//print(ct1);
						
						//for( i = 1; i< 16; ++i ) {
						
							//print(ct1);
							diff = rand() & 0xf;
							if( diff == 0 )
								diff = rand() & 0xf;
								
							if ( fault_on_crypto_aead_decrypt(msg2, &mlen2, NULL, ct1, clen, ad, adlen, nonce, key, diff, pos ) == 0 ) {
								//printf("T'=T+delta::\n");
								//print(ct1);
								printf("\nState, before the key and X2 is xoring to produce the Tag::\n");
								for( i = 0; i < 8; ++i ) {
								
									if( ( i != 0 ) && ( i % 2 == 0 ) )
										printf("\n");
									printf("%02x ", Rstate[ i ]);
								}

								printf("\nState after X2 is xoring but before key injected to produce the Tag::\n");
								for( i = 0; i < 8; ++i ) {
								
									if( ( i != 0 ) && ( i % 2 == 0 ) )
										printf("\n");
									printf("%02x ", Rstate1[ i ]);
								}

								
								printf("\nTag Compare is successful!!Tag Compare is successful!!Tag Compare is successful!!Tag Compare is successful!!\n\n");
								printf("diff = %x %x %x %x %x\n", diff1, diff2, diff3, diff4, diff);
								extract_tags( ct, ct1, tag, ftag );
								print_tags( tag, ftag );

								/*printf("\nkeys::\n");
								for( i = 0; i < 8; ++i ) {
								
									if( ( i != 0 ) && ( i % 2 == 0 ) )
										printf("\n");
									printf("%02x ", Rstate1[ i ]^tag[ i ]);
								}*/

								printf("\nled state after first round::\n");
								for( short i = 0; i < 4; ++i ) {

									for( short j = 0; j < 4; ++j )
									
										printf("%x ", st[ i ][ j ]);
									
									printf("\n");
								}
								printf("\n\n\n\n............................\n\n");
								
								Recover_state_columnwise( tag, ftag, pos, count, &ddt[ 0 ] );
								printf("............................................\n");
								//return 0;
								++count;
							}
							//print(ct1);
							
						if( count == number )
							diff4 = 31;
					}
									
					if( count == number )
						diff3 = 31;	
				}
				
				if( count == number )
					diff2 = 31;
			}
			
			if( count == number )
				diff1 = 31;
		}
		//printf("...............total count = %d....................\n\n", count);
		count = 0;
	}
	
	
	state_column0();
	state_column1();
	state_column2();
	state_column3();
	print_state( state );
	print(ct1);
	
	//printf("field mult:: %x, %x, %x, %x\n", FieldMult(0x4,0xd), FieldMult(0x2,0x9), FieldMult(0x8,0xf), FieldMult(0xb,0x5));
	
	return 0;
}
