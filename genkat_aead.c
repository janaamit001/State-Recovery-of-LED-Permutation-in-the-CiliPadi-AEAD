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

extern unsigned char Rstate[ 8 ];
const unsigned char inv_s[16] = {5, 14, 15, 8, 12, 1, 2, 13, 11, 4, 6, 3, 0, 7, 9, 10};


void init_buffer(unsigned char *buffer, unsigned long long numbytes) {

	for (unsigned long long i = 0; i < numbytes; i++)
		buffer[i] = (unsigned char)i;
	
	return;
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

unsigned char first_row_MC_inv( unsigned char t[], unsigned char ft[] ) {

	unsigned char val = inv_s[ FieldMult(0xc, t[ 0 ]) ^ FieldMult(0xc, t[ 1 ]) ^ FieldMult(0xd, t[ 2 ]) ^ FieldMult(0x4, t[ 3 ]) ] ^ inv_s[ FieldMult(0xc, ft[ 0 ]) ^ FieldMult(0xc, ft[ 1 ]) ^ FieldMult(0xd, ft[ 2 ]) ^ FieldMult(0x4, ft[ 3 ]) ];
	
	//printf("%x ", val);

	return ( val );

}


unsigned char second_row_MC_inv( unsigned char t[], unsigned char ft[] ) {

	unsigned char val = inv_s[ FieldMult(0x3, t[ 0 ]) ^ FieldMult(0x8, t[ 1 ]) ^ FieldMult(0x4, t[ 2 ]) ^ FieldMult(0x5, t[ 3 ]) ] ^ inv_s[ FieldMult(0x3, ft[ 0 ]) ^ FieldMult(0x8, ft[ 1 ]) ^ FieldMult(0x4, ft[ 2 ]) ^ FieldMult(0x5, ft[ 3 ]) ];
	
	//printf("%x ", val);

	return ( val );

}

unsigned char third_row_MC_inv( unsigned char t[], unsigned char ft[] ) {

	return ( inv_s[ FieldMult(0x7, t[ 0 ]) ^ FieldMult(0x6, t[ 1 ]) ^ FieldMult(0x2, t[ 2 ]) ^ FieldMult(0xe, t[ 3 ]) ] ^ inv_s[ FieldMult(0x7, ft[ 0 ]) ^ FieldMult(0x6, ft[ 1 ]) ^ FieldMult(0x2, ft[ 2 ]) ^ FieldMult(0xe, ft[ 3 ]) ] );

}

unsigned char fourth_row_MC_inv( unsigned char t[], unsigned char ft[] ) {

	return ( inv_s[ FieldMult(0xd, t[ 0 ]) ^ FieldMult(0x9, t[ 1 ]) ^ FieldMult(0x9, t[ 2 ]) ^ FieldMult(0xd, t[ 3 ]) ] ^ inv_s[ FieldMult(0xd, ft[ 0 ]) ^ FieldMult(0x9, ft[ 1 ]) ^ FieldMult(0x9, ft[ 2 ]) ^ FieldMult(0xd, ft[ 3 ]) ] );

}


void fprint_bstr(FILE *fp, const char *label, const unsigned char *data, unsigned long long length)
{    
    fprintf(fp, "%s", label);
        
	for (unsigned long long i = 0; i < length; i++)
		fprintf(fp, "%x", data[i]);
	    
    //fprintf(fp, "\n");
}


void Recover_state_columnwise( unsigned char tag[], unsigned char ftag[] ) {

	unsigned char state[ 4 ][ 4 ], fstate[ 4 ][ 4 ];
	unsigned int i, j, count1  = 0, count2 = 0, count3 = 0, count4 = 0;
	unsigned char z1[ 4 ], z2[ 8 ], t1[ 4 ], ft1[ 4 ],t2[ 4 ], ft2[ 4 ],t3[ 4 ], ft3[ 4 ],t4[ 4 ], ft4[ 4 ];
	FILE *f1, *f2, *f3, *f4;
	bool data1[ 16 ] = { 0 };
	bool data2[ 16 ] = { 0 };
	bool data3[ 16 ] = { 0 };
	bool data4[ 16 ] = { 0 };
	unsigned char val;

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
	
	//f1 = fopen("key_column1.txt", "w");
	f2 = fopen("key_column48.txt", "w");
	
	for( z1[ 0 ] = 0; z1[ 0 ] < 16; ++z1[ 0 ] ) {
	
		for( z1[ 1 ] = 0; z1[ 1 ] < 16; ++z1[ 1 ] ) {
		
			for( z1[ 2 ] = 0; z1[ 2 ] < 16; ++z1[ 2 ] ) {
			
				for( z1[ 3 ] = 0; z1[ 3 ] < 16; ++z1[ 3 ] ) {
				
					for( i = 0; i < 4; ++i ) {
					
						t1[ i ] = z1[ i ] ^ state[ i ][ 3 ];
						ft1[ i ] = z1[ i ] ^ fstate[ i ][ 3 ];
					}
					
					//data1[ FieldMult( 0xd,first_row_MC_inv( t1, ft1 ) ) ] = 1;
					
					val = FieldMult( 0xd,first_row_MC_inv( t1, ft1 ) );
					data1[ val ] = 1;
					if( val == 0x7 ) {
					
						//fprint_bstr(f2, "", z1, 4);
						++count1;
					}
				}
			}
		}	
	}
	
	for( i = 0; i < 16; ++i )
		printf("%d ", data1[ i ]);
	printf("\n");
	
	for( z2[ 0 ] = 0; z2[ 0 ] < 16; ++z2[ 0 ] ) {
	
		for( z2[ 1 ] = 0; z2[ 1 ] < 16; ++z2[ 1 ] ) {
		
			for( z2[ 2 ] = 0; z2[ 2 ] < 16; ++z2[ 2 ] ) {
			
				for( z2[ 3 ] = 0; z2[ 3 ] < 16; ++z2[ 3 ] ) {
				
					for( i = 0; i < 4; ++i ) {
					
						t2[ i ] = z2[ i ] ^ state[ i ][ 2 ];
						ft2[ i ] = z2[ i ] ^ fstate[ i ][ 2 ];
					}
	
					//data2[ FieldMult( 0xf, second_row_MC_inv( t2, ft2 ) ) ] = 1;
					val = FieldMult( 0xf, second_row_MC_inv( t2, ft2 ) );
					data2[ val ] = 1;
					if( val == 0x7 ) {
					
						//fprint_bstr(f2, "", z2, 4);
						++count2;
					}
					
					
				}
			}
		}
	}
	
	
	for( i = 0; i < 16; ++i )
		printf("%d ", data2[ i ]);
	printf("\n");


	for( z2[ 0 ] = 0; z2[ 0 ] < 16; ++z2[ 0 ] ) {
	
		for( z2[ 1 ] = 0; z2[ 1 ] < 16; ++z2[ 1 ] ) {
		
			for( z2[ 2 ] = 0; z2[ 2 ] < 16; ++z2[ 2 ] ) {
			
				for( z2[ 3 ] = 0; z2[ 3 ] < 16; ++z2[ 3 ] ) {
				
					for( i = 0; i < 4; ++i ) {
					
						t3[ i ] = z2[ i ] ^ state[ i ][ 1 ];
						ft3[ i ] = z2[ i ] ^ fstate[ i ][ 1 ];
					}
	
					//data3[ FieldMult( 0x5, third_row_MC_inv( t3, ft3 ) ) ] = 1;
					val = FieldMult( 0x5, third_row_MC_inv( t3, ft3 ) );
					data3[ val ] = 1;
					if( val == 0xe ) {
					
						//fprint_bstr(f2, "", z2, 4);
						++count3;
					}
					
				}
			}
		}
	}
	
	
	for( i = 0; i < 16; ++i )
		printf("%d ", data3[ i ]);
	printf("\n");
	
	
	
	for( z2[ 0 ] = 0; z2[ 0 ] < 16; ++z2[ 0 ] ) {
	
		for( z2[ 1 ] = 0; z2[ 1 ] < 16; ++z2[ 1 ] ) {
		
			for( z2[ 2 ] = 0; z2[ 2 ] < 16; ++z2[ 2 ] ) {
			
				for( z2[ 3 ] = 0; z2[ 3 ] < 16; ++z2[ 3 ] ) {
				
					for( i = 0; i < 4; ++i ) {
					
						t4[ i ] = z2[ i ] ^ state[ i ][ 0 ];
						ft4[ i ] = z2[ i ] ^ fstate[ i ][ 0 ];
					}
	
					//data4[ FieldMult( 0x9, fourth_row_MC_inv( t4, ft4 ) ) ] = 1;
					val = FieldMult( 0x9, fourth_row_MC_inv( t4, ft4 ) );
					data4 [ val ] = 1;
					if( val == 0x7 ) {
					
						fprint_bstr(f2, "", z2, 4);
						++count4;
					}
					
					
				}
			}
		}
	}
	
	
	for( i = 0; i < 16; ++i )
		printf("%d ", data4[ i ]);
	printf("\n");


	

	//fclose(f1);
	fclose(f2);
	printf("number of keys will be %d %d %d %d\n", count1, count2, count3, count4);
	return;
}



/*void Recover_state_columnwise( unsigned char tag[], unsigned char ftag[] ) {

	unsigned char state[ 4 ][ 4 ], fstate[ 4 ][ 4 ];
	unsigned int i, j, count1  = 0, count2 = 0, count3 = 0, count4 = 0;
	unsigned char z1[ 4 ], z2[ 8 ], t1[ 4 ], ft1[ 4 ],t2[ 4 ], ft2[ 4 ],t3[ 4 ], ft3[ 4 ],t4[ 4 ], ft4[ 4 ];
	FILE *f1, *f2, *f3, *f4;
	bool data1[ 16 ] = { 0 };
	bool data2[ 16 ] = { 0 };
	bool data3[ 16 ] = { 0 };
	bool data4[ 16 ] = { 0 };
	unsigned char val;

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
	
	//f1 = fopen("key_column1.txt", "w");
	f2 = fopen("key_column32.txt", "w");
	
	for( z1[ 0 ] = 0; z1[ 0 ] < 16; ++z1[ 0 ] ) {
	
		for( z1[ 1 ] = 0; z1[ 1 ] < 16; ++z1[ 1 ] ) {
		
			for( z1[ 2 ] = 0; z1[ 2 ] < 16; ++z1[ 2 ] ) {
			
				for( z1[ 3 ] = 0; z1[ 3 ] < 16; ++z1[ 3 ] ) {
				
					for( i = 0; i < 4; ++i ) {
					
						t1[ i ] = z1[ i ] ^ state[ i ][ 2 ];
						ft1[ i ] = z1[ i ] ^ fstate[ i ][ 2 ];
					}
					
					//data1[ FieldMult( 0xd,first_row_MC_inv( t1, ft1 ) ) ] = 1;
					
					val = FieldMult( 0xd,first_row_MC_inv( t1, ft1 ) );
					data1[ val ] = 1;
					if( val == 0x7 ) {
					
						//fprint_bstr(f2, "", z1, 4);
						++count1;
					}
				}
			}
		}	
	}
	
	for( i = 0; i < 16; ++i )
		printf("%d ", data1[ i ]);
	printf("\n");
	
	for( z2[ 0 ] = 0; z2[ 0 ] < 16; ++z2[ 0 ] ) {
	
		for( z2[ 1 ] = 0; z2[ 1 ] < 16; ++z2[ 1 ] ) {
		
			for( z2[ 2 ] = 0; z2[ 2 ] < 16; ++z2[ 2 ] ) {
			
				for( z2[ 3 ] = 0; z2[ 3 ] < 16; ++z2[ 3 ] ) {
				
					for( i = 0; i < 4; ++i ) {
					
						t2[ i ] = z2[ i ] ^ state[ i ][ 1 ];
						ft2[ i ] = z2[ i ] ^ fstate[ i ][ 1 ];
					}
	
					//data2[ FieldMult( 0xf, second_row_MC_inv( t2, ft2 ) ) ] = 1;
					val = FieldMult( 0xf, second_row_MC_inv( t2, ft2 ) );
					data2[ val ] = 1;
					if( val == 0x7 ) {
					
						//fprint_bstr(f2, "", z2, 4);
						++count2;
					}
					
					
				}
			}
		}
	}
	
	
	for( i = 0; i < 16; ++i )
		printf("%d ", data2[ i ]);
	printf("\n");


	for( z2[ 0 ] = 0; z2[ 0 ] < 16; ++z2[ 0 ] ) {
	
		for( z2[ 1 ] = 0; z2[ 1 ] < 16; ++z2[ 1 ] ) {
		
			for( z2[ 2 ] = 0; z2[ 2 ] < 16; ++z2[ 2 ] ) {
			
				for( z2[ 3 ] = 0; z2[ 3 ] < 16; ++z2[ 3 ] ) {
				
					for( i = 0; i < 4; ++i ) {
					
						t3[ i ] = z2[ i ] ^ state[ i ][ 0 ];
						ft3[ i ] = z2[ i ] ^ fstate[ i ][ 0 ];
					}
	
					//data3[ FieldMult( 0x5, third_row_MC_inv( t3, ft3 ) ) ] = 1;
					val = FieldMult( 0x5, third_row_MC_inv( t3, ft3 ) );
					data3[ val ] = 1;
					if( val == 0xe ) {
					
						fprint_bstr(f2, "", z2, 4);
						++count3;
					}
					
				}
			}
		}
	}
	
	
	for( i = 0; i < 16; ++i )
		printf("%d ", data3[ i ]);
	printf("\n");
	
	
	
	for( z2[ 0 ] = 0; z2[ 0 ] < 16; ++z2[ 0 ] ) {
	
		for( z2[ 1 ] = 0; z2[ 1 ] < 16; ++z2[ 1 ] ) {
		
			for( z2[ 2 ] = 0; z2[ 2 ] < 16; ++z2[ 2 ] ) {
			
				for( z2[ 3 ] = 0; z2[ 3 ] < 16; ++z2[ 3 ] ) {
				
					for( i = 0; i < 4; ++i ) {
					
						t4[ i ] = z2[ i ] ^ state[ i ][ 3 ];
						ft4[ i ] = z2[ i ] ^ fstate[ i ][ 3 ];
					}
	
					//data4[ FieldMult( 0x9, fourth_row_MC_inv( t4, ft4 ) ) ] = 1;
					val = FieldMult( 0x9, fourth_row_MC_inv( t4, ft4 ) );
					data4 [ val ] = 1;
					if( val == 0x7 )
						++count4;
					
					
				}
			}
		}
	}
	
	
	for( i = 0; i < 16; ++i )
		printf("%d ", data4[ i ]);
	printf("\n");


	

	//fclose(f1);
	fclose(f2);
	printf("number of keys will be %d %d %d %d\n", count1, count2, count3, count4);
	return;
}*/



/*void Recover_state_columnwise( unsigned char tag[], unsigned char ftag[] ) {

	unsigned char state[ 4 ][ 4 ], fstate[ 4 ][ 4 ];
	unsigned int i, j, count1  = 0, count2 = 0, count3 = 0, count4 = 0;
	unsigned char z1[ 4 ], z2[ 8 ], t1[ 4 ], ft1[ 4 ],t2[ 4 ], ft2[ 4 ],t3[ 4 ], ft3[ 4 ],t4[ 4 ], ft4[ 4 ];
	FILE *f1, *f2, *f3, *f4;
	bool data1[ 16 ] = { 0 };
	bool data2[ 16 ] = { 0 };
	bool data3[ 16 ] = { 0 };
	bool data4[ 16 ] = { 0 };
	unsigned char val;

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
	
	//f1 = fopen("key_column1.txt", "w");
	f2 = fopen("key_column2c.txt", "w");
	
	for( z1[ 0 ] = 0; z1[ 0 ] < 16; ++z1[ 0 ] ) {
	
		for( z1[ 1 ] = 0; z1[ 1 ] < 16; ++z1[ 1 ] ) {
		
			for( z1[ 2 ] = 0; z1[ 2 ] < 16; ++z1[ 2 ] ) {
			
				for( z1[ 3 ] = 0; z1[ 3 ] < 16; ++z1[ 3 ] ) {
				
					for( i = 0; i < 4; ++i ) {
					
						t1[ i ] = z1[ i ] ^ state[ i ][ 1 ];
						ft1[ i ] = z1[ i ] ^ fstate[ i ][ 1 ];
					}
					
					//data1[ FieldMult( 0xd,first_row_MC_inv( t1, ft1 ) ) ] = 1;
					
					val = FieldMult( 0xd,first_row_MC_inv( t1, ft1 ) );
					data1[ val ] = 1;
					if( val == 0x7 ) {
					
						//fprint_bstr(f2, "", z1, 4);
						++count1;
					}
				}
			}
		}	
	}
	
	for( i = 0; i < 16; ++i )
		printf("%d ", data1[ i ]);
	printf("\n");
	
	for( z2[ 0 ] = 0; z2[ 0 ] < 16; ++z2[ 0 ] ) {
	
		for( z2[ 1 ] = 0; z2[ 1 ] < 16; ++z2[ 1 ] ) {
		
			for( z2[ 2 ] = 0; z2[ 2 ] < 16; ++z2[ 2 ] ) {
			
				for( z2[ 3 ] = 0; z2[ 3 ] < 16; ++z2[ 3 ] ) {
				
					for( i = 0; i < 4; ++i ) {
					
						t2[ i ] = z2[ i ] ^ state[ i ][ 0 ];
						ft2[ i ] = z2[ i ] ^ fstate[ i ][ 0 ];
					}
	
					//data2[ FieldMult( 0xf, second_row_MC_inv( t2, ft2 ) ) ] = 1;
					val = FieldMult( 0xf, second_row_MC_inv( t2, ft2 ) );
					data2[ val ] = 1;
					if( val == 0x7 ) {
					
						fprint_bstr(f2, "", z2, 4);
						++count2;
					}
					
					
				}
			}
		}
	}
	
	
	for( i = 0; i < 16; ++i )
		printf("%d ", data2[ i ]);
	printf("\n");


	for( z2[ 0 ] = 0; z2[ 0 ] < 16; ++z2[ 0 ] ) {
	
		for( z2[ 1 ] = 0; z2[ 1 ] < 16; ++z2[ 1 ] ) {
		
			for( z2[ 2 ] = 0; z2[ 2 ] < 16; ++z2[ 2 ] ) {
			
				for( z2[ 3 ] = 0; z2[ 3 ] < 16; ++z2[ 3 ] ) {
				
					for( i = 0; i < 4; ++i ) {
					
						t3[ i ] = z2[ i ] ^ state[ i ][ 3 ];
						ft3[ i ] = z2[ i ] ^ fstate[ i ][ 3 ];
					}
	
					//data3[ FieldMult( 0x5, third_row_MC_inv( t3, ft3 ) ) ] = 1;
					val = FieldMult( 0x5, third_row_MC_inv( t3, ft3 ) );
					data3[ val ] = 1;
					if( val == 0x7 )
						++count3;
					
					
				}
			}
		}
	}
	
	
	for( i = 0; i < 16; ++i )
		printf("%d ", data3[ i ]);
	printf("\n");
	
	
	
	for( z2[ 0 ] = 0; z2[ 0 ] < 16; ++z2[ 0 ] ) {
	
		for( z2[ 1 ] = 0; z2[ 1 ] < 16; ++z2[ 1 ] ) {
		
			for( z2[ 2 ] = 0; z2[ 2 ] < 16; ++z2[ 2 ] ) {
			
				for( z2[ 3 ] = 0; z2[ 3 ] < 16; ++z2[ 3 ] ) {
				
					for( i = 0; i < 4; ++i ) {
					
						t4[ i ] = z2[ i ] ^ state[ i ][ 2 ];
						ft4[ i ] = z2[ i ] ^ fstate[ i ][ 2 ];
					}
	
					//data4[ FieldMult( 0x9, fourth_row_MC_inv( t4, ft4 ) ) ] = 1;
					val = FieldMult( 0x9, fourth_row_MC_inv( t4, ft4 ) );
					data4 [ val ] = 1;
					if( val == 0x7 )
						++count4;
					
					
				}
			}
		}
	}
	
	
	for( i = 0; i < 16; ++i )
		printf("%d ", data4[ i ]);
	printf("\n");


	

	//fclose(f1);
	fclose(f2);
	printf("number of keys will be %d %d %d %d\n", count1, count2, count3, count4);
	return;
}*/





/*void Recover_state_columnwise( unsigned char tag[], unsigned char ftag[] ) {

	unsigned char state[ 4 ][ 4 ], fstate[ 4 ][ 4 ];
	unsigned int i, j, count1  = 0, count2 = 0, count3 = 0, count4 = 0;
	unsigned char z1[ 4 ], z2[ 8 ], t1[ 4 ], ft1[ 4 ],t2[ 4 ], ft2[ 4 ],t3[ 4 ], ft3[ 4 ],t4[ 4 ], ft4[ 4 ];
	FILE *f1, *f2, *f3, *f4;
	bool data1[ 16 ] = { 0 };
	bool data2[ 16 ] = { 0 };
	bool data3[ 16 ] = { 0 };
	bool data4[ 16 ] = { 0 };
	unsigned char val;

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
	
	//f1 = fopen("key_column1.txt", "w");
	f2 = fopen("key_column2c.txt", "w");
	
	for( z1[ 0 ] = 0; z1[ 0 ] < 16; ++z1[ 0 ] ) {
	
		for( z1[ 1 ] = 0; z1[ 1 ] < 16; ++z1[ 1 ] ) {
		
			for( z1[ 2 ] = 0; z1[ 2 ] < 16; ++z1[ 2 ] ) {
			
				for( z1[ 3 ] = 0; z1[ 3 ] < 16; ++z1[ 3 ] ) {
				
					for( i = 0; i < 4; ++i ) {
					
						t1[ i ] = z1[ i ] ^ state[ i ][ 0 ];
						ft1[ i ] = z1[ i ] ^ fstate[ i ][ 0 ];
					}
					
					//data1[ FieldMult( 0xd,first_row_MC_inv( t1, ft1 ) ) ] = 1;
					
					val = FieldMult( 0xd,first_row_MC_inv( t1, ft1 ) );
					data1[ val ] = 1;
					if( val == 0x0 ) {
					
						fprint_bstr(f2, "", z1, 4);
						++count1;
					}
				}
			}
		}	
	}
	
	for( i = 0; i < 16; ++i )
		printf("%d ", data1[ i ]);
	printf("\n");
	
	for( z2[ 0 ] = 0; z2[ 0 ] < 16; ++z2[ 0 ] ) {
	
		for( z2[ 1 ] = 0; z2[ 1 ] < 16; ++z2[ 1 ] ) {
		
			for( z2[ 2 ] = 0; z2[ 2 ] < 16; ++z2[ 2 ] ) {
			
				for( z2[ 3 ] = 0; z2[ 3 ] < 16; ++z2[ 3 ] ) {
				
					for( i = 0; i < 4; ++i ) {
					
						t2[ i ] = z2[ i ] ^ state[ i ][ 3 ];
						ft2[ i ] = z2[ i ] ^ fstate[ i ][ 3 ];
					}
	
					//data2[ FieldMult( 0xf, second_row_MC_inv( t2, ft2 ) ) ] = 1;
					val = FieldMult( 0xf, second_row_MC_inv( t2, ft2 ) );
					data2[ val ] = 1;
					if( val == 0x9 )
						++count2;
					
					
				}
			}
		}
	}
	
	
	for( i = 0; i < 16; ++i )
		printf("%d ", data2[ i ]);
	printf("\n");


	for( z2[ 0 ] = 0; z2[ 0 ] < 16; ++z2[ 0 ] ) {
	
		for( z2[ 1 ] = 0; z2[ 1 ] < 16; ++z2[ 1 ] ) {
		
			for( z2[ 2 ] = 0; z2[ 2 ] < 16; ++z2[ 2 ] ) {
			
				for( z2[ 3 ] = 0; z2[ 3 ] < 16; ++z2[ 3 ] ) {
				
					for( i = 0; i < 4; ++i ) {
					
						t3[ i ] = z2[ i ] ^ state[ i ][ 2 ];
						ft3[ i ] = z2[ i ] ^ fstate[ i ][ 2 ];
					}
	
					//data3[ FieldMult( 0x5, third_row_MC_inv( t3, ft3 ) ) ] = 1;
					val = FieldMult( 0x5, third_row_MC_inv( t3, ft3 ) );
					data3[ val ] = 1;
					if( val == 0x0 )
						++count3;
					
					
				}
			}
		}
	}
	
	
	for( i = 0; i < 16; ++i )
		printf("%d ", data3[ i ]);
	printf("\n");
	
	
	
	for( z2[ 0 ] = 0; z2[ 0 ] < 16; ++z2[ 0 ] ) {
	
		for( z2[ 1 ] = 0; z2[ 1 ] < 16; ++z2[ 1 ] ) {
		
			for( z2[ 2 ] = 0; z2[ 2 ] < 16; ++z2[ 2 ] ) {
			
				for( z2[ 3 ] = 0; z2[ 3 ] < 16; ++z2[ 3 ] ) {
				
					for( i = 0; i < 4; ++i ) {
					
						t4[ i ] = z2[ i ] ^ state[ i ][ 1 ];
						ft4[ i ] = z2[ i ] ^ fstate[ i ][ 1 ];
					}
	
					//data4[ FieldMult( 0x9, fourth_row_MC_inv( t4, ft4 ) ) ] = 1;
					val = FieldMult( 0x9, fourth_row_MC_inv( t4, ft4 ) );
					data4 [ val ] = 1;
					if( val == 0xf )
						++count4;
					
					
				}
			}
		}
	}
	
	
	for( i = 0; i < 16; ++i )
		printf("%d ", data4[ i ]);
	printf("\n");


	

	//fclose(f1);
	fclose(f2);
	printf("number of keys will be %d %d %d %d\n", count1, count2, count3, count4);
	return;
}*/


int main() {
	
	FILE                *fp;
	char                fileName[MAX_FILE_NAME];
	unsigned char       key[CRYPTO_KEYBYTES];
	unsigned char		nonce[CRYPTO_NPUBBYTES];
	unsigned char       msg[MAX_MESSAGE_LENGTH];
	unsigned char       msg2[MAX_MESSAGE_LENGTH];
	unsigned char		ad[MAX_ASSOCIATED_DATA_LENGTH];
	unsigned char		ct[MAX_MESSAGE_LENGTH + CRYPTO_ABYTES];
	unsigned char ct1[ MAX_MESSAGE_LENGTH + CRYPTO_ABYTES ];
	//unsigned long long  clen, mlen2;
	int                 count = 1, i, j;
	int                 func_ret, ret_val = KAT_SUCCESS;
	unsigned long long mlen, mlen2, clen, adlen;
	unsigned char diff, diff1, diff2, diff3, diff4, state[ 4 ][ 4 ];
	unsigned char tag[ 8 ], ftag[ 8 ];
	unsigned short pos = 0;
	time_t t;
	
	srand( (unsigned) time( &t ) );
	
	init_buffer(key, sizeof(key));
	init_buffer(nonce, sizeof(nonce));
	init_buffer(msg, sizeof(msg));
	init_buffer(ad, sizeof(ad));
	
	mlen = adlen = mlen2 = 32;
	clen = 48;
	
	/*for( i = 0; i < 4; ++i ) {
	
		for( j = 0; j < 4; ++j )
			state[ i ][ j ] = 0;
	}*/
	
	for( short i = 0; i < 16; ++i )
		printf("key[ %d ] = %d ", i, key[ i ]);
		
	/*msg[ 0 ] = 0x00;
	msg[ 1 ] = 0x01;
	msg[ 31 ] = 0x00;*/
	printf("....................................\n");
	if ( crypto_aead_encrypt(ct, &clen, msg, mlen, ad, adlen, NULL, nonce, key) == 0)
		;//print(ct);
		
	if ( crypto_aead_decrypt(msg2, &mlen2, NULL, ct, clen, ad, adlen, nonce, key) == 0) {
	
		print(ct);
		printf("Tag Compare is successful!!\n\n\n");
	}
	else
		printf("Not successful!!\n\n\n");
	
	/*ct[ 0 ] = 0x00;	
	if ( crypto_aead_decrypt(msg2, &mlen2, NULL, ct, clen, ad, adlen, nonce, key) == 0)
		printf("Tag Compare is successful!!\n");
	else
		printf("Not successful!!\n");
		
	ct[ 0 ] = 0x58;
	if ( crypto_aead_decrypt(msg2, &mlen2, NULL, ct, clen, ad, adlen, nonce, key) == 0)
		printf("Tag Compare is successful!!\n");
	else
		printf("Not successful!!\n");*/
		
		
	/*for( diff1 = 0; diff1 < 16; ++diff1 ) {
	
		for( diff2 = 0; diff2 < 16; ++diff2 ) {
	
			for( diff3 = 0; diff3 < 16; ++diff3 ) {
	
				for( diff4 = 0; diff4 < 16; ++diff4 ) {*/
					
					
					for( i = 0; i < 4; ++i ) {
	
						for( j = 0; j < 4; ++j )
							state[ i ][ j ] = 0;
					}
					
					state[ 0 ][ 3 ] = 0x1;//diff1;//0x1;//diff1;//0x1;//diff1;//0x7;//0x6;//0x5;//0x4;//0x3;//0x2;//diff1;//0xb;//diff1;//0xa;//0x1;//0x2;//diff1;//0x1;//diff1;//0x0a;//diff1;
					state[ 1 ][ 3 ] = 0x2;//diff2;//0x6;//diff2;//0xb;//diff2;//0xb;//0xe;//0x7;//0xc;//0x6;//0x9;//diff2;//0x4;//diff2;//0x5;//0x8;//0x9;//diff2;//0x8;//diff2;//0x05;//diff2;
					state[ 2 ][ 3 ] = 0x7;//diff3;//0xb;//diff3;//0x9;//diff3;//0x5;//0x2;//0x8;//0xf;//0x4;//0x7;//diff3;//0x3;//diff3;//0x9;//0xd;//0x7;//diff3;//0xd;//diff3;//0x09;//diff3;
					state[ 3 ][ 3 ] = 0xc;//diff4;//0xf;//diff4;//0x3;//diff4;//0x9;//0x3;//0xa;//0x7;//0xb;//0x4;//diff4;//0x1;//diff4;//0xd;//0x5;//0x4;//diff4;//0x5;//diff4;//0x0d;//diff4;
					//printf("state difference before sr and mc:\n");
					//print_state( state );
					ShiftRow(state);
					MixColumn( state );
					//printf("state difference after sr and mc:\n");
					//print_state( state );
					copy_ciphertext( ct1, ct );
					xor_of_diff_tag( state, ct1);
					//print(ct1);
					
					for( i = 1; i< 16; ++i ) {
					
						//print(ct1);
						diff = 0x8;//i;//0x2;//i;//0xc;//i;//0xf;//0x6;//0xd;//0x09;//0x8;//i;//0x2;//rand() % 16;//0x1;//0x4//0x7;//rand() % 16;
						if ( fault_on_crypto_aead_decrypt(msg2, &mlen2, NULL, ct1, clen, ad, adlen, nonce, key, diff) == 0) {
							//print(ct1);
							printf("\nState, before the key and X2 is xoring to produce the Tag::\n");
							for( i = 0; i < 8; ++i ) {
							
								if( ( i != 0 ) && ( i % 2 == 0 ) )
									printf("\n");
								printf("%02x ", Rstate[ i ] ^ i);
							}
							
							printf("\nTag Compare is successful!!Tag Compare is successful!!Tag Compare is successful!!Tag Compare is successful!!\n\n");
							printf("diff = %x %x %x %x %x\n", diff1, diff2, diff3, diff4, diff);
							extract_tags( ct, ct1, tag, ftag );
							print_tags( tag, ftag );
							Recover_state_columnwise( tag, ftag );
							return 0;
						}
						//print(ct1);
					}
				/*}				
					
			}
		
		}
	
	}*/
	
	//print_state( state );
	//print(ct1);
	
	//printf("field mult:: %x, %x, %x, %x\n", FieldMult(0x4,0xd), FieldMult(0x2,0x9), FieldMult(0x8,0xf), FieldMult(0xb,0x5));
	
	return 0;
}

//void init_buffer(unsigned char *buffer, unsigned long long numbytes);

//void fprint_bstr(FILE *fp, const char *label, const unsigned char *data, unsigned long long length);

//int generate_test_vectors();

/*int main()
{
	int ret = generate_test_vectors();

	if (ret != KAT_SUCCESS) {
		fprintf(stderr, "test vector generation failed with code %d\n", ret);
	}

	return ret;
}

int generate_test_vectors()
{
	FILE                *fp;
	char                fileName[MAX_FILE_NAME];
	unsigned char       key[CRYPTO_KEYBYTES];
	unsigned char		nonce[CRYPTO_NPUBBYTES];
	unsigned char       msg[MAX_MESSAGE_LENGTH];
	unsigned char       msg2[MAX_MESSAGE_LENGTH];
	unsigned char		ad[MAX_ASSOCIATED_DATA_LENGTH];
	unsigned char		ct[MAX_MESSAGE_LENGTH + CRYPTO_ABYTES];
	unsigned long long  clen, mlen2;
	int                 count = 1;
	int                 func_ret, ret_val = KAT_SUCCESS;

	init_buffer(key, sizeof(key));
	init_buffer(nonce, sizeof(nonce));
	init_buffer(msg, sizeof(msg));
	init_buffer(ad, sizeof(ad));

	sprintf(fileName, "LWC_AEAD_KAT_%d_%d.txt", (CRYPTO_KEYBYTES * 8), (CRYPTO_NPUBBYTES * 8));

	if ((fp = fopen(fileName, "w")) == NULL) {
		fprintf(stderr, "Couldn't open <%s> for write\n", fileName);
		return KAT_FILE_OPEN_ERROR;
	}

	for (unsigned long long mlen = 0; (mlen <= MAX_MESSAGE_LENGTH) && (ret_val == KAT_SUCCESS); mlen++) {

		for (unsigned long long adlen = 0; adlen <= MAX_ASSOCIATED_DATA_LENGTH; adlen++) {

			fprintf(fp, "Count = %d\n", count++);

			fprint_bstr(fp, "Key = ", key, CRYPTO_KEYBYTES);

			fprint_bstr(fp, "Nonce = ", nonce, CRYPTO_NPUBBYTES);

			fprint_bstr(fp, "PT = ", msg, mlen);

			fprint_bstr(fp, "AD = ", ad, adlen);

			if ((func_ret = crypto_aead_encrypt(ct, &clen, msg, mlen, ad, adlen, NULL, nonce, key)) != 0) {
				fprintf(fp, "crypto_aead_encrypt returned <%d>\n", func_ret);
				ret_val = KAT_CRYPTO_FAILURE;
				break;
			}

			fprint_bstr(fp, "CT = ", ct, clen);

			fprintf(fp, "\n");

			if ((func_ret = crypto_aead_decrypt(msg2, &mlen2, NULL, ct, clen, ad, adlen, nonce, key)) != 0) {
				fprintf(fp, "crypto_aead_decrypt returned <%d>\n", func_ret);
				ret_val = KAT_CRYPTO_FAILURE;
				break;
			}

			if (mlen != mlen2) {
				fprintf(fp, "crypto_aead_decrypt returned bad 'mlen': Got <%llu>, expected <%llu>\n", mlen2, mlen);
				ret_val = KAT_CRYPTO_FAILURE;
				break;
			}

			if (memcmp(msg, msg2, mlen)) {
				fprintf(fp, "crypto_aead_decrypt did not recover the plaintext\n");
				ret_val = KAT_CRYPTO_FAILURE;
				break;
			}
		}
	}

	fclose(fp);

	return ret_val;
}


void fprint_bstr(FILE *fp, const char *label, const unsigned char *data, unsigned long long length)
{    
    fprintf(fp, "%s", label);
        
	for (unsigned long long i = 0; i < length; i++)
		fprintf(fp, "%02X", data[i]);
	    
    fprintf(fp, "\n");
}

void init_buffer(unsigned char *buffer, unsigned long long numbytes)
{
	for (unsigned long long i = 0; i < numbytes; i++)
		buffer[i] = (unsigned char)i;
}*/
