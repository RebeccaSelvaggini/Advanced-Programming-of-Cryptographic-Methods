#include <stdio.h>
#include <inttypes.h>
#include <stdlib.h>

//Costanti in AES128
#define BYTES_IN_WORD   4
#define WORDS_IN_KEY    4
#define NR_ROUNDS      10
#define BLOCK_SIZE     16

// Matrice inversa mix columns.
uint8_t InvMatrix[4][4]=   {{0x0e,0x0b,0x0d,0x09},
   			    {0x09,0x0e,0x0b,0x0d},
   			    {0x0d,0x09,0x0e,0x0b},
   			    {0x0b,0x0d,0x09,0x0e}};

uint8_t Key[WORDS_IN_KEY][BYTES_IN_WORD]= {{0x2b,0x7e,0x15,0x16},
   					   {0x28,0xae,0xd2,0xa6},
   				   	   {0xab,0xf7,0x15,0x88},
   					   {0x09,0xcf,0x4f,0x3c}};

uint8_t SBox[256] = {
  0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
  0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
  0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
  0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
  0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
  0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
  0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
  0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
  0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
  0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
  0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
  0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
  0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
  0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
  0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
  0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16 };
  
uint8_t InvSBox[256] = {
  0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
  0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
  0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
  0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
  0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
  0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
  0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
  0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
  0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
  0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
  0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
  0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
  0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
  0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
  0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
  0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d };
  
uint8_t RCon[] = {0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36};

//Padding
void padding(uint8_t buf[], int buflen, int numblocks, int inlength){	
	for (int i = inlength; i<numblocks*16 -1; i++) {
		buf[i] = 0;
	}
	buf[numblocks*16 -1] = 16-buflen;
};

uint8_t xtime(uint8_t x) { 
	return (x<<1)^((x>>7)*(0x1b)); 
};

// Moltiplicazione tra a e b
uint8_t multiplyF_256(uint8_t a, uint8_t b){	
	uint8_t app = 0;
	for (uint8_t i=0; i<=7; i++){
		app ^= ((b>>i)&1)*a;
		a = xtime(a);
	}
	return app;
};

void addRoundKey(uint8_t r, uint8_t state[4][4] , uint8_t roundKey[NR_ROUNDS+1][WORDS_IN_KEY][BYTES_IN_WORD]){
	uint8_t key[WORDS_IN_KEY][BYTES_IN_WORD];
	for (int i=0; i<WORDS_IN_KEY; i++){
		for (int j=0; j<BYTES_IN_WORD; j++){
			key[i][j] = roundKey[r][i][j];
		}	
	}
	for (int i=0; i<4; i++){
		for (int j=0; j<4; j++){
			state[i][j] = state[i][j]^key[j][i];
		}	
	}
};

void subBytes(uint8_t state[4][4]){
	for (int i=0; i<4; i++){
		for (int j=0; j<4; j++){
			state[i][j] = SBox[state[i][j]];
		}	
	}
};

void RotWord(uint8_t word[BYTES_IN_WORD]){
	uint8_t app = word[0];
	for (int i=0; i<=2; i++){
		word[i] = word[i+1];
	}
	word[3] = app;
};

void RotWord2(uint8_t word[4]){
	uint8_t app = word[3];
	for (int i=1; i<=3; i++){
		word[i] = word[i-1];
	}
	word[0] = app;
};

void mixColumns(uint8_t state[4][4]){
	uint8_t appoggio[4][4];
	for (int i=0; i<4; i++){
		for (int j=0; j<4; j++){
			appoggio[i][j] = state[i][j];
			state[i][j] = 0;
		}	
	}
	
	for (int i=0; i<4; i++){
		state[0][i] = xtime(appoggio[0][i])^xtime(appoggio[1][i])^(appoggio[1][i])^(appoggio[2][i])^(appoggio[3][i]);
		state[1][i] = (appoggio[0][i])^xtime(appoggio[1][i])^xtime(appoggio[2][i])^(appoggio[2][i])^(appoggio[3][i]);
		state[2][i] = (appoggio[0][i])^(appoggio[1][i])^xtime(appoggio[2][i])^xtime(appoggio[3][i])^(appoggio[3][i]);
		state[3][i] = xtime(appoggio[0][i])^(appoggio[0][i])^(appoggio[1][i])^(appoggio[2][i])^xtime(appoggio[3][i]);
	}	
};


void shiftRows(uint8_t state[4][4]){
	// Shifto la riga 2.
	uint8_t app = state[1][0];
	for (int i=0; i<3; i++){ state[1][i] = state[1][i+1]; }
	state[1][3] = app;
	// Shifto la riga 3.
	uint8_t app1 = state[2][0];
	uint8_t app2 = state[2][1];
	for (int i=0; i<2; i++){ state[2][i] = state[2][i+2]; }
	state[2][2] = app1;
	state[2][3] = app2;
	// Shifto la riga 4.
	app1 = state[3][0];
	app2 = state[3][1];
	uint8_t app3 = state[3][2];
	state[3][0] = state[3][3];
	state[3][1] = app1;
	state[3][2] = app2;
	state[3][3] = app3;
};



void roundKeyGen(uint8_t roundKey[NR_ROUNDS+1][WORDS_IN_KEY][BYTES_IN_WORD], uint8_t Key[WORDS_IN_KEY][BYTES_IN_WORD]){
	for (int i=0; i<4; i++){
		for (int j=0; j<4; j++){
			roundKey[0][i][j] = Key[i][j]; 		
		}
	}

	for (int i=1; i<=NR_ROUNDS; i++){
		uint8_t appoggio[BYTES_IN_WORD];
		for (int t=0; t<4; t++){
			appoggio[t] = roundKey[i-1][3][t];
		}
		// Ruoto.
		RotWord(appoggio);
		// Applico la SBox.
		for (int j=0; j<=3; j++){
			appoggio[j] = SBox[appoggio[j]];
		}
		// Sommo con la round constant.
		appoggio[0] = appoggio[0]^RCon[i];
		// Aggiorno la prima parola della nuova round key.
		for (int j=0; j<=3; j++){
			roundKey[i][0][j] = roundKey[i-1][0][j]^appoggio[j];
		}
		// Aggiorno le altre 3 parole della nuova round key.
		for (int j=1; j<=3; j++){
			for (int t=0; t<=3; t++){
				roundKey[i][j][t] = roundKey[i-1][j][t]^roundKey[i][j-1][t];			
			}
		}
	}
};


//Cripta il singolo blocco
void encryptAES(uint8_t buf[], uint8_t roundKey[NR_ROUNDS+1][WORDS_IN_KEY][BYTES_IN_WORD]){
	// Costruisco lo stato 4x4.
	uint8_t state[4][4];
	int t = 0; // Lo uso per scorrere in buf.
	for (int i=0; i<4; i++){
		for (int j=0; j<4; j++){
			state[j][i] = buf[t];
			t = t+1;
		}	
	}
	
	// Whitening.
	addRoundKey(0, state, roundKey);
	
	for (int i=1; i<=NR_ROUNDS-1; i++){
		
		subBytes(state);
		shiftRows(state);
		mixColumns(state);
		addRoundKey(i, state, roundKey);
		
	}

	subBytes(state);
	shiftRows(state);
	addRoundKey(10, state, roundKey);
	
	// Copio in buf il risultato.
	t = 0; // Lo uso per scorrere in buf.
	for (int i=0; i<4; i++){
		for (int j=0; j<4; j++){
			buf[t] = state[j][i];
			t = t+1;
		}	
	}
};



//Aggiunge vec (iv o ciphertext appena calcolato per il blocco precedente) a buf (successivo blocco plaintext) implementando il CBC.
void CBC(uint8_t buf[BLOCK_SIZE], uint8_t vec[BLOCK_SIZE]){
	for (int i=0; i<BLOCK_SIZE; i++){
		*(buf+i) ^= vec[i];
	}
};

// Cripta l'intero buffer in modalit?? CBC
void encryptCBC(uint8_t buf[], int inlength, uint8_t roundKey[NR_ROUNDS+1][WORDS_IN_KEY][BYTES_IN_WORD], uint8_t iv[BLOCK_SIZE], uint8_t ctx[], int lenctx){
	int numblocks = inlength/16 +1;
	int lenlastblock = inlength%16;
	uint8_t lastblock[16];
	
	for (int i=0; i<inlength; i++) ctx[i]=buf[i];
	if (lenlastblock == 0) { 
		for (int i=inlength; i<inlength+16; i++) { ctx[i] = 0; }
	}
	else { padding(ctx, lenlastblock, numblocks, inlength); }
	
	uint8_t bufnum[16];
	
	for (int i=0; i<numblocks; i++){
		for (int j=0; j<16; j++) { bufnum[j] = *(ctx +(i*16 + j)); }

		CBC(bufnum, iv);
		encryptAES(bufnum, roundKey);

		for (int j=0; j<16; j++) { iv[j] = bufnum[j]; }	// iv = bufnum;
		// Copio in buf il risultato.
		for (int j=0; j<16; j++) { *(ctx +(i*16 + j)) = bufnum[j]; }
	}
};


// DA QUI IN POI INIZIA LA DECRYPTION


// Inversa della funzione di shift delle righe
void invshiftRows(uint8_t state[4][4]){
	
   	uint8_t tmp[4][4] = {{state[1][3],state[1][0], state[1][1],state[1][2]},
                        	{state[2][2],state[2][3],state[2][0], state[2][1]},
                        	{state[3][1], state[3][2],state[3][3], state[3][0]}};
   	for (int i = 1; i<4; i++){
 		for (int j=0; j<4; j++){
     		state[i][j] = tmp[i-1][j];
        }
    }
};

// Inversa della funzione SBox
void invsubBytes(uint8_t state[4][4]){
	for (int i=0; i<4; i++){
		for (int j=0; j<4; j++){
			state[i][j] = InvSBox[state[i][j]];
		}	
	}
};


// Inversa della funzione mix columns
void invmixColumns(uint8_t state[4][4]){
    uint8_t tmp;
    uint8_t app[4][4];
    for (uint8_t i =0; i<4; i++){
	for (uint8_t j= 0; j<4; j++){
     		tmp = 0;
     		for (uint8_t k=0; k<4; k++){ tmp ^= multiplyF_256(InvMatrix[j][k], state[k][i]); }
                app[j][i] = tmp;
	}
    }
	for (uint8_t i =0; i<4; i++){
		for (uint8_t j= 0; j<4; j++){
			state[i][j] = app[i][j];
		}
	}
};


// Decrypt singolo blocco.
void decryptAES(uint8_t buf[], uint8_t roundKey[NR_ROUNDS+1][WORDS_IN_KEY][BYTES_IN_WORD]){
	// Costruisco lo stato 4x4.
	uint8_t state[4][4];
	int t = 0; // Lo uso per scorrere in buf.
	for (int i=0; i<4; i++){
		for (int j=0; j<4; j++){
			state[j][i] = buf[t];
			t = t+1;
		}	
	}

	addRoundKey(10, state, roundKey);

	for (int i=1; i<=NR_ROUNDS-1; i++){
		invshiftRows(state);
		invsubBytes(state);
		addRoundKey(10-i, state, roundKey);	
		invmixColumns(state);
	}
	invshiftRows(state);
	invsubBytes(state);
	addRoundKey(0, state, roundKey);
	// Copio in buf il risultato.
	t = 0; // Lo uso per scorrere in buf.
	for (int i=0; i<4; i++){
		for (int j=0; j<4; j++){
			buf[t] = state[j][i];
			t = t+1;
		}	
	}
};

// Decripta l'intero buffer in modalit?? CBC
void decryptCBC(uint8_t buf[], int inlength, uint8_t roundKey[NR_ROUNDS+1][WORDS_IN_KEY][BYTES_IN_WORD], uint8_t iv[BLOCK_SIZE], uint8_t* plaintext, int*pllen){
	int numblocks = inlength/16;
	uint8_t bufnum[16];
	uint8_t ctx[16];
	for (int i=0; i<numblocks; i++){
		for (int j=0; j<16; j++) {
			bufnum[j] = buf[i*16 + j]; 
			ctx[j]= buf[i*16 + j]; }
		 
		decryptAES(bufnum, roundKey);		
		CBC(bufnum, iv);
		for (int j=0; j<16; j++) { iv[j] = ctx[j]; }	// iv = bufnum;
		// Copio in buf il risultato.
		for (int j=0; j<16; j++) { buf[i*16 + j] = bufnum[j]; }
	}
	int n = buf[inlength-1];
	
	if (n==0) {n=16;}
	*pllen = inlength -n;
	
	for(int i=0; i<inlength -n; i++) plaintext[i] =buf[i];
};
