#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include "aes.h"

#define FILE_NAME "original.txt"
#define ENCODED_FILE_NAME "secured.txt.enc"

int main (int argc, char *argv[])
{
    aes256_context ctx;
	FILE *in_file;
	long fileSize;
	FILE *out_file;
    uint8_t key[32];
	uint8_t i;
	uint8_t fileBuf[16];
	uint8_t *tmpBuf;
	
	time_t start, end;
	float gap;

	in_file = fopen(FILE_NAME, "rb");
	out_file = fopen(ENCODED_FILE_NAME, "wb");
	if(in_file == NULL) exit(1);

	fseek(in_file, 0, SEEK_END);
	fileSize = ftell(in_file);
	rewind(in_file);
	
	// set a test key
	for (i = 0; i < sizeof(key);i++) key[i] = i;
	
	start = clock();

	while( fread(fileBuf, 1, sizeof(fileBuf), in_file) )
	{
		aes256_init(&ctx, key);
		aes256_encrypt_ecb(&ctx, fileBuf);
		
		fwrite(fileBuf, 1, sizeof(fileBuf), out_file);
		fileSize -= sizeof(fileBuf);

		if(0 < fileSize && fileSize < sizeof(fileBuf))
		{
			tmpBuf = (uint8_t *)malloc(sizeof(uint8_t)*fileSize);
			
			fread(tmpBuf, 1, fileSize, in_file);
			
			aes256_init(&ctx, key);
			aes256_encrypt_ecb(&ctx, tmpBuf);
			
			fwrite(tmpBuf, 1, fileSize, out_file);			
			break;
		}
	}
	
	aes256_done(&ctx);
	
	end = clock();
	gap = (float) (end - start)/CLOCKS_PER_SEC;
	printf("걸린시간 : %f초", gap);

	
	fclose(in_file);
	fclose(out_file);
    return 0;
}