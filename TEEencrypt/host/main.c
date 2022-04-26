/*
 * Copyright (c) 2016, Linaro Limited
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
#include <err.h>
#include <stdio.h>
#include <string.h>

/* OP-TEE TEE client API (built by optee_client) */
#include <tee_client_api.h>

/* To the the UUID (found the the TA's h-file(s)) */
#include <TEEencrypt_ta.h>

int main(int argc, char* argv[])
{
	TEEC_Result res;
	TEEC_Context ctx;
	TEEC_Session sess;
	TEEC_Operation op;
	TEEC_UUID uuid = TA_TEEencrypt_UUID;
	uint32_t err_origin;
	
	char plaintxt[64] = {0, };
	char ciphertxt[64] = {0, };
	char enckey[1] = {0};
	FILE *fp;
	int len = 64;
	// Context Initialize
	res = TEEC_InitializeContext(NULL, &ctx);
	if(res != TEEC_SUCCESS)
		errx(1, "TEEC_InitializeContext failed with code 0x%x", res);
	// Session Open
	res = TEEC_OpenSession(&ctx, &sess, &uuid,
			       TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
	if(res != TEEC_SUCCESS)
		errx(1, "TEEC_OpenSession failed with code 0x%x origin 0x%x", res, err_origin);
	
	memset(&op, 0, sizeof(op));

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE,
					 TEEC_NONE, TEEC_NONE);
	op.params[0].tmpref.buffer = plaintxt;
	op.params[0].tmpref.size = sizeof(plaintxt);

	// Encryption
	if(strcmp(argv[1], "-e") == 0) {
		printf("========================Encryption========================\n");

		// Read plain text
		char path[100] = "/root/";
		strcat(path, argv[2]);
		fp = fopen(path, "r");
		fread(plaintxt, 1, sizeof(plaintxt), fp);
		fclose(fp);
		printf("Plain text : %s\n", plaintxt);

		// Random key get
		memcpy(op.params[0].tmpref.buffer, plaintxt, len);
		res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_RANDOMKEY_GET, &op, &err_origin);
		if(res != TEEC_SUCCESS) {
			printf("Random Key Error\n");
			return -1;
		}

		// Encrypt plain text -> get cipher text
		memcpy(op.params[0].tmpref.buffer, plaintxt, len);
		res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_ENC_VALUE, &op, &err_origin);
		if(res != TEEC_SUCCESS) {
			printf("Encrypt Error\n");
			return -1;
		}
		memcpy(ciphertxt, op.params[0].tmpref.buffer, len);
		printf("Cipher text : %s\n", ciphertxt);

		// save cipher text
		char cipherpath[100] = "/root/ciphertext";
		fp = fopen(cipherpath, "w");
		fwrite(ciphertxt, strlen(ciphertxt), 1, fp);
		fclose(fp);

		// Encrypt random key -> Encrypt key
		memcpy(op.params[0].tmpref.buffer, enckey, 1);
		res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_RANDOMKEY_ENC, &op, &err_origin);
		if(res != TEEC_SUCCESS) {
			printf("Encrypt Random Key Error\n");
			return -1;
		}
		memcpy(enckey, op.params[0].tmpref.buffer, 1);
		printf("Encrypt Key : %s\n", enckey);

		// Save encrypt key
		char keypath[100] = "/root/encryptedkey";
		fp = fopen(keypath, "w");
		fprintf(fp, "%c", enckey[0]);
		fclose(fp);

	// Decryption
	} else if(strcmp(argv[1], "-d") == 0) {
		printf("========================decryption========================\n");

		// Read Encrypt key
		char enckey_path[100] = "/root/";
		strcat(enckey_path, argv[3]);
		fp = fopen(enckey_path, "r");
		fread(enckey, 1, sizeof(enckey), fp);
		fclose(fp);
		printf("Encrypted Key : %s\n", enckey);

		// Decryption encrypt key
		memcpy(op.params[0].tmpref.buffer, enckey, 1);
		res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_RANDOMKEY_DEC, &op, &err_origin);
		if(res != TEEC_SUCCESS) {
			printf("Decrypt Random Key Error\n");
			return -1;
		}

		// Read cipher text
		char cipher_path[100] = "/root/";
		strcat(cipher_path, argv[2]);
		fp = fopen(cipher_path, "r");
		fread(ciphertxt, 1, sizeof(ciphertxt), fp);
		fclose(fp);
		printf("Cipher text : %s\n", ciphertxt);
				
		// Decryption cipher text
		memcpy(op.params[0].tmpref.buffer, ciphertxt, len);
		res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_DEC_VALUE, &op, &err_origin);
		if(res != TEEC_SUCCESS) {
			printf("Decrypt Error");
			return -1;
		}
		
		// Save plain text
		memcpy(plaintxt, op.params[0].tmpref.buffer, len);
		printf("Plain text : %s\n", plaintxt);
		fp = fopen("/root/plaintext", "w");
		fwrite(plaintxt, strlen(plaintxt), 1, fp);
		fclose(fp);

	// Not encrypt or decrypt
	} else {
		printf("Error\n");
	}
	TEEC_CloseSession(&sess);

	TEEC_FinalizeContext(&ctx);

	return 0;
}

