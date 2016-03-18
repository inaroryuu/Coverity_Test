#ifndef __JOHN_DB_READ_H__
#define __JOHN_DB_READ_H__

#include <stdio.h>
#include <errno.h>
#include <john/type.h>
#include <john/rsa_public_decrypt.h>

#define JohnGet(pp)\
({\
	int count = -1;\
	int rc = -1;\
	int i = 0;\
	int iKeyLen = 0;\
	unsigned int iEncKeyLen = 0;\
	unsigned int iDataLen = 0;\
	unsigned char keyEncrypted[JOHN_SHARED_RSA_KEY_BUFFER_SIZE] = {'\0'};\
	unsigned char keyData[JOHN_SPECIFIC_RSA_KEY_BUFFER_SIZE] = {'\0'};\
	unsigned char dataEncrypted[JOHN_MAX_BUFFER_LENGTH] = {'\0'};\
\
	*pp = (JOHN_DATA*) malloc(sizeof(JOHN_DATA) * 10);\
	iKeyLen = JohnRSAPublicDecrypt(keyEncrypted, iEncKeyLen, keyData, sizeof(keyData));\
	if (0 < iKeyLen) {\
		JohnRSAPublicDecryptWithKey(dataEncrypted, iDataLen, *pp[i].data, sizeof(*pp[i].data), keyData, (unsigned int)iKeyLen, 0);\
		i++;\
	 }\
	count;\
})

#endif /* __JOHN_DB_READ_H__ */
