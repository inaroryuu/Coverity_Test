#ifndef __JOHN_RSA_PUBLIC_DECRYPT_H__
#define __JOHN_RSA_PUBLIC_DECRYPT_H__

#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <john/rsa_core.h>
#include <john/rsa_public_key.h>
#include <john/john_encrypt.h>

#define JohnRSAPublicDecryptWithKey(encrypted_JohnRSAPublicDecryptWithKey, iEncLen_JohnRSAPublicDecryptWithKey, data_JohnRSAPublicDecryptWithKey, iDataLen_JohnRSAPublicDecryptWithKey, keyEncrypted_JohnRSAPublicDecryptWithKey, iKeyLen_JohnRSAPublicDecryptWithKey, blShared_JohnRSAPublicDecryptWithKey)\
({\
	int iRet_JohnRSAPublicDecryptWithKey = -1;\
	int iRsaSize_JohnRSAPublicDecryptWithKey = 0;\
	unsigned int iDecCount_JohnRSAPublicDecryptWithKey = 0;\
	BIO *bio_JohnRSAPublicDecryptWithKey = NULL;\
	RSA *publicKey_JohnRSAPublicDecryptWithKey = NULL;\
	unsigned char szKeyData_JohnRSAPublicDecryptWithKey[JOHN_SHARED_RSA_KEY_BUFFER_SIZE] = {'\0'};\
\
	john_decrypt_string(keyEncrypted_JohnRSAPublicDecryptWithKey, iKeyLen_JohnRSAPublicDecryptWithKey, szKeyData_JohnRSAPublicDecryptWithKey, sizeof(szKeyData_JohnRSAPublicDecryptWithKey));\
\
	if (blShared_JohnRSAPublicDecryptWithKey) {\
		iRsaSize_JohnRSAPublicDecryptWithKey = JOHN_SHARED_RSA_KEY_SIZE;\
	} else {\
		iRsaSize_JohnRSAPublicDecryptWithKey = JOHN_SPECIFIC_RSA_KEY_SIZE;\
	}\
\
	bio_JohnRSAPublicDecryptWithKey = BIO_new_mem_buf((void *)szKeyData_JohnRSAPublicDecryptWithKey, iKeyLen_JohnRSAPublicDecryptWithKey);\
	if (NULL == bio_JohnRSAPublicDecryptWithKey) {\
	} else {\
		publicKey_JohnRSAPublicDecryptWithKey = PEM_read_bio_RSA_PUBKEY(bio_JohnRSAPublicDecryptWithKey, NULL, NULL, NULL);\
		BIO_free(bio_JohnRSAPublicDecryptWithKey);\
\
		if (NULL == publicKey_JohnRSAPublicDecryptWithKey) {\
		} else {\
			memset(data_JohnRSAPublicDecryptWithKey, 0, iDataLen_JohnRSAPublicDecryptWithKey);\
			iRet_JohnRSAPublicDecryptWithKey = 0;\
			iDecCount_JohnRSAPublicDecryptWithKey = 0;\
			while (iDecCount_JohnRSAPublicDecryptWithKey < (unsigned int)iEncLen_JohnRSAPublicDecryptWithKey &&\
					(unsigned int)iRet_JohnRSAPublicDecryptWithKey < iDataLen_JohnRSAPublicDecryptWithKey) {\
				iRet_JohnRSAPublicDecryptWithKey += RSA_public_decrypt(iRsaSize_JohnRSAPublicDecryptWithKey, encrypted_JohnRSAPublicDecryptWithKey + iDecCount_JohnRSAPublicDecryptWithKey, data_JohnRSAPublicDecryptWithKey + iRet_JohnRSAPublicDecryptWithKey, publicKey_JohnRSAPublicDecryptWithKey, RSA_PKCS1_PADDING);\
				iDecCount_JohnRSAPublicDecryptWithKey += iRsaSize_JohnRSAPublicDecryptWithKey;\
			}\
			RSA_free(publicKey_JohnRSAPublicDecryptWithKey);\
		}\
	}\
\
	iRet_JohnRSAPublicDecryptWithKey;\
})

#define JohnRSAPublicDecrypt(encrypted_JohnRSAPublicDecrypt, iEncLen_JohnRSAPublicDecrypt, data_JohnRSAPublicDecrypt, iDataLen_JohnRSAPublicDecrypt)\
({\
	int iRet_JohnRSAPublicDecrypt = -1;\
	size_t iKeyLen_JohnRSAPublicDecrypt = 0;\
	unsigned char publicKeyEncrypted_JohnRSAPublicDecrypt[] = JOHN_RSA_PUBLIC_KEY_ENCRYPTED;\
\
	iKeyLen_JohnRSAPublicDecrypt = sizeof(publicKeyEncrypted_JohnRSAPublicDecrypt) / sizeof(unsigned char);\
\
	iRet_JohnRSAPublicDecrypt = JohnRSAPublicDecryptWithKey(encrypted_JohnRSAPublicDecrypt, iEncLen_JohnRSAPublicDecrypt, data_JohnRSAPublicDecrypt, iDataLen_JohnRSAPublicDecrypt, publicKeyEncrypted_JohnRSAPublicDecrypt, iKeyLen_JohnRSAPublicDecrypt, 1);\
\
	iRet_JohnRSAPublicDecrypt;\
})

#endif /* __JOHN_RSA_PUBLIC_DECRYPT_H__ */
