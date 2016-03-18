#ifndef __JOHN_ENCRYPT_H__
#define __JOHN_ENCRYPT_H__

#include <stdlib.h>
#include <string.h>

#define john_encrypt_string(szString_john_encrypt_string, iStrLen_john_encrypt_string, encrypted_john_encrypt_string, iEncLen_john_encrypt_string)\
({\
	size_t lenIndex_john_encrypt_string = 0;\
	unsigned char xor_key_john_encrypt_string = 0;\
	if (0 < iStrLen_john_encrypt_string && iStrLen_john_encrypt_string <= iEncLen_john_encrypt_string) {\
		xor_key_john_encrypt_string = (unsigned char)iStrLen_john_encrypt_string;\
		memset(encrypted_john_encrypt_string, 0, iEncLen_john_encrypt_string);\
\
		for (lenIndex_john_encrypt_string = 0; lenIndex_john_encrypt_string < (size_t)iStrLen_john_encrypt_string; lenIndex_john_encrypt_string++) {\
			encrypted_john_encrypt_string[lenIndex_john_encrypt_string] = szString_john_encrypt_string[lenIndex_john_encrypt_string] ^ xor_key_john_encrypt_string;\
			xor_key_john_encrypt_string = encrypted_john_encrypt_string[lenIndex_john_encrypt_string];\
		}\
	}\
})

#define john_decrypt_string(encrypted_john_decrypt_string, iEncLen_john_decrypt_string, szString_john_decrypt_string, iStrLen_john_decrypt_string)\
({\
	size_t lenIndex_john_decrypt_string = 0;\
	unsigned char xor_key_john_decrypt_string = 0;\
	if (0 < iEncLen_john_decrypt_string && iEncLen_john_decrypt_string <= iStrLen_john_decrypt_string) {\
		xor_key_john_decrypt_string = (unsigned char)iEncLen_john_decrypt_string;\
		memset(szString_john_decrypt_string, 0, iStrLen_john_decrypt_string);\
\
		for (lenIndex_john_decrypt_string = 0; lenIndex_john_decrypt_string < (size_t)iEncLen_john_decrypt_string; lenIndex_john_decrypt_string++) {\
			szString_john_decrypt_string[lenIndex_john_decrypt_string] = encrypted_john_decrypt_string[lenIndex_john_decrypt_string] ^ xor_key_john_decrypt_string;\
			xor_key_john_decrypt_string = encrypted_john_decrypt_string[lenIndex_john_decrypt_string];\
		}\
	}\
})

#define john_shift_encrypt_string(szString_john_shift_encrypt_string, iStrLen_john_shift_encrypt_string, encrypted_john_shift_encrypt_string, iEncLen_john_shift_encrypt_string)\
({\
	size_t lenIndex_john_shift_encrypt_string = 0;\
	unsigned char shift_key_john_shift_encrypt_string = 0;\
	if (0 < iStrLen_john_shift_encrypt_string && iStrLen_john_shift_encrypt_string <= iEncLen_john_shift_encrypt_string) {\
		shift_key_john_shift_encrypt_string = (unsigned char)iStrLen_john_shift_encrypt_string % 256;\
		memset(encrypted_john_shift_encrypt_string, 0, iEncLen_john_shift_encrypt_string);\
\
		for (lenIndex_john_shift_encrypt_string = 0; lenIndex_john_shift_encrypt_string < (size_t)iStrLen_john_shift_encrypt_string; lenIndex_john_shift_encrypt_string++) {\
			if (szString_john_shift_encrypt_string[lenIndex_john_shift_encrypt_string] > 256 - shift_key_john_shift_encrypt_string) {\
				encrypted_john_shift_encrypt_string[lenIndex_john_shift_encrypt_string] = szString_john_shift_encrypt_string[lenIndex_john_shift_encrypt_string] + (shift_key_john_shift_encrypt_string - 256);\
			} else {\
				encrypted_john_shift_encrypt_string[lenIndex_john_shift_encrypt_string] = szString_john_shift_encrypt_string[lenIndex_john_shift_encrypt_string] + shift_key_john_shift_encrypt_string;\
			}\
		}\
	}\
})

#define john_shift_decrypt_string(encrypted_john_shift_decrypt_string, iEncLen_john_shift_decrypt_string, szString_john_shift_decrypt_string, iStrLen_john_shift_decrypt_string)\
({\
	size_t lenIndex_john_shift_decrypt_string = 0;\
	unsigned char shift_key_john_shift_decrypt_string = 0;\
	if (0 < iEncLen_john_shift_decrypt_string && iEncLen_john_shift_decrypt_string <= iStrLen_john_shift_decrypt_string) {\
		shift_key_john_shift_decrypt_string = (unsigned char)iEncLen_john_shift_decrypt_string % 256;\
		memset(szString_john_shift_decrypt_string, 0, iStrLen_john_shift_decrypt_string);\
\
		for (lenIndex_john_shift_decrypt_string = 0; lenIndex_john_shift_decrypt_string < (size_t)iEncLen_john_shift_decrypt_string; lenIndex_john_shift_decrypt_string++) {\
			if (szString_john_shift_decrypt_string[lenIndex_john_shift_decrypt_string] < shift_key_john_shift_decrypt_string) {\
				szString_john_shift_decrypt_string[lenIndex_john_shift_decrypt_string] = encrypted_john_shift_decrypt_string[lenIndex_john_shift_decrypt_string] + (256 - shift_key_john_shift_decrypt_string);\
			} else {\
				szString_john_shift_decrypt_string[lenIndex_john_shift_decrypt_string] = encrypted_john_shift_decrypt_string[lenIndex_john_shift_decrypt_string] - shift_key_john_shift_decrypt_string;\
			}\
		}\
	}\
})

#define john_xor_encrypt_string(szString_john_xor_encrypt_string, iStrLen_john_xor_encrypt_string, encrypted_john_xor_encrypt_string, iEncLen_john_xor_encrypt_string)\
({\
	size_t lenIndex_john_xor_encrypt_string = 0;\
	unsigned char xor_key_john_xor_encrypt_string = 0;\
	if (0 < iStrLen_john_xor_encrypt_string && iStrLen_john_xor_encrypt_string <= iEncLen_john_xor_encrypt_string) {\
		xor_key_john_xor_encrypt_string = (unsigned char)iStrLen_john_xor_encrypt_string;\
		memset(encrypted_john_xor_encrypt_string, 0, iEncLen_john_xor_encrypt_string);\
\
		for (lenIndex_john_xor_encrypt_string = 0; lenIndex_john_xor_encrypt_string < (size_t)iStrLen_john_xor_encrypt_string; lenIndex_john_xor_encrypt_string++) {\
			encrypted_john_xor_encrypt_string[lenIndex_john_xor_encrypt_string] = szString_john_xor_encrypt_string[lenIndex_john_xor_encrypt_string] ^ xor_key_john_xor_encrypt_string;\
		}\
	}\
})

#define john_xor_decrypt_string(encrypted_john_xor_decrypt_string, iEncLen_john_xor_decrypt_string, szString_john_xor_decrypt_string, iStrLen_john_xor_decrypt_string)\
({\
	size_t lenIndex_john_xor_decrypt_string = 0;\
	unsigned char xor_key_john_xor_decrypt_string = 0;\
	if (0 < iEncLen_john_xor_decrypt_string && iEncLen_john_xor_decrypt_string <= iStrLen_john_xor_decrypt_string) {\
		xor_key_john_xor_decrypt_string = (unsigned char)iEncLen_john_xor_decrypt_string;\
		memset(szString_john_xor_decrypt_string, 0, iStrLen_john_xor_decrypt_string);\
\
		for (lenIndex_john_xor_decrypt_string = 0; lenIndex_john_xor_decrypt_string < (size_t)iEncLen_john_xor_decrypt_string; lenIndex_john_xor_decrypt_string++) {\
			szString_john_xor_decrypt_string[lenIndex_john_xor_decrypt_string] = encrypted_john_xor_decrypt_string[lenIndex_john_xor_decrypt_string] ^ xor_key_john_xor_decrypt_string;\
		}\
	}\
})

#endif /* __JOHN_ENCRYPT_H__ */
