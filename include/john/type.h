#ifndef __JOHN_TYPE_H__
#define __JOHN_TYPE_H__

#include <time.h>
#include <john/rsa_core.h>

#define JOHN_MAX_BUFFER_LENGTH 4096

typedef struct _tag_Data {
	int type;
	time_t installTime;
	unsigned char data[JOHN_MAX_BUFFER_LENGTH];
	int status;
} JOHN_DATA;

#endif /* __JOHN_TYPE_H__ */
