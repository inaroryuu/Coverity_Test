#include <stdlib.h>
#include <john/db_read.h>

int main()
{
	int iRet = 0;
	JOHN_DATA *pData = NULL;

	iRet = JohnGet(&pData);

	if (NULL != pData) {
		free(pData);
	}
	return 0;
}
