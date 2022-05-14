#include "Header.h"
HANDLE WINAPI NewGetCurrentProcess(VOID) {
	printf("Viet da sua function \n");
	return GetCurrentProcess();
}

