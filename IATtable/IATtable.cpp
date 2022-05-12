// IATtable.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include "Header.h"

int main()
{	
	FunctionList fList ;
	MODULEINFO modInfo;
	HMODULE hMod = GetModuleHandle(0);

	GetModuleInformation(GetCurrentProcess(), hMod, &modInfo, sizeof(MODULEINFO));
	LPBYTE lpAddress = (LPBYTE)modInfo.lpBaseOfDll;
	printf("Base virtual address(DOS_HEADER) of Process :%p\n", (void*)lpAddress);
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)lpAddress;
	printIATtable(lpAddress, pDosHeader, &fList);
	printDosHeader(pDosHeader);
	printNTHeader(pDosHeader);
	printDataDirectory(pDosHeader);
	printSectionHeader(pDosHeader);
}
