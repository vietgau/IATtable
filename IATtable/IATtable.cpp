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
	
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)lpAddress;
	//MessageBoxA(NULL, "fuck offf!!!", NULL, 0);
	char* funcName = (char*)"GetProcAddress";
	//printIATtable(lpAddress, &fList);
	RunFunction(funcName);
	//printDosHeader(pDosHeader);
	//printNTHeader(pDosHeader);
	//printDataDirectory(pDosHeader);
	//printSectionHeader(pDosHeader);
	//display_list(&fList);
}
