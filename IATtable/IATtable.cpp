// IATtable.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include "Header.h"

int main()
{	
	FunctionList fList ;
	MODULEINFO modInfo;
	HMODULE hMod = GetModuleHandle(0);
	//DWORD PID = GetCurrentProcessId();
	//HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, PID);
	//LPBYTE lpAddress1 = GetProcAddress
	GetModuleInformation(GetCurrentProcess(), hMod, &modInfo, sizeof(MODULEINFO));
	LPBYTE lpAddress = (LPBYTE)modInfo.lpBaseOfDll;
	printIATtable(lpAddress, &fList);
	//printDosHeader(pDosHeader);
	//printNTHeader(pDosHeader);
	//printDataDirectory(pDosHeader);
	//printSectionHeader(pDosHeader);
	display_list(&fList);
}
