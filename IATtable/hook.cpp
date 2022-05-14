#include "Header.h"
PSIZE_T FindFunctionAddress(char* funcName) {

	MODULEINFO modInfo;
	HMODULE hMod = GetModuleHandle(0);
	GetModuleInformation(GetCurrentProcess(), hMod, &modInfo, sizeof(MODULEINFO));
	LPBYTE lpAddress = (LPBYTE)modInfo.lpBaseOfDll;
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)lpAddress;
	PIMAGE_NT_HEADERS pNTHeader = (PIMAGE_NT_HEADERS)(lpAddress + pDosHeader->e_lfanew);
	PIMAGE_OPTIONAL_HEADER pOptionHeader = (PIMAGE_OPTIONAL_HEADER) & (pNTHeader->OptionalHeader);
	PIMAGE_IMPORT_DESCRIPTOR pImportDir = PIMAGE_IMPORT_DESCRIPTOR(lpAddress + pOptionHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
	PIMAGE_THUNK_DATA	pOriginalFirstThunk = (PIMAGE_THUNK_DATA)(lpAddress + pImportDir->OriginalFirstThunk);
	PIMAGE_THUNK_DATA	pFirstThunk = (PIMAGE_THUNK_DATA)(lpAddress + pImportDir->FirstThunk);
	PSIZE_T				pFunction = nullptr;
	do {
		PIMAGE_IMPORT_BY_NAME pName = (PIMAGE_IMPORT_BY_NAME)(lpAddress + pOriginalFirstThunk->u1.AddressOfData);
		if (!strcmp(funcName, (char*)pName->Name)) {
			pFunction = (PSIZE_T) & (pFirstThunk->u1.Function);
			printf(" %s dia chi : 0x%p\n\n", (char*)pName->Name, (void*)(*pFunction));
			return pFunction;
		}
		pFirstThunk++;
		pOriginalFirstThunk++;

	} while (pOriginalFirstThunk->u1.AddressOfData);

	return 0;
}
void RunFunction(char* funcName)
{
	PSIZE_T pFunction = FindFunctionAddress(funcName);
	PSIZE_T pGPA;
	NewGetProcAddress GPA = (NewGetProcAddress)*pFunction;
	pGPA = (PSIZE_T)GPA(GetModuleHandle(TEXT("kernel32.dll")), "GetCurrentProcess");
	printf(" GetCurrentProcess: %p\n\n", pGPA);
}
void HookFunction(char* funcName, SIZE_T function)
{
	PSIZE_T pOldFunction = FindFunctionAddress(funcName);
	DWORD accessProtectionValue, accessProtec;

	int vProtect = VirtualProtect(pOldFunction, sizeof(PSIZE_T), PAGE_EXECUTE_READWRITE, &accessProtectionValue);
	*pOldFunction = function;
	vProtect = VirtualProtect(pOldFunction, sizeof(PSIZE_T), accessProtectionValue, &accessProtec);
}