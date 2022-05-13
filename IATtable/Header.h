#pragma once

#include <Windows.h>
#include <Psapi.h>
#include <vector>
#include<iostream>
using namespace std;
typedef struct function {
	char* name;
	LPVOID address;
}TY_Function;
typedef vector <TY_Function> FunctionList;

typedef FARPROC (WINAPI *NewGetProcAddress)(
    _In_ HMODULE hModule,
    _In_ LPCSTR lpProcName
);

typedef int (WINAPI *NewMessageBoxA)(
    _In_opt_ HWND hWnd,
    _In_opt_ LPCSTR lpText,
    _In_opt_ LPCSTR lpCaption,
    _In_ UINT uType);

VOID printDosHeader(IMAGE_DOS_HEADER* dosHeader);
VOID printNTHeader(IMAGE_DOS_HEADER* dosHeader);
VOID printNTSignature(IMAGE_DOS_HEADER* dosHeader);
VOID printFileHeader(IMAGE_DOS_HEADER* dosHeader);
VOID printOptionHeader(IMAGE_DOS_HEADER* dosHeader);
VOID printDataDirectory(IMAGE_DOS_HEADER* dosHeader);
VOID printSectionHeader(IMAGE_DOS_HEADER* dosHeader);
VOID printIATtable(LPBYTE lpAddress, FunctionList* fList);
void display_list(FunctionList* fList);
void print_info(TY_Function* f);
PSIZE_T FindFunctionAddress(char* funcName);
void RunFunction(char* funcName);