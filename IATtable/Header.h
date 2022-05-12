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
VOID printDosHeader(IMAGE_DOS_HEADER* dosHeader);
VOID printNTHeader(IMAGE_DOS_HEADER* dosHeader);
VOID printNTSignature(IMAGE_DOS_HEADER* dosHeader);
VOID printFileHeader(IMAGE_DOS_HEADER* dosHeader);
VOID printOptionHeader(IMAGE_DOS_HEADER* dosHeader);
VOID printDataDirectory(IMAGE_DOS_HEADER* dosHeader);
VOID printSectionHeader(IMAGE_DOS_HEADER* dosHeader);
VOID printIATtable(LPBYTE lpAddress, IMAGE_DOS_HEADER* pDosHeader, FunctionList* fList);
