#include "Header.h"

VOID printDosHeader(IMAGE_DOS_HEADER* dosHeader) {
	DWORD offset = 0;
	printf("\nDOS_HEADER\n");
	printf("e_magic | offset: %4X | valua: %4X \n", offset, dosHeader->e_magic);
	offset = (sizeof(IMAGE_DOS_HEADER) - sizeof(dosHeader->e_lfanew));
	printf("e_lfanew| offset: %4X | valua: %4X \n", offset, dosHeader->e_lfanew);
}
VOID printNTHeader(IMAGE_DOS_HEADER* dosHeader) {
	printf("\nNT_HEADER\n");
	printNTSignature(dosHeader);
	printFileHeader(dosHeader);
	printOptionHeader(dosHeader);
}
VOID printNTSignature(IMAGE_DOS_HEADER* dosHeader) {
	int offset;
	PIMAGE_NT_HEADERS ntHeader;
	ntHeader = (PIMAGE_NT_HEADERS64)((DWORD64)(dosHeader)+(dosHeader->e_lfanew));
	offset = dosHeader->e_lfanew;
	printf("\nNT_Signature\n");
	printf("Signature | offset: %4X | valua: %4X \n", offset, ntHeader->Signature);
}
VOID printFileHeader(IMAGE_DOS_HEADER* dosHeader) {
	DWORD offset;
	IMAGE_FILE_HEADER fileHeader;
	PIMAGE_NT_HEADERS ntHeader;
	ntHeader = (PIMAGE_NT_HEADERS64)((DWORD64)(dosHeader)+(dosHeader->e_lfanew));
	fileHeader = ntHeader->FileHeader;
	printf("\nFile_Header\n");
	offset = dosHeader->e_lfanew + sizeof(ntHeader->Signature);
	printf("File header Machine | ofset: %4X | valua: %4X \n", offset, fileHeader.Machine);
	offset += sizeof(fileHeader.Machine);
	printf("File header NumberOfSections | offset: %4X | valua: %4X \n", offset, fileHeader.NumberOfSections);
	offset += sizeof(fileHeader.NumberOfSections);
	printf("File header TimeDateStamp | offset: %4X | valua: %4X \n", offset, fileHeader.TimeDateStamp);
	offset += sizeof(fileHeader.TimeDateStamp);
	printf("File header PointerToSymbolTable | offset: %4X | valua: %4X \n", offset, fileHeader.PointerToSymbolTable);
	offset += sizeof(fileHeader.PointerToSymbolTable);
	printf("File header NumberOfSymbols | offset: %4X | valua: %4X \n", offset, fileHeader.NumberOfSymbols);
	offset += sizeof(fileHeader.NumberOfSymbols);
	printf("File header SizeOfOptionalHeader | offset: %4X | valua: %4X \n", offset, fileHeader.SizeOfOptionalHeader);
	offset += sizeof(fileHeader.SizeOfOptionalHeader);
	printf("File header Characteristics | offset: %4X | valua: %4X \n", offset, fileHeader.Characteristics);


}
VOID printOptionHeader(IMAGE_DOS_HEADER* dosHeader) {
	DWORD offset;
	IMAGE_OPTIONAL_HEADER optionHeader;
	PIMAGE_NT_HEADERS ntHeader;
	ntHeader = (PIMAGE_NT_HEADERS64)((DWORD64)(dosHeader)+(dosHeader->e_lfanew));
	optionHeader = ntHeader->OptionalHeader;
	printf("\nOption_Header\n");
	offset = dosHeader->e_lfanew + sizeof(IMAGE_NT_SIGNATURE) + sizeof(IMAGE_FILE_HEADER);
	printf("Magic | offset: %4X | valua: %4X \n", offset, optionHeader.Magic);
	offset += sizeof(optionHeader.Magic);
	printf("MajorLinkerVersion | offset: %4X | valua: %4X \n", offset, optionHeader.MajorLinkerVersion);
	offset += sizeof(optionHeader.MajorLinkerVersion);
	printf("MinorLinkerVersion | offset: %4X | valua: %4X \n", offset, optionHeader.MinorLinkerVersion);
	offset += sizeof(optionHeader.MinorLinkerVersion);
	printf("SizeOfCode | offset: %4X | valua: %4X \n", offset, optionHeader.SizeOfCode);
	offset += sizeof(optionHeader.SizeOfCode);
	printf("SizeOfInitializedData | offset: %4X | valua: %4X \n", offset, optionHeader.SizeOfInitializedData);
	offset += sizeof(optionHeader.SizeOfInitializedData);
	printf("SizeOfUninitializedData | offset: %4X | valua: %4X \n", offset, optionHeader.SizeOfUninitializedData);
	offset += sizeof(optionHeader.SizeOfUninitializedData);
	printf("AddressOfEntryPoint | offset: %4X | valua: %4X \n", offset, optionHeader.AddressOfEntryPoint);
	offset += sizeof(optionHeader.AddressOfEntryPoint);
	printf("BaseOfCode | ofset: %4X | valua: %4X \n", offset, optionHeader.BaseOfCode);
	offset += sizeof(optionHeader.BaseOfCode);
	printf("ImageBase | offset: %4X | valua: %4X \n", offset, optionHeader.ImageBase);
	offset += sizeof(optionHeader.ImageBase);
	printf("SectionAlignment | offset: %4X | valua: %4X \n", offset, optionHeader.SectionAlignment);
	offset += sizeof(optionHeader.SectionAlignment);
	printf("FileAlignment | offset: %4X | valua: %4X \n", offset, optionHeader.FileAlignment);
	offset += sizeof(optionHeader.FileAlignment);
	printf("MajorOperatingSystemVersion | offset: %4X | valua: %4X \n", offset, optionHeader.MajorOperatingSystemVersion);
	offset += sizeof(optionHeader.MajorOperatingSystemVersion);
	printf("MinorOperatingSystemVersion | offset: %4X | valua: %4X \n", offset, optionHeader.MinorOperatingSystemVersion);
	offset += sizeof(optionHeader.MinorOperatingSystemVersion);
	printf("MajorImageVersion | offset: %4X | valua: %4X \n", offset, optionHeader.MajorImageVersion);
	offset += sizeof(optionHeader.MajorImageVersion);
	printf("MinorImageVersion | offset: %4X | valua: %4X \n", offset, optionHeader.MinorImageVersion);
	offset += sizeof(optionHeader.MinorImageVersion);
	printf("MajorSubsystemVersion | offset: %4X | valua: %4X \n", offset, optionHeader.MajorSubsystemVersion);
	offset += sizeof(optionHeader.MajorSubsystemVersion);
	printf("MinorSubsystemVersion | offset: %4X | valua: %4X \n", offset, optionHeader.MinorSubsystemVersion);
	offset += sizeof(optionHeader.MinorSubsystemVersion);
	printf("Win32VersionValue | offset: %4X | valua: %4X \n", offset, optionHeader.Win32VersionValue);
	offset += sizeof(optionHeader.Win32VersionValue);
	printf("SizeOfImage | offset: %4X | valua: %4X \n", offset, optionHeader.SizeOfImage);
	offset += sizeof(optionHeader.SizeOfImage);
	printf("SizeOfHeaders | offset: %4X | valua: %4X \n", offset, optionHeader.SizeOfHeaders);
	offset += sizeof(optionHeader.SizeOfHeaders);
	printf("CheckSum | offset: %4X | valua: %4X \n", offset, optionHeader.CheckSum);
	offset += sizeof(optionHeader.CheckSum);
	printf("Subsystem | offset: %4X | valua: %4X \n", offset, optionHeader.Subsystem);
	offset += sizeof(optionHeader.Subsystem);
	printf("DllCharacteristics | offset: %4X | valua: %4X \n", offset, optionHeader.DllCharacteristics);
	offset += sizeof(optionHeader.DllCharacteristics);
	printf("SizeOfStackReserve | offset: %4X | valua: %4X \n", offset, optionHeader.SizeOfStackReserve);
	offset += sizeof(optionHeader.SizeOfStackReserve);
	printf("SizeOfStackCommit | offset: %4X | valua: %4X \n", offset, optionHeader.SizeOfStackCommit);
	offset += sizeof(optionHeader.SizeOfStackCommit);
	printf("SizeOfHeapReserve | offset: %4X | valua: %4X \n", offset, optionHeader.SizeOfHeapReserve);
	offset += sizeof(optionHeader.SizeOfHeapReserve);
	printf("SizeOfHeapCommit | offset: %4X | valua: %4X \n", offset, optionHeader.SizeOfHeapCommit);
	offset += sizeof(optionHeader.SizeOfHeapCommit);
	printf("LoaderFlags | offset: %4X | valua: %4X \n", offset, optionHeader.LoaderFlags);
	offset += sizeof(optionHeader.LoaderFlags);
	printf("NumberOfRvaAndSizes | offset: %4X | valua: %4X \n", offset, optionHeader.NumberOfRvaAndSizes);
	offset += sizeof(optionHeader.NumberOfRvaAndSizes);

	//printf("DataDirectory | offset: %4X | valua: %4X \n", offset, optionHeader.DataDirectory);
	//offset += sizeof(optionHeader.DataDirectory);

}
VOID printDataDirectory(IMAGE_DOS_HEADER* dosHeader) {
	DWORD offset;
	PIMAGE_NT_HEADERS ntHeader;
	PIMAGE_DATA_DIRECTORY dataDir;
	ntHeader = (PIMAGE_NT_HEADERS64)((DWORD64)(dosHeader)+(dosHeader->e_lfanew));
	dataDir = ntHeader->OptionalHeader.DataDirectory;
	printf("\nDataDirectory\n");
	offset = dosHeader->e_lfanew + sizeof(IMAGE_NT_SIGNATURE) + sizeof(IMAGE_FILE_HEADER) + (ntHeader->FileHeader.SizeOfOptionalHeader - sizeof(IMAGE_DATA_DIRECTORY) * 16);
	for (int i = 0; i < 16; i++)
	{
		printf("VirtualAddress [%d] | offset: %4X | valua: %4X \n", i, offset, dataDir[i].VirtualAddress);
		offset += sizeof(dataDir[i].VirtualAddress);
		printf("Size [%d] | offset: %4X | valua: %4X \n", i, offset, dataDir[i].Size);
		offset += sizeof(dataDir[i].Size);
		printf("\n");
	}
}
VOID printSectionHeader(IMAGE_DOS_HEADER* dosHeader) {
	DWORD offset, numberOfSection;
	IMAGE_FILE_HEADER fileHeader;
	PIMAGE_SECTION_HEADER sectionHeader;
	PIMAGE_NT_HEADERS ntHeader;

	ntHeader = (PIMAGE_NT_HEADERS64)((DWORD64)(dosHeader)+(dosHeader->e_lfanew));
	sectionHeader = (PIMAGE_SECTION_HEADER)((DWORD64)ntHeader + sizeof(IMAGE_NT_HEADERS));
	fileHeader = ntHeader->FileHeader;
	numberOfSection = fileHeader.NumberOfSections;
	offset = dosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS);
	printf("\nSectionHeader\n ");
	for (int i = 0; i < numberOfSection; i++) {
		printf(" Name of section : %4X\n ", sectionHeader[i].Name);
		offset += sizeof(sectionHeader[i].Name);
		printf("VirtualSize[%d] | offset: %4X | valua: %4X \n ", i, offset, sectionHeader[i].Misc.VirtualSize);
		offset += sizeof(sectionHeader[i].Misc.VirtualSize);
		printf("VirtualAddress[%d] | offset: %4X | valua: %4X \n ", i, offset, sectionHeader[i].VirtualAddress);
		offset += sizeof(sectionHeader[i].VirtualAddress);
		printf("SizeOfRawData[%d] | offset: %4X | valua: %4X \n ", i, offset, sectionHeader[i].SizeOfRawData);
		offset += sizeof(sectionHeader[i].SizeOfRawData);
		printf("PointerToRawData[%d] | offset: %4X | valua: %4X \n ", i, offset, sectionHeader[i].PointerToRawData);
		offset += sizeof(sectionHeader[i].PointerToRawData);
		printf("PointerToRelocations[%d] | offset: %4X | valua: %4X \n ", i, offset, sectionHeader[i].PointerToRelocations);
		offset += sizeof(sectionHeader[i].PointerToRelocations);
		printf("PointerToLinenumbers[%d] | offset: %4X | valua: %4X \n ", i, offset, sectionHeader[i].PointerToLinenumbers);
		offset += sizeof(sectionHeader[i].PointerToLinenumbers);
		printf("NumberOfRelocations[%d] | offset: %4X | valua: %4X \n ", i, offset, sectionHeader[i].NumberOfRelocations);
		offset += sizeof(sectionHeader[i].NumberOfRelocations);
		printf("NumberOfLinenumbers[%d] | offset: %4X | valua: %4X \n ", i, offset, sectionHeader[i].NumberOfLinenumbers);
		offset += sizeof(sectionHeader[i].NumberOfLinenumbers);
		printf("Characteristics[%d] | offset: %4X | valua: %4X \n ", i, offset, sectionHeader[i].Characteristics);
		offset += sizeof(sectionHeader[i].Characteristics);
		printf("\n");

	}

}
VOID printIATtable(LPBYTE lpAddress ,  FunctionList* fList) {
	char* funcName = (char*)"GetProcAddress";
	HookFunction(funcName, (SIZE_T)NewGetCurrentProcess());
	printf("Base virtual address(DOS_HEADER) of Process :%p\n", (void*)lpAddress);
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)lpAddress;
	PIMAGE_NT_HEADERS pNTHeader = (PIMAGE_NT_HEADERS)(lpAddress + pDosHeader->e_lfanew);
	printf("NT_HEADER Address : %p\n", (void*)pNTHeader);
	PIMAGE_OPTIONAL_HEADER pOptionHeader = (PIMAGE_OPTIONAL_HEADER) & (pNTHeader->OptionalHeader);
	printf("OPTIONAL_HEADER Address : %p\n", (void*)(pOptionHeader));
	PIMAGE_IMPORT_DESCRIPTOR pImportDir = PIMAGE_IMPORT_DESCRIPTOR(lpAddress + pOptionHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
	printf("IMPORT_DIRECTORY_TABLE address %p\n\n", (void*)(pImportDir));
	for (; pImportDir->Characteristics; pImportDir++)
		if (!strcmp("KERNEL32.dll", (char*)(lpAddress + pImportDir->Name))) {
			printf("IMPORT DIRECROTY ENTRY : %s\n", (char*)(lpAddress + pImportDir->Name));
			break;
		}
	PIMAGE_THUNK_DATA	pOriginalFirstThunk = (PIMAGE_THUNK_DATA)(lpAddress + pImportDir->OriginalFirstThunk); // ILT
	PIMAGE_THUNK_DATA	pFirstThunk = (PIMAGE_THUNK_DATA)(lpAddress + pImportDir->FirstThunk); // IAT
	PSIZE_T				pFunction = nullptr;
	TY_Function f;
	do {
		PIMAGE_IMPORT_BY_NAME pName = (PIMAGE_IMPORT_BY_NAME)(lpAddress + pOriginalFirstThunk->u1.AddressOfData);
		pFunction = (PSIZE_T) & (pFirstThunk->u1.Function);
		char* name = pName->Name;
		LPVOID address = (void*)(*pFunction);
		f.name = name;
		f.address = address;
		printf(" %s dia chi : 0x%p\n\n", name, address);
		fList->push_back(f);
		pFirstThunk++;
		pOriginalFirstThunk++;

	} while (pOriginalFirstThunk->u1.AddressOfData);
}
void display_list(FunctionList* fList) {
	if (fList->empty()) {
		cout << "NO RECORDS\n";
		return;
	}
	
	cout << "NAME\t" << "address\t\n";
	cout << "---------------------------------------------------------------\n";

	for (auto tmp : *fList) {
		print_info(&tmp);
	}
}
void print_info(TY_Function* f) {
	cout << f->name << "\t" << f->address << "\t" << endl;	
}
