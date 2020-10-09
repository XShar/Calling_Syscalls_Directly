#include "Calling_Directly_Function.h"
#include <stdio.h>

//Экспорт ассемблерных функций
extern "C" NTSTATUS ZwCreateFile(
    PHANDLE            FileHandle,
    ACCESS_MASK        DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PIO_STATUS_BLOCK   IoStatusBlock,
    PLARGE_INTEGER     AllocationSize,
    ULONG              FileAttributes,
    ULONG              ShareAccess,
    ULONG              CreateDisposition,
    ULONG              CreateOptions,
    PVOID              EaBuffer,
    ULONG              EaLength
    );
extern "C"  unsigned char SetCallNumber(unsigned char call_number);


typedef const UNICODE_STRING* PCUNICODE_STRING;


#define IS_ADDRESS_BETWEEN( left, right, address ) ( (address) >= (left) && (address) < (right) )

static PIMAGE_SECTION_HEADER SectionByRVA(PIMAGE_SECTION_HEADER pSections, DWORD dwSections, DWORD rva)
{
	PIMAGE_SECTION_HEADER pSectionHeader = pSections;
	DWORD i;

	for (i = 0; i < dwSections; i++, pSectionHeader++)
	{
		// Is the RVA within this section?
		if (IS_ADDRESS_BETWEEN(pSectionHeader->VirtualAddress, (pSectionHeader->VirtualAddress + pSectionHeader->SizeOfRawData), rva))
			return pSectionHeader;
	}

	return 0;
}

static DWORD RawOffsetByRVA(PIMAGE_SECTION_HEADER pSections, DWORD dwSections, DWORD dwFileSize, DWORD rva)
{
	PIMAGE_SECTION_HEADER pSectionHeader;
	DWORD dwOffset, dwDelta;

	pSectionHeader = SectionByRVA(pSections, dwSections, rva);
	if (!pSectionHeader)
	{
		return 0;
	}

	dwDelta = rva - pSectionHeader->VirtualAddress;
	dwOffset = pSectionHeader->PointerToRawData + dwDelta;

	if (dwOffset >= dwFileSize)
		return 0;
	else
	{
		return dwOffset;
	}
}

#define GET_POINTER(RVA) ( pBuffer + RawOffsetByRVA( Sections, dwSections, dwFileSize, (RVA) ) )

static unsigned char GetSysCallNumber(char *module, char* name_api)
{
	unsigned char call_number = 0;
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)module;
	PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)((LPBYTE)pDosHeader + pDosHeader->e_lfanew);

	if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE || pNtHeader->Signature != IMAGE_NT_SIGNATURE)
	{
		printf("+++ Error header\n");
		return -1;
	}


	PIMAGE_EXPORT_DIRECTORY pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((LPBYTE)pDosHeader + pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
	if (!pExportDirectory)
	{
		printf("+++ Error export dir\n");
		return -1;
	}

	PDWORD dwAddress = (PDWORD)((LPBYTE)pDosHeader + pExportDirectory->AddressOfFunctions);
	PDWORD dwName = (PDWORD)((LPBYTE)pDosHeader + pExportDirectory->AddressOfNames);
	PWORD dwOrdinal = (PWORD)((LPBYTE)pDosHeader + pExportDirectory->AddressOfNameOrdinals);

	static unsigned char pBuf[32] = { 0 };
	static const unsigned char pSig[4] = { 0x4C, 0x8B, 0xD1, 0xB8 };

	for (DWORD i = 0; i < pExportDirectory->NumberOfFunctions; i++)
	{

		memset(&pBuf, 0, 32);

		PVOID pAddr = (PVOID)((LPBYTE)pDosHeader + dwAddress[dwOrdinal[i]]);
		char* szName = (char*)pDosHeader + dwName[i];

		memcpy(&pBuf, pAddr, 32);

		if (!pAddr || !szName)
			break;

		for (int x = 0; x < sizeof(pSig); x++)
		{

			if (pBuf[x] != pSig[x])
				break;

			if (x == sizeof(pSig) - 1) {
				if (!strcmp(name_api, szName))
				{
					call_number = pBuf[4];
					break;
				}
			}
		}
	}

	return call_number;
}

NTSTATUS sys_NTCreateFile(
    PHANDLE            FileHandle,
    ACCESS_MASK        DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PIO_STATUS_BLOCK   IoStatusBlock,
    PLARGE_INTEGER     AllocationSize,
    ULONG              FileAttributes,
    ULONG              ShareAccess,
    ULONG              CreateDisposition,
    ULONG              CreateOptions,
    PVOID              EaBuffer,
    ULONG              EaLength)
{
	NTSTATUS status = 0;

	char* module = NULL;
	module = (char*)GetModuleHandleA((char*)"ntdll.dll");
	if (module == NULL) 
	{
		printf("+++ Error GetModuleHandle \n");
		status = (-1);
	}

	unsigned char call_number = 0;
	call_number = GetSysCallNumber(module, (char*)"ZwCreateFile");

	if (call_number != 0)
	{
		/*
		Вызов ассемблерной функции, которая установит call_number в глобальную переменную ассемблерного модуля
		*/
		SetCallNumber(call_number);
		//Вызов ассемблерной функции ZwCreateFile
		status = ZwCreateFile(FileHandle,
			DesiredAccess,
			ObjectAttributes,
			IoStatusBlock,
			AllocationSize,
			FileAttributes,
			ShareAccess,
			CreateDisposition,
			CreateOptions,
			EaBuffer,
			EaLength);
	}
	else {
		wprintf(L"+++Error to get call_number\n");
		status = (-1);
	}

   return status;
}