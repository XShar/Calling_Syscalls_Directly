#include <stdio.h>
#include <Windows.h>
#include <stdio.h>

#include "Calling_Directly_Function.h"

typedef void (WINAPI* _RtlInitUnicodeString)(
	PUNICODE_STRING DestinationString,
	PCWSTR SourceString
	);

int main(int argc, char* argv[])
{
	WCHAR chDmpFile[MAX_PATH] = L"\\??\\";
	WCHAR chWinPath[MAX_PATH];

	GetCurrentDirectory(MAX_PATH, chWinPath);

	wcscat_s(chDmpFile, sizeof(chDmpFile) / sizeof(wchar_t), chWinPath);
	wcscat_s(chDmpFile, sizeof(chDmpFile) / sizeof(wchar_t), L"\\test_file.txt");

	_RtlInitUnicodeString RtlInitUnicodeString = (_RtlInitUnicodeString)
		GetProcAddress(GetModuleHandle(L"ntdll.dll"), "RtlInitUnicodeString");
	if (RtlInitUnicodeString == NULL) {
		wprintf(L"+++ Failed to create testfile.\n");
		system("pause");
	}

	UNICODE_STRING uFileName;
	RtlInitUnicodeString(&uFileName, chDmpFile);

	HANDLE hTestFile = NULL;
	IO_STATUS_BLOCK IoStatusBlock;

	ZeroMemory(&IoStatusBlock, sizeof(IoStatusBlock));
	OBJECT_ATTRIBUTES FileObjectAttributes;
	InitializeObjectAttributes(&FileObjectAttributes, &uFileName, OBJ_CASE_INSENSITIVE, NULL, NULL);

	NTSTATUS status = sys_NTCreateFile(&hTestFile, FILE_GENERIC_WRITE, &FileObjectAttributes, &IoStatusBlock, 0,
		FILE_ATTRIBUTE_NORMAL, FILE_SHARE_WRITE, FILE_OVERWRITE_IF, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);

	if (hTestFile == INVALID_HANDLE_VALUE) {
		wprintf(L"	[!] Failed to create testfile.\n");
		system("pause");
	}

	wprintf(L"+++ Test File Created is OK \n");

	system("pause");

	return 0;
}
