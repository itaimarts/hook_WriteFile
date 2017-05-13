
#pragma comment(lib, "detours.lib")

#undef UNICODE
#include <windows.h>
#include "detours.h"
#include <fstream>
#include <string>
#include <direct.h>
#include <strsafe.h>

extern __declspec(dllexport) void foo();

#define DIR_PATH "C:\\temp\\"

BOOL (WINAPI * Real_WriteFile) (
	HANDLE       hFile,
	LPCVOID      lpBuffer,
	DWORD        nNumberOfBytesToWrite,
	LPDWORD      lpNumberOfBytesWritten,
	LPOVERLAPPED lpOverlapped) = WriteFile;

BOOL WINAPI Routed_WriteFile(
	HANDLE       hFile,
	LPCVOID      lpBuffer,
	DWORD        nNumberOfBytesToWrite,
	LPDWORD      lpNumberOfBytesWritten,
	LPOVERLAPPED lpOverlapped)
{

	DWORD pid = GetCurrentProcessId();
	char name[500];
	char fullPIDLogFilePath[1024];
	char logger[1024];
	size_t i;
	char DataBuffer[500];
	//DWORD dwBytesToWrite;
	DWORD dwBytesWritten = 0;
	BOOL bErrorFlag = FALSE;
	wchar_t wtext[1024];
	HANDLE hFile1;


	//sprintf_s(logger, "Entered hook => file name: %s, log file: %s\n", DataBuffer, fullPIDLogFilePath);
	//OutputDebugString(TEXT(logger));

	//converting full log file path to LPWSTR
	sprintf_s(fullPIDLogFilePath, "%s%d.txt", DIR_PATH, pid);
	mbstowcs(wtext, fullPIDLogFilePath, strlen(fullPIDLogFilePath) + 1);//Plus null
	LPWSTR ptr = wtext;

	hFile1 = CreateFileW(ptr, FILE_APPEND_DATA, FILE_SHARE_WRITE, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

	if (hFile1 == INVALID_HANDLE_VALUE)
		OutputDebugString(TEXT("Unable to open file\n"));

	//open log file
	//wcstombs_s(&i, DataBuffer, (size_t)500, , 500);
	//sprintf_s(DataBuffer, "%s\r\n", DataBuffer);
	//dwBytesToWrite = (DWORD)strlen(DataBuffer);
	//sprintf_s(logger, "length: %d\n", dwBytesToWrite);
	//OutputDebugString(logger);

	bErrorFlag = Real_WriteFile(
		hFile1,           // open file handle
		(char *) lpBuffer,      // start of data to write
		(DWORD)strlen((char *)lpBuffer),  // number of bytes to write
		&dwBytesWritten, // number of bytes that were written
		NULL);            // no overlapped structure

	if (FALSE == bErrorFlag)
		OutputDebugString(TEXT("write the requested file in our log\n"));
	else
		if (dwBytesWritten != strlen((char *)lpBuffer))
			OutputDebugString(TEXT("number of written bytes not equal to requested one\n"));
		else
			OutputDebugString(TEXT("documented succefully\n"));

	CloseHandle(hFile1);

	return Real_WriteFile(
		hFile,
		lpBuffer,
		nNumberOfBytesToWrite,
		lpNumberOfBytesWritten,
		lpOverlapped);
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
	LONG Error;
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:

		OutputDebugString(TEXT("Attaching HookCreateFileDll.dll"));
		DetourRestoreAfterWith();
		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());
		DetourAttach(&(PVOID&)Real_WriteFile, Routed_WriteFile);
		Error = DetourTransactionCommit();

		if (Error == NO_ERROR)
			OutputDebugString(TEXT("Hooked Success"));
		else
			OutputDebugString(TEXT("Hook Error"));

		break;
	case DLL_PROCESS_DETACH:
		OutputDebugString(TEXT("De-Attaching HookCreateFileDll.dll"));
		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());
		DetourDetach(&(PVOID&)Real_WriteFile, Routed_WriteFile);
		Error = DetourTransactionCommit();

		if (Error == NO_ERROR)
			OutputDebugString(TEXT("Un-Hooked Success"));
		else
			OutputDebugString(TEXT("Un-Hook Error"));
		break;
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
		break;
	}
	return TRUE;
}

