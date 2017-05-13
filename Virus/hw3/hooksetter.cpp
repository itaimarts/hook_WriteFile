#include "stdafx.h"
#include <vector>
#include <string>
#include <windows.h>
#include <Tlhelp32.h>
#include <windows.h>
#include <stdio.h>
#include "detours.h"
#undef UNICODE
#pragma comment (lib, "detours.lib")
using std::vector;
using std::string;

#define DLL_NAME "hookdll.dll"

int main(void)
{
    vector<string>processNames;
    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);
    HANDLE hTool32 = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
    BOOL bProcess = Process32First(hTool32, &pe32);
    if(bProcess == TRUE){
        while((Process32Next(hTool32, &pe32)) == TRUE){
            processNames.push_back(pe32.szExeFile);
           
            char* DirPath = new char[MAX_PATH];
            char* FullPath = new char[MAX_PATH];
            GetCurrentDirectory(MAX_PATH, DirPath);
            sprintf_s(FullPath, MAX_PATH, "%s\\hookdll.dll", DirPath);
            HANDLE hProcess = OpenProcess(PROCESS_CREATE_THREAD    | PROCESS_VM_OPERATION    |
                PROCESS_VM_WRITE, FALSE, pe32.th32ProcessID);

            LPVOID LoadLibraryAddr = (LPVOID)GetProcAddress(GetModuleHandle("kernel32.dll"),
                "LoadLibraryA");

            LPVOID LLParam = (LPVOID)VirtualAllocEx(hProcess, NULL, strlen(FullPath),
                MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
            WriteProcessMemory(hProcess, LLParam, FullPath, strlen(FullPath), NULL);
            CreateRemoteThread(hProcess, NULL, NULL, (LPTHREAD_START_ROUTINE)LoadLibraryAddr,
                LLParam, NULL, NULL);
            CloseHandle(hProcess);
            delete [] DirPath;
            delete [] FullPath;   
        }
    }
    CloseHandle(hTool32);
    return 0;
}


