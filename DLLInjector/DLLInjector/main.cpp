#include <iostream>
#include <wchar.h>
#include <Windows.h>
#include <TlHelp32.h>

<<<<<<< HEAD
#define TARGET L"S1GameProtected.exe"
=======
#define TARGET L"Examples.exe"
#define DLL_PATH L"D:\\HackDLL.dll"
>>>>>>> d85adfbeea761b6db2c5b0d52602bafb30e1995c

typedef struct Param {
	FARPROC loadLibrary;
	WCHAR dllName[1024];
} PARAM;

typedef HMODULE(__stdcall *PLOADLIBRARYW) (
	LPCWSTR lpLibFileName
	);

void InjectFunction(LPVOID lpParam) {
	PARAM* param = (PARAM *)lpParam;
	HMODULE hmd = ((PLOADLIBRARYW)param->loadLibrary)(param->dllName);
}

DWORD GetPidByProcessName(WCHAR *name);

int wmain(int argc, WCHAR *argv[]) {
	if (argc < 2) {
		printf("USAGE : DLLInjector DLLNAME");
		return 1;
	}

	SIZE_T written;
	int dataSize = -1;
	unsigned char* data = (unsigned char *)InjectFunction;
	while (data[++dataSize] != 0xc3);

	DWORD pid = GetPidByProcessName(TARGET);
	std::cout << "[*] pid : " << pid << std::endl;

	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);

	PARAM param;
	HMODULE hMod = LoadLibraryW(L"Kernel32.dll");
	param.loadLibrary = GetProcAddress(hMod, "LoadLibraryW");
	wcscpy(param.dllName, argv[1]);

	LPVOID vAddr = VirtualAllocEx(hProcess, NULL, dataSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	LPVOID argAddr = VirtualAllocEx(hProcess, NULL, sizeof(PARAM), MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	std::cout << "[*] vAddr " << std::hex << vAddr << std::endl;
	std::cout << "[*] argAddr " << argAddr << std::endl;

	WriteProcessMemory(hProcess, vAddr, data, dataSize + 1, &written);
	WriteProcessMemory(hProcess, argAddr, (unsigned char *)&param, sizeof(param), &written);

	CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)vAddr, argAddr, 0, NULL);

	return 0;
}

DWORD GetPidByProcessName(WCHAR *name) {
	PROCESSENTRY32W entry;
	memset(&entry, 0, sizeof(PROCESSENTRY32W));
	entry.dwSize = sizeof(PROCESSENTRY32W);

	DWORD pid = -1;
	HANDLE hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if (Process32FirstW(hSnapShot, &entry)) {
		do {
			if (!wcscmp(name, entry.szExeFile)) {
				pid = entry.th32ProcessID;
				break;
			}
		} while (Process32Next(hSnapShot, &entry));
	}

	CloseHandle(hSnapShot);

	return pid;
}
