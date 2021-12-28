// DLL_Injector.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <Windows.h>

int main(int argc, char *argv[])
{
	DWORD pid;
	std::string dll_path = argv[1];
	std::string windowName = argv[2];
	LPVOID address;
	DWORD bytesWritten;

	HWND hWindow = FindWindowA(NULL, windowName.c_str());

	if (hWindow) {
		std::cout << "Found window '" << windowName << "'" << std::endl;

		GetWindowThreadProcessId(hWindow, &pid);

		if (pid) {
			std::cout << "Found '" << windowName << "' PID: " << pid << std::endl;

			HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);

			if (hProcess) {
				std::cout << "Process with PID '" << pid << "' opened succesfully" << std::endl;

				address = VirtualAllocEx(hProcess, NULL, strlen(dll_path.c_str()), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
				
				if (address != 0x0) {
					std::cout << "Memory allocated in the target process succesfully" << std::endl;

					WriteProcessMemory(hProcess, address, (LPVOID)dll_path.c_str(), sizeof(dll_path), &bytesWritten);

					HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");

					if (hKernel32) {
						FARPROC loadLibaryAddress = GetProcAddress(hKernel32, "LoadLibraryA");
						HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)loadLibaryAddress, address, 0, NULL);

						if (hThread) {
							std::cout << "Succesfully injected the DLL" << std::endl;

							CloseHandle(hThread);
						}
						else {
							std::cout << "Something failed when trying to inject the DLL. Exiting.." << std::endl;
						}
					}
					else {
						std::cout << "Could not get a handle to KERNEL32.dll. Exiting..." << std::endl;
					}

					VirtualFreeEx(hProcess, address, 0, MEM_RELEASE);
				}
				else {
					std::cout << "Something failed when trying to allocate memory in the target process. Exiting..." << std::endl;
				}

				CloseHandle(hProcess);
			}
			else {
				std::cout << "Something failed when trying to open the process with PID. Exiting..." << pid << std::endl;
			}
		}
		else {
			std::cout << "PID of window " << windowName << " not found. Exiting..." << std::endl;
		}
	}
	else {
		std::cout << "Window " << windowName << " not found. Exiting.." << std::endl;
	}
}