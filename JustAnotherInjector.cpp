#include <iostream>
#include <Windows.h>
#include <VersionHelpers.h>
#include <stdlib.h>
#include <string>

// https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights
#define CREATE_THREAD_ACCESS (PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ)


/*
=================================================================================================================
Here we inject the user-specified DLL into the target process.
We will use the LoadLibrary method, which will:

   1- Connect to the process
   2- Allocate internal memory through the use of VirtualAllocEx() big enough to fit the DLL path name
   3- Write the DLL path name into the space through the use of WriteProcessMemory()
   4- Find the address for LoadLibrary through the use of GetProcAddress() and create a new remote thread 
      with our DLL path as argument through the use of CreateRemoteThread().

This is defined as the simplest way to inject DLLs and is detected by most, if not all, the AntiCheat engines.
=================================================================================================================
*/
BOOL InjectDLLIntoProcess(DWORD ProcessID, std::string DLLPath)
{
	LPCSTR specified_DLL = DLLPath.c_str();
	LPVOID LoadLibAddy, RemoteString;
	BOOL retwait;

	std::cout << "Trying to open the target process." << std::endl;

	if (!ProcessID)
		return 0;

	HANDLE Proc = OpenProcess(CREATE_THREAD_ACCESS, FALSE, ProcessID);

	if (!Proc){
		std::cout << "Can't open the target process through OpenProcess()." << GetLastError() << std::endl;
		return 0;
	}
	else { std::cout << "Process has been opened." << std::endl; }

	// Allocate memory for the dllpath in the target process, length of the path string + null terminator
	LPVOID pDllPath = VirtualAllocEx(Proc, 0, strlen(specified_DLL) + 1, MEM_COMMIT, PAGE_READWRITE);
	if (pDllPath == nullptr) {
		std::cout << "Can't allocate memory in the target process." << std::endl;
		return 0;
	}
	else { std::cout << "Memory allocated." << std::endl; }

	// Write the path to the address of the memory we just allocated in the target process
	DWORD WriteDLLPathAddress = WriteProcessMemory(Proc, pDllPath, (LPVOID)specified_DLL, strlen(specified_DLL) + 1, 0);
	if (WriteDLLPathAddress == 0) {
		std::cout << "Can't write the DLL path in the target process." << std::endl;
		return 0;
	}

	// Create a Remote Thread in the target process which calls LoadLibraryA as our dllpath as an argument -> program loads our dll
	HANDLE hLoadThread = CreateRemoteThread(Proc, 0, 0,
		(LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandleA("Kernel32.dll"), "LoadLibraryA"), pDllPath, 0, 0);
	if (hLoadThread == INVALID_HANDLE_VALUE) {
		std::cout << "Can't create the thread in the target process." << std::endl;
		return 0;
	}

	// Wait for our DLL to get loaded into the thread before proceeding
	if (retwait = WaitForSingleObject(hLoadThread, INFINITE) == WAIT_OBJECT_0) { std::cout << "Loaded!" << std::endl; }

	// Free the allocated memory used to store our DLL Path
	VirtualFreeEx(Proc, pDllPath, 0, MEM_RELEASE);
	CloseHandle(Proc);

	return 0;
}

/*
=================================================================================================================
Here we are going to create the EnumWindowsProc callback function  we will call later in the EnumWindows function.
It will list all the processes based on various filters such as IsWindowVisible.
To continue the enumeration, the callback function must return TRUE; to stop enumeration, it must return FALSE.
https://learn.microsoft.com/en-us/previous-versions/windows/desktop/legacy/ms633498(v=vs.85)
=================================================================================================================
*/
BOOL CALLBACK EnumWindowsProc(HWND hWnd, LPARAM lParam) {
	DWORD dwThreadId, dwProcessId;
	HINSTANCE hInstance;
	char title[256]{};

	// If no Window Handle is passed when the function is called, return TRUE(SKIP)
	if (!hWnd)
		return TRUE;   
	// If the Window is not visibile, return TRUE(SKIP)
	if (!::IsWindowVisible(hWnd))
		return TRUE;
	
	/* 
		If the Window doesn't have a title, return TRUE.
		Save the Window Title into the "title" variable.
		In case you have strange one-string results for the Windows Titles on x86, use the following code instead:

		if (!SendMessage(hWnd, WM_GETTEXT, sizeof(String), (LPARAM)String))

		https://stackoverflow.com/questions/54579064/wm-gettext-returning-only-single-character
	*/
	if (!SendMessageA(hWnd, WM_GETTEXT, sizeof(title), (LPARAM)title))
		return TRUE;        // No window title

	/* 
		In case you have strange errors on x86 regarding GWLP not being available, use the following code instead:

		hInstance = (HINSTANCE)GetWindowLong(hWnd, GWL_HINSTANCE);
	*/
	hInstance = (HINSTANCE)GetWindowLongPtr(hWnd, GWLP_HINSTANCE);
	dwThreadId = GetWindowThreadProcessId(hWnd, &dwProcessId);
	std::cout << "PID: " << dwProcessId << '\t' << title << '\t' << std::endl;
	return TRUE;
}


int main()
{
	// Credits

	std::cout << R"(
       #    #    ### 
       #   # #    #   
       #  #   #   #   
       # #     #  #    
 #     # #######  #    Just Another (DLL) Injector
 #     # #     #  #    Made by Balzabu
  #####  #     # ###   https://github.com/Balzabu)" << "\n\n" << std::endl;


	/*
		=================================================================================================================
		Here we check if the program is executing on a O.S. higher than Windows XP as anything older than it
		is unsupported due to the use the Windows API CreateRemoteThread() function to inject the DLL.
		To detect which OS the software is running on, we are going to use the IsWindowsXPOrGreater() function
		coming from the <VersionHelpers.h>

		https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createremotethread
		https://learn.microsoft.com/en-us/windows/win32/api/versionhelpers/nf-versionhelpers-iswindowsxporgreater
		=================================================================================================================
	*/
	if (IsWindowsXPOrGreater()) {
		std::cout << "Your OS is supported." << "\n\n" << std::endl;

		std::string dll_path;
		DWORD target_PID;
		BOOL is_Process_Selected = FALSE;

		std::cout << "DLL Path: ", std::getline(std::cin, dll_path);
		// Get rid of the " character for paths with namespaces in them
		dll_path.erase(std::remove(dll_path.begin(), dll_path.end(), '"'), dll_path.end());

	/*
		=================================================================================================================
		Here we display the list of the current running processes; the list can be refreshed if the user inputs "-1"
		in the target PID input.
		This could be extended with additional checks to see if the user-supplied input is correct or not.
		=================================================================================================================
	*/
		while (is_Process_Selected == FALSE) {
			std::cout << "Currently running processes:\n" << std::endl;
			EnumWindows(EnumWindowsProc, NULL);
			std::cout << "\nTarget PID, write '-1' to refresh processes list: ", std::cin >> target_PID;
			if (target_PID == -1) {
				system("CLS");
				continue;
			}
			else {
				std::cout << "\n";
				is_Process_Selected = TRUE;
			}
		}
		InjectDLLIntoProcess(target_PID, dll_path);
	}
	else {
		std::cout << "Your OS is not supported." << std::endl;
		return 0;
	}

	return 0;
}