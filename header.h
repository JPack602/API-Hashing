#ifndef __HEADER_H__
#define __HEADER_H__

#ifdef __cplusplus
#extern "C" {
#endif

#include <stdio.h>
#include <stdint.h>     // uintptr_t
#include <windows.h>
#include <winternl.h>   // UNICODE_STRING
#include <ctype.h>      // isalpha

#ifndef RELEASE
#define DEBUG
#endif

typedef struct
{
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	LIST_ENTRY InInitializationOrderLinks;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG Flags;
	WORD LoadCount;
	WORD TlsIndex;
	union
	{
		LIST_ENTRY HashLinks;
		struct
		{
			PVOID SectionPointer;
			ULONG CheckSum;
		};
	};
	union
	{
		ULONG TimeDateStamp;
		PVOID LoadedImports;
	};
	// _ACTIVATION_CONTEXT *EntryPointActivationContext;
	PVOID PatchInformation;
	LIST_ENTRY ForwarderLinks;
	LIST_ENTRY ServiceTagLinks;
	LIST_ENTRY StaticLinks;
} UD_LDR_DATA_TABLE_ENTRY, *UD_LPLDR_DATA_TABLE_ENTRY;   // _LDR_DATA_TABLE_ENTRY

typedef struct
{
	ULONG Length;
	BOOLEAN Initialized;
	PVOID SsHandle;

	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;

	PVOID EntryInProgress;
	BOOLEAN ShutdownInProgress;
	HANDLE ShutdownThreadId;

} UD_PEB_LDR_DATA, *UD_LPPEB_LDR_DATA;   // UnDocumented structure



typedef struct {
	char    *lpDllName;
	uint32_t dwFuncHash;
} LibAndHash;



// �֐��ւ̃|�C���^
extern FARPROC g_fnLoadLibraryA  ;
extern FARPROC g_fnGetProcAddress;



// DLL�Ɗ֐��n�b�V���̃y�A�������z��̓Y����
typedef enum {
	LOAD_LIBRARY_A,
	GET_PROC_ADDRESS,
	MESSAGE_BOX_A
} LibAndHashIndex;



// PEB����Kernel32.dll�̃A�h���X���擾
extern void *LoadKernel32(void);
// �֐��ւ̃|�C���^���擾
extern void *SolveFunctionAddress(void *lpModule, const uint32_t dwHash);



#ifdef DEBUG
// �n�b�V�����擾
extern uint32_t GenHash(uint8_t *lpString);
// �n�b�V�����擾(���������\�̈�ɑ��݂��镶����̂ݎg�p��)
extern uint32_t CalcHash(uint8_t *lpString);
#endif

#ifdef __cplusplus
}
#endif

#endif