#include "header.h"

#include <string.h>

LibAndHash fnLibAndHashPair[] = {
	"kernel32.dll", 0x9322F2DB,   // LoadLibraryA
	"kernel32.dll", 0xDE5F2EC9,   // GetProcAddress
	"user32.dll",   0x1C4E3F7A,   // MessageBoxA
};

int main(int argc, char **argv)
{
	FARPROC fnMessageBoxA = NULL;
	HMODULE hModule = NULL;

	// kernel32のアドレスを取得
	hModule = LoadKernel32();
	if (! hModule) return 1;

	// LoadLibraryAのアドレスを取得
	g_fnLoadLibraryA = SolveFunctionAddress(hModule, fnLibAndHashPair[LOAD_LIBRARY_A].dwFuncHash);
	if (! g_fnLoadLibraryA) return 1;

	// user32.dllをロード
	hModule = g_fnLoadLibraryA(fnLibAndHashPair[MESSAGE_BOX_A].lpDllName);
	if (! hModule) return 1;

	// MessageBoxAのアドレスを解決
	fnMessageBoxA = SolveFunctionAddress(hModule, fnLibAndHashPair[MESSAGE_BOX_A].dwFuncHash);
	if (! fnMessageBoxA) return 1;

	fnMessageBoxA(NULL, "test", "sample text.", MB_OK);

	return 0;
}