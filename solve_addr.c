#include "header.h"

// 関数へのポインタ
FARPROC g_fnLoadLibraryA   = NULL;
FARPROC g_fnGetProcAddress = NULL;

// PEB構造体のアドレスを取得
PEB *Nt​​CurrentPeb(VOID)
{
	return NtCurrentTeb()->ProcessEnvironmentBlock;
}

// Kernel32.dllのアドレスを取得
void *LoadKernel32(void)
{
	// Kernel32の情報
	static UD_LDR_DATA_TABLE_ENTRY *lpKernel32 = NULL;

	// すでにアドレス取得済み(NULLでない)場合、return
	if (lpKernel32) goto FuncEnd;

	// PEB構造体
	PEB *lpPeb = NULL;

	// PEB_LDR_DATA構造体(プロセスにロードされたモジュール)
	UD_PEB_LDR_DATA *lpLdr = NULL;

	LIST_ENTRY *lpInLoadOrderModuleList = { 0 };

	// PEBのアドレスを取得
	lpPeb = Nt​​CurrentPeb();
	if (! lpPeb) return NULL;

	// PEB_LDR_DATA構造体を取得
	lpLdr = lpPeb->Ldr;

	// InLoadOrderModuleListのアドレスを取得
	lpInLoadOrderModuleList = &lpLdr->InLoadOrderModuleList;

	// リストからLDR_DATA_TABLE_ENTRY構造体を取り出す
	// Kernel32の情報を取得
	// kernel32.dllのアドレスは3番名
	lpKernel32 = lpInLoadOrderModuleList->Flink->Flink->Flink;

FuncEnd:
	return lpKernel32->DllBase;
}

// DLLのエクスポートセクションから目的の関数のアドレスを取得
// GetProcAddressみたいな関数
void *SolveFunctionAddress(void *lpModule, const uint32_t dwHash)
{
	if (! lpModule) return NULL;
	if (! dwHash)   return NULL;

	// DLLのアドレス
	HMODULE hModule = lpModule;

	// DOSヘッダー
	IMAGE_DOS_HEADER       *lpDosHeader = (IMAGE_DOS_HEADER *)hModule;
	// NTヘッダー
	IMAGE_NT_HEADERS       *lpNtHeaders = (IMAGE_NT_HEADERS *)((BYTE *)hModule + lpDosHeader->e_lfanew);
	// Optionalヘッダー
	IMAGE_OPTIONAL_HEADER  *lpOptionalHeader = &lpNtHeaders->OptionalHeader;
	// エクスポート情報
	IMAGE_DATA_DIRECTORY   *lpDirectory = &lpOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
	// エクスポート情報
	IMAGE_EXPORT_DIRECTORY *lpImgExport = (IMAGE_EXPORT_DIRECTORY *)((BYTE *)hModule + lpDirectory->VirtualAddress);

	// 関数のアドレスへのポインタ
	uint32_t *lpFuncAddrList = (uintptr_t)hModule + (uintptr_t)lpImgExport->AddressOfFunctions;
	// 関数の名前へのポインタ
	uint32_t *lpFuncName     = (uintptr_t)hModule + (uintptr_t)lpImgExport->AddressOfNames;
	// 関数の序数へのポインタ
	uint16_t *lpOrdinals     = (uintptr_t)hModule + (uintptr_t)lpImgExport->AddressOfNameOrdinals;

	// 配列の添え字
	int nIndex = 0;
	// ターゲットとなる関数のアドレス
	void *lpFuncAddr = NULL;

	for (int i = 0; i < lpImgExport->NumberOfNames; ++i)
	{
		nIndex = lpOrdinals[i];

		// ハッシュ値を比較して関数名をチェック
		if (HashWithFnv1((uintptr_t)hModule + lpFuncName[i]) - dwHash == 0)
		{
			// 一致していたら、関数へのポインタを取得
			lpFuncAddr = (uintptr_t)hModule + lpFuncAddrList[nIndex];

			// 関数へのポインタ(メモリアドレス)をreturn
			return lpFuncAddr;
		}
	}

	return NULL;
}

// 文字列からハッシュを取得
uint32_t HashWithFnv1(uint8_t *lpString)
{
	// FNV_OFFSET_BASIS_32 : 2166136261
	uint32_t dwHash = 2166136261UL;

	while (*lpString)
	{
		// FNV_PRIME_32 : 16777619
		dwHash *= 16777619UL;
		dwHash ^= *lpString++;
	}

	return dwHash;
}

#ifdef DEBUG
uint32_t GenHash(uint8_t *lpString)
{
	printf("%s : 0x%04X\n", lpString, HashWithFnv1(lpString));
}
#endif