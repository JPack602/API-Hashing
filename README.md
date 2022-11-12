![title_letter](https://user-images.githubusercontent.com/80070644/201461047-7062464d-75f5-44ce-99d2-f6fff5009d23.png)

# API Hashing  
Windows API Hashingを行っているサンプルコードです。  
  
API Hashingは日本語で書かれた資料が少ない（存在"は"しているが有料の記事である事が多い）為、今回はAPI Hashingの仕組みについてイラストとサンプルコードとを用いて紹介したいと思います。これはプログラム内で関数をただ呼び出すだけではなく、関数をエクスポートしてるDLLから目的の関数を探し出し、動的にアドレスを解決する仕組みのことを指します。この「API Hashing」というテクニックを用いることで以下の様に、プログラム内で呼び出されている関数(Windows API等々)を隠す事が可能です。またAPI Monitorでも関数呼び出しの様子をモニタリングすることが困難となります。

![cmpare_import_dir](https://user-images.githubusercontent.com/80070644/201461071-ffdb092e-3816-4208-982b-36a1c266d506.png)
<br>

インポートしている関数を隠すだけなら、[UPX](https://upx.github.io/)の様なパッカーを使用した方が手軽ではありますが、今回は「API Hashing」というタイトルが付いている都合上、パッカーについては触れません。
<br>

※サンプルコードを閲覧する場合は画面上にコードを表示した状態で、"github.com"というドメインを"github 1s .com"に書き換えることで、VSCode上で閲覧することが可能です。
※本内容には誤りを含む可能性があります。
<br>

今回はMessageBoxA関数のアドレスを取得するところをゴールとします。

MessageBoxA関数はUser32.dllからエクスポートされているので、User32.dllのアドレスを取得すること第一段階です。しかし、「LoadLibrary関数やGetModuleHandle関数無しで、どうやって目的のDLLをロードするの？」と疑問を持つかもしれませんが、気にする必要はありません。LoadLibrary関数はKernel32.dllからエクスポートされており、このKernel32.dll自体はプログラマが明示的にロードせずとも、プロセスが開始するタイミングで勝手にロードされる為、この"勝手"にロードされたKernel32.dllの中からLoadLibrary関数を探せば良いだけなのです。ちなみにntdll.dllなども"勝手"にロードされます。
<br>

~~話がそれますが、ntdll.dllは速い段階で使用可能なライブラリで、OSが起動するよりも前から使用可能です。その為、OSを起動するためのソフトウェア(＝ 2次ブートローダー)はntdll.dllからエクスポートされている関数を使用してプログラムが作られています。よって、マスターブートレコードを暗号化するランサムウェアなど、OSの起動よりも先に何かしらの処理を行いたい場合は、必然的にntdll.dllを利用することとなります。~~
<br>

流れとしては以下の様になります。

1. PEB構造体からkernel32.dllのアドレスを取得。
2. kernel32.dllの中からLoadLibrary関数のアドレスを取得。
3. LoadLibrary関数を用いて、DLLをロード。

## 1. PEB構造体からkernel32.dllのアドレスを取得

まず初めに、コードを見せながら紹介します。

```C
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
```
まずPEBの場所ですが、これはTEBの中にあります。TEBはプロセス内のスレッドに関する情報を格納している為、複数個スレッドがある場合その数だけTEB構造体がプロセスメモリー内に存在していることになります。 [^1] まず、TEB構造体のアドレスを取得しない事には、何も始まりません。幸いNt​​CurrentPebという関数(マクロ？)が存在している為、これを使うとTEB構造体のアドレスが取得可能です。

PEBのアドレスが取得できたら次に、Kernel32.dllのアドレスを取得します。PEB構造体などのUnDocumentedな構造体の中身(どんなメンバ変数が存在するかなど)はWinDbgなどを使用すると確認することが出来ますが、今回は[このサイト](https://atmarkit.itmedia.co.jp/ait/articles/1111/18/news146_2.html)[^2]を参考にさせて頂きました。

以下の図の様にPEB構造体のメンバ変数Ldrを参照します。
その中には、InLoadOrderModuleList・InMemoryOrderModuleList・InInitializationOrderModuleListの3つが存在しており、どれを使用してもイイのですが、今回はInLoadOrderModuleListを使用するものとします。これらのリストはプロセスにロードされているモジュールの情報を持ち、順番通りに双方向リンクリストを辿っていくとkernel32.dllのアドレスが手に入ります。

これで第一段階はクリアです。
![kernel32 dll](https://user-images.githubusercontent.com/80070644/201461101-8809d02d-9b12-405c-a942-7ef611ee1f99.png)

## 2. kernel32.dllの中からLoadLibrary関数のアドレスを取得

``` C
LibAndHash fnLibAndHashPair[] = {
	"kernel32.dll", 0x9322F2DB,   // LoadLibraryA
	"kernel32.dll", 0xDE5F2EC9,   // GetProcAddress
	"user32.dll",   0x1C4E3F7A,   // MessageBoxA
};

// DLLのエクスポートセクションから関数のアドレスを取得
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
```
第二段階では上記の関数を利用して、LoadLibrary関数のアドレスを取得します。注目してほしいのは、この関数はDLLのアドレスと関数名のハッシュ値を引数として受け取ります。そうすることにより逆アセンブルやデバッグされたとしても、引数からどの関数のアドレスを取得しようとしているのか、特定することが困難になります。

今回はLoadLibrary関数のアドレスを取得する必要がある為、第一引数に"kernel32.dll"、第二引数にLoadLibraryAという文字列のハッシュ"0x9322F2DB"を指定するとアドレスを取得することが可能です。

## 3. LoadLibrary関数を用いてDLLをロード

```C
// user32.dllをロード
hModule = g_fnLoadLibraryA("user32.dll");
if (! hModule) return 1;

// MessageBoxAのアドレスを解決
fnMessageBoxA = SolveFunctionAddress(hModule, 0x1C4E3F7A);
if (! fnMessageBoxA) return 1;

fnMessageBoxA(NULL, "test", "sample text.", MB_OK);
```
下準備は整っているので後は上記の様に、MessageBoxAをエクスポートしているuser32.dllをロードする。そして、先ほど紹介した関数を利用して、DLLのアドレス・関数名のハッシュを渡す事により、関数のアドレスは取得ができます。実際に使用する際は、LoadLibrary関数に渡すDLL名を暗号化すると、より効果的でしょう。

https://user-images.githubusercontent.com/80070644/201461106-5b9ec9b4-6299-4f60-8eb4-9904cfeedd3b.mp4


## さいごに。
"API Hashing"について詳細な説明が出来たかは分かりませんが、この記事を見ている方のお役に立てれば幸いです。

### 参考文献
[^1]: [Find kernel32 address](https://cocomelonc.github.io/tutorial/2021/10/30/windows-shellcoding-2.html)
[^2]: [PEB構造体](https://atmarkit.itmedia.co.jp/ait/articles/1111/18/news146_2.html)
