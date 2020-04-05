---
title: DLL 注入之远程线程注入
date: 2017-05-10 21:45:08
tags: [DLL 注入]
categories: Windows
keywords: [DLL 注入，远程线程注入]
---

在 Windows 中有多种方法实现 DLL 注入，可以[使用消息钩子注入 DLL](http://0x4c43.cn/2017/0508/dll-injection-windows-message-hook/)，但是通过消息钩子的方法可控性差，不能准确的注入到指定的进程中。而使用远程线程注入的方法可以实现准确地在指定时刻将 DLL 注入到指定的进程中，其可控性较好。

# 0x01 注入原理
使用 Windows 远程线程机制，在本地进程中通过 CreateRemoteThread 函数在其他进程中开启并运行一个线程。CreateRemoteThread 函数原型如下：
```C
HANDLE WINAPI CreateRemoteThread (
	HANDLE                  hProcess,	// 远程进程句柄
	LPSECURITY_ATTRIBUTES  	lpThreadAttributes,	// 线程的安全属性
	SIZE_T                  dwStackSize,		// 线程栈的大小
	LPTHREAD_START_ROUTINE	lpStartAddress,  // 线程入口函数的起始地址
	LPVOID                  lpParameter, 		// 传递给线程函数的参数
	DWORD                   dwCreationFlags,	// 线程是否立即启动
	LPDWORD                 lpThreadId		// 用于保存内核分配给线程的ID
)；
```
主要关注三个参数：hProcess、lpStartAddress 和 lpParameter。hProcess 是要执行线程的目标进程句柄；lpStartAddress 是线程函数的起始地址，且该函数必须位于目标进程内；lpParameter 是传递给线程函数的参数。

为了使远程进程加载 DLL，把 LoadLibrary 函数作为 CreateRemoteThread 的线程函数，要加载的 DLL 路径作为线程函数的参数即可。

>让远程进程执行 LoadLibrary 函数加载 DLL 文件，需解决两个问题：    
1）获得远程进程中 LoadLibrary 函数的地址：Kernel32.dll 是系统基本库，且 Windows 系统中，所有进程加载 Kernel32.dll 模块基址是固定且一致的，所以只需获取本地进程中 LoadLibrary 地址。   
2）向远程进程传递需加载 DLL 的路径：通过 Windows API 函数把路径写入远程进程中，使用以下API：OpenProcess、VirtualAllocEx、WriteProcessMemory、VirtualFreeEx。

# 0x02 注入过程
## 1. 获取目标进程句柄
使用 OpenProcess 函数打开远程进程的句柄。访问权限 dwDesiredAccess 需要设置为 PROCESS_ALL_ACCESS。
```C
HANDLE WINAPI OpenProcess (
	DWORD 	dwDesiredAccess,	// 指定所得句柄具有的访问权限
	BOOL  	bInheritHandle,		// 是否可被继承
	DWORD 	dwProcessId		// 指定要打开的进程ID
);

hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPID);
```

## 2. 在目标进程分配内存空间
使用 VirtualAllocEx 在目标进程中分配足够的内存空间，用于保存要加载 DLL 的路径。
```C
LPVOID WINAPI VirtualAllocEx (
	HANDLE 	hProcess,	// 目标进程句柄
	LPVOID	lpAddress,	// 期望的起始地址，通常置为NULL
	SIZE_T  dwSize,		// 需分配的内存大小
	DWORD  	flAllocationType, // 分配内存空间的类型，取 MEM_COMMIT
	DWORD 	flProtect		// 内存访问权限，指定为可读可写：PAGE_READWRITE
);

pRemoteBuf = VirtualAllocEx(hProcess, NULL, dwBufSize, MEM_COMMIT, PAGE_READWRITE);
```

## 3. 写入 DLL 路径至目标进程
用 WriteProcessMemory 函数把需加载的 DLL 路径写入到远程进程分配的内存空间。
```C
BOOL WINAPI WriteProcessMemory (
	HANDLE    hProcess,		// 目标进程句柄
	LPVOID    lpBaseAddress,	// 目标进程内存空间首地址
	LPCVOID   lpBuffer,		// 需写入数据的内存空间地址
	SIZE_T    nSize,			// 需写入数据字节数
	SIZE_T    *lpNumberOfBytesWritten	  // 实际写入的字节数，设置为 NULL
);

WriteProcessMemory(hProcess, pRemoteBuf, (LPVOID)szDllPath, dwBufSize, NULL);
```

## 4. 获取 LoadLibraryW 地址
Windows 系统中，LoadLibraryW 函数位于 kernel32.dll 中，并且系统核心 DLL 会加载到固定地址，所以系统中所有进程的 LoadLibraryW 函数地址是相同的。用 GetProcAddress 函数获取本地进程 LoadLibraryW 地址即可。
```C
WINAPI GetProcAddress (
	MODULE 	hModule,	  // 模块句柄
	LPCSTR 	lpProcName	// 函数名
);

hMod = GetModuleHandle(L"kernel32.dll");
pThreadProc = (LPTHREAD_START_ROUTINE)GetProcAddress(hMod, "LoadLibraryW");
```

## 5. 在目标进程中运行远程线程
使用 CreateRemoteThread 函数是目标进程调用 LoadLibraryW 函数加载 DLL。
```C
hThread = CreateRemoteThread(hProcess, NULL, 0, pThreadProc, pRemoteBuf, 0, NULL);
```

# 0x03 测试
## 1. 需注入 DLL 源码
```C
//Injectdll.dll
#include "windows.h"
#include "tchar.h"

HMODULE g_hMod = NULL;
BOOL WINAPI DllMain(HINSTANCE hinstDll, DWORD dwReason, LPVOID lpvReserved)
{
	TCHAR Msg[50] = _T("Inject to ");
	TCHAR szPath[MAX_PATH] = {0};
	if(!GetModuleFileName(g_hMod, szPath, MAX_PATH))
		return FALSE;
	_tcscat(Msg, szPath);

	switch( dwReason )
	{
		case DLL_PROCESS_ATTACH:  
			OutputDebugString(L"Sucess inject <Injectdll.dll> !!");
			MessageBox(NULL, Msg, TEXT("InjectDll"), MB_OK);  
			break;  
		case DLL_PROCESS_DETACH:  
			MessageBox(NULL, TEXT("Dll unInjected!!!"), TEXT("InjectDll"), MB_OK);  
			break;  
    }  
    return TRUE;  
}   
```

## 2. 注入程序
```C
// Injectmain.cpp

#include "windows.h"
#include "tchar.h"

BOOL InjectDll(DWORD dwPID, LPCTSTR szDllPath)
{
	HANDLE hProcess = NULL, hThread = NULL;
	HMODULE hMod = NULL;
	LPVOID pRemoteBuf = NULL;
	DWORD dwBufSize = (DWORD)(_tcslen(szDllPath) + 1) * sizeof(TCHAR);
	LPTHREAD_START_ROUTINE pThreadProc;

	// Open target process to inject dll
	if( !(hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPID)) )
	{
		_tprintf(L"Fail to open process %d ! [%d]\n", dwPID, GetLastError());
		return FALSE;
	}

	// Allocate memory in the remote process big enough for the DLL path name
	pRemoteBuf = VirtualAllocEx(hProcess, NULL, dwBufSize, MEM_COMMIT, PAGE_READWRITE);

	// Write the DLL path name to the space allocated in the target process
	WriteProcessMemory(hProcess, pRemoteBuf, (LPVOID)szDllPath, dwBufSize, NULL);

	// Find the address of LoadLibrary in target process(same to this process)
	hMod = GetModuleHandle(L"kernel32.dll");
	pThreadProc = (LPTHREAD_START_ROUTINE)GetProcAddress(hMod, "LoadLibraryW");

	// Create a remote thread in target process
	hThread = CreateRemoteThread(hProcess, NULL, 0, pThreadProc, pRemoteBuf, 0, NULL);
	WaitForSingleObject(hThread, INFINITE);

	CloseHandle(hThread);
	VirtualFreeEx(hProcess, pRemoteBuf, 0, MEM_RELEASE);
	CloseHandle(hProcess);

	return TRUE;
}

int _tmain(int argc, TCHAR *argv[])
{
	if( argc != 3 )
	{
		_tprintf(L"Usage: %s <pid> <dll_path> \n", argv[0]);
		return 1;
	}

	// Inject DLL
	if( InjectDll((DWORD)_tstol(argv[1]), argv[2]) )
		_tprintf(L"InjectDll <%s>sucess! \n", argv[2]);
	else
		_tprintf(L"InjectDLL <%s> fail! \n", argv[2]);

	return 0;
}
```
## 3. 测试效果   
运行 Injectmain.exe 将 DLL 注入到进程 3656（notepad.exe）中，注入成功将弹出消息框。    
![](https://raw.githubusercontent.com/0x4C43/BlogImages/master/1586020220_94028700-file_1494473311845_13a5b.png)     
查看 notepad.exe 进程加载的模块列表，可以看到 InjectDll.dll 已被加载。     
![](https://raw.githubusercontent.com/0x4C43/BlogImages/master/1586020218_35149412-file_1494473313402_167fd.png)    

----
References:   
[1] 逆向工程核心原理   
[2] [DLL注入浅析（下）](https://etenal.me/archives/871)
