/*
  This sandbox module is from [Fossil
  grader](http://code.google.com/p/fossil-grader/).

  This library is a modification from a program called trun, taken
  from an unknown source.  (FIX THIS)

  When compiling with Mingw, add "-lpsapi" to link Windows'memory stat
  library.
*/
#include <windows.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <stdio.h>
#include "execute.h"

#define INITIAL_WAIT_FOR_MEM_CHECK  100

/* 
==How execute works==

===Start up===
Set up basic configurations: input file, output file
into STARTUPINFO struct to be passed to CreateProcess.

Create a child process with CreateProcess.

===Wait===
Use WaitForSingleObject to wait.

===Killing chile process===
This process is really involved, because (1) programs in
DOS mode actually runs inside NTVDM so killing them
requires to kill NTVDM, (2) something a program crashes
NTVDM and a dialog box pops up, and we need to close
that dialog box MANUALLY, and (3) for Win32 apps that crash,
some reporting service in Windows opens a dialog box,
and it has to be killed.

Those extra steps are what's exactly done here:
1. Kill the process if there's any
2. In case that there's no real process, find NTVDM 
and kill it (repeatedly until it's gone)
3. Check if NTVDM crashed and some warning dialog opens,
if there's any, signal the user and wait.
4. For real Win32 apps, find process "dwwin.exe" which
represents an agent for reporting service and also 
opens a dialog.  If finds it, kill it (repeatedly)
until it's gone.

Step 4. might be problematic --- dwwin.exe might not
be a universal process for error reporting services???
*/



/*
These are routines that check NTVDM crash dialog.
It works by enumerating all window titles, and
checks for "16 bit" or something with ".exe" somewhere 
and starts with "cmd.exe".
*/
bool NTVDMcrashed_found;

/* this is a callback for window title enumeration */
BOOL CALLBACK EnumWindowsProc(HWND hWnd, LPARAM lParam)
{
  char buffer[256];
  GetWindowText(hWnd, buffer, 256);
  
  if(strlen(buffer)!=0) {
    if(strstr(buffer,"16 bit")!=0) {
      NTVDMcrashed_found = true;
    }
    if((strstr(buffer,".exe")!=0) && 
       (strstr(buffer,"cmd.exe")==buffer)) {
      NTVDMcrashed_found = true;
      printf("Title: %s\n",buffer);
    }
  }
  return TRUE;
}

bool check_ntvdm_dialog()
{
  NTVDMcrashed_found = false;

  FARPROC EnumProcInstance = MakeProcInstance((FARPROC)EnumWindowsProc,
					      AfxGetInstanceHandle());
  EnumWindows((WNDENUMPROC)EnumProcInstance, (LPARAM)0);
  FreeProcInstance(EnumProcInstance);
  
  return NTVDMcrashed_found;
}

DWORD get_process_id(char *pname)
{
  HANDLE hProcessSnap;
  HANDLE hProcess;
  PROCESSENTRY32 pe32;
  DWORD dwPriorityClass;
  DWORD pid=0;

  hProcessSnap = CreateToolhelp32Snapshot( TH32CS_SNAPPROCESS, 0 );
  if( hProcessSnap == INVALID_HANDLE_VALUE ) {
    return 0;
  }
  
  pe32.dwSize = sizeof( PROCESSENTRY32 );
  if( !Process32First( hProcessSnap, &pe32 ) ) {
    CloseHandle( hProcessSnap ); 
    return 0;
  }

  do {
    if(strcasecmp(pe32.szExeFile ,pname)==0)
      pid = pe32.th32ProcessID;
  } while( Process32Next( hProcessSnap, &pe32 ) );
  
  CloseHandle( hProcessSnap );
  return pid;
}

DWORD get_ntvdm_pid()
{
  return get_process_id("ntvdm.exe");
}

void kill_error_report()
{
  DWORD pid;
  do {
    if((pid = get_process_id("dwwin.exe"))!=0) {
      fprintf(stderr," -- with error report (pid: %ld)\n",pid);
      HANDLE hProcess = OpenProcess( PROCESS_ALL_ACCESS, FALSE, pid);
      if(hProcess!=NULL) {
	TerminateProcess(hProcess, 0);
	Sleep(500);
	while(get_process_id("dwwin.exe")==pid) {
	  fprintf(stderr,"wait for dwwin.exe to die...\n");
	  Sleep(500);
	}
      } else
	fprintf(stderr,"do not have permission (%d)\n",
		GetLastError());
    }
  } while(get_process_id("dwwin.exe")!=0);
}

void wait_dialog()
{
  kill_error_report();
  if(check_ntvdm_dialog()) {
    fprintf(stderr,"Some dialog opens; please MANUALLY kill it.");
    fflush(stderr);
    do {
      Sleep(1000);
    } while(check_ntvdm_dialog());
    fprintf(stderr,"... done\n");
  }
}

void setstartupinfo(STARTUPINFO *si, char *inname, char *outname)
{
  SECURITY_ATTRIBUTES sa;

  ZeroMemory(&sa, sizeof(sa));
  sa.nLength = sizeof(SECURITY_ATTRIBUTES);
  sa.lpSecurityDescriptor = NULL;
  sa.bInheritHandle = TRUE;
  
  si->dwFlags = STARTF_USESTDHANDLES;
  if((inname!=0) && (strcmp(inname,"-")!=0)) {
    si->hStdInput = CreateFile(inname,
			       FILE_READ_DATA, 
			       FILE_SHARE_READ,
			       &sa,
			       OPEN_EXISTING,
			       FILE_ATTRIBUTE_NORMAL,
			       NULL);
  } else
    si->hStdInput = NULL;
  
  if((outname!=0) && (strcmp(outname,"-")!=0)) {
    si->hStdOutput = CreateFile(outname,
				FILE_WRITE_DATA, 
				FILE_SHARE_READ,
				&sa,
				CREATE_ALWAYS,
				FILE_ATTRIBUTE_NORMAL,
				NULL);
  } else
    si->hStdOutput = NULL;
  
  si->hStdError = NULL;
}

// taken from http://msdn.microsoft.com/en-us/library/ms682050(VS.85).aspx
void PrintMemoryInfo(DWORD processID)
{
  HANDLE hProcess;
  PROCESS_MEMORY_COUNTERS pmc;

  // Print the process identifier.
  
  printf("\nProcess ID: %u\n", processID);
  
  // Print information about the memory usage of the process.
  
  hProcess = OpenProcess(PROCESS_QUERY_INFORMATION |
			 PROCESS_VM_READ,
			 FALSE,processID);
  if(hProcess == NULL)
    return;
  
  if(GetProcessMemoryInfo(hProcess, &pmc, sizeof(pmc))) {
    printf("\tPageFaultCount: %d\n",pmc.PageFaultCount);
    printf("\tPeakWorkingSetSize: %d\n", 
	   pmc.PeakWorkingSetSize);
    printf("\tWorkingSetSize: %d\n",pmc.WorkingSetSize);
    printf("\tQuotaPeakPagedPoolUsage: %d\n", 
	   pmc.QuotaPeakPagedPoolUsage);
    printf("\tQuotaPagedPoolUsage: %d\n", 
	   pmc.QuotaPagedPoolUsage);
    printf("\tQuotaPeakNonPagedPoolUsage: %d\n", 
	   pmc.QuotaPeakNonPagedPoolUsage);
    printf("\tQuotaNonPagedPoolUsage: %d\n", 
	   pmc.QuotaNonPagedPoolUsage);
    printf("\tPagefileUsage: %d\n",pmc.PagefileUsage); 
    printf("\tPeakPagefileUsage: %d\n", 
	   pmc.PeakPagefileUsage);
  }
  CloseHandle( hProcess );
}

int check_memory_usage(DWORD pid, int max_mem, int *actual_usage) {
  // modified from http://msdn.microsoft.com/en-us/library/ms682050(VS.85).aspx
  //PrintMemoryInfo(pid);
  HANDLE hProcess;
  PROCESS_MEMORY_COUNTERS pmc;

  if((max_mem==0) || (pid==0))
    return 1;

  if(pid == get_ntvdm_pid()) {
    fprintf(stderr,"ntvdm: ignored\n");
    return 1;
  }

  hProcess = OpenProcess(PROCESS_QUERY_INFORMATION |
			 PROCESS_VM_READ,
			 FALSE, pid);
  if(hProcess == NULL)
    return 1;

  int max_mem_usage = 0;
  if(GetProcessMemoryInfo(hProcess, &pmc, sizeof(pmc))) {
    max_mem_usage = pmc.PeakWorkingSetSize;
    if(pmc.PeakPagefileUsage > max_mem_usage)
      max_mem_usage = pmc.PeakPagefileUsage;
  }
  CloseHandle(hProcess);
  if(actual_usage != NULL)
    (*actual_usage) = max_mem_usage;
  return (max_mem_usage <= max_mem);
}

void report_stat(double time_used, int memory_used)
{
  fprintf(stderr,"%.4lfr%.4lfu%.4lfs%dm\n",
	  time_used,
	  time_used, (double)0, 
	  memory_used);
}

double get_process_time_usage(HANDLE hProcess)
{
  FILETIME creation_time;
  FILETIME exit_time;
  FILETIME kernel_time;
  FILETIME user_time;
  GetProcessTimes(hProcess, 
		  &creation_time,
		  &exit_time,
		  &kernel_time,
		  &user_time);

  SYSTEMTIME sys_kernel_time;
  SYSTEMTIME sys_user_time;
  FileTimeToSystemTime(&kernel_time, &sys_kernel_time);
  FileTimeToSystemTime(&user_time, &sys_user_time);

  double time_used = 
    ((sys_kernel_time.wSecond + sys_kernel_time.wMilliseconds/1000.0) +
     (sys_user_time.wSecond + sys_user_time.wMilliseconds/1000.0));
  return time_used;
}

int execute(char *exname, char *inname, char *outname, double t, int max_mem)
{
  STARTUPINFO si;
  PROCESS_INFORMATION pi;
  int ifsuccess = EXE_RESULT_OK;
  
  ZeroMemory(&si, sizeof(si));
  si.cb = sizeof(si);
  ZeroMemory(&pi, sizeof(pi));
  
  setstartupinfo(&si, inname, outname);
  
  if(!CreateProcess( NULL,  // No module name (use command line). 
		     TEXT(exname), // Command line. 
		     NULL,  // Process handle not inheritable. 
		     NULL,  // Thread handle not inheritable. 
		     TRUE,  // Set handle inheritance to FALSE. 
		     0,     // No creation flags. 
		     NULL,  // Use parent's environment block. 
		     NULL,  // Use parent's starting directory. 
		     &si,   // Pointer to STARTUPINFO structure.
		     &pi))  // Pointer to PROCESS_INFORMATION structure. 
    {
      //printf( "CreateProcess failed (%d).\n", GetLastError() );
      fprintf(stderr, "Process creation error.\n");
      report_stat(0,0);
      return EXE_RESULT_ERROR;
    }
  //fprintf(stderr,"Process ID: %ld\n",pi.dwProcessId);
  //fprintf(stderr,"time limit = %d\n",t);
  
  // checking memory usage
  // wait 0.1 sec before checking mem usage
  
  SetProcessWorkingSetSize(pi.hProcess,
			   1,
			   max_mem);
  int actual_memory_usage = 0;

  Sleep(INITIAL_WAIT_FOR_MEM_CHECK);
  if(!check_memory_usage(pi.dwProcessId,max_mem,&actual_memory_usage)) {
    // using too much memory
    fprintf(stderr,"Memory limit exceeded.\n");
    //PrintMemoryInfo(pi.dwProcessId);
    ifsuccess = EXE_RESULT_MEMORY;
  }

  //printf("PID: %d\n", pi.dwProcessId);

  if(ifsuccess != EXE_RESULT_MEMORY) {
    int based_time = (int)(t*1000) + 1 - INITIAL_WAIT_FOR_MEM_CHECK;
    bool major_timed_out = (WaitForSingleObject(pi.hProcess, 
						based_time)==WAIT_TIMEOUT);
    if(major_timed_out) {
      // wait some more for user time.
      double time_used = get_process_time_usage(pi.hProcess);
      while(time_used <= t) {
	int iter_time = 100;
	if(t - time_used < 200)
	  iter_time = 20;
	bool iter_timed_out = (WaitForSingleObject(pi.hProcess, 
						   iter_time)==WAIT_TIMEOUT);
	if(!iter_timed_out)
	  break;
	
	time_used = get_process_time_usage(pi.hProcess);
	//printf("%lf\n",time_used);
      }
      ifsuccess = EXE_RESULT_TIMEOUT;
    }
  }

  if((ifsuccess == EXE_RESULT_MEMORY) || (ifsuccess == EXE_RESULT_TIMEOUT)) {
    // Kill process, because (1) it used too much memory, or (2) time limit
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pi.dwProcessId);

    if(ifsuccess != EXE_RESULT_MEMORY)
      fprintf(stderr,"Time limit exceeded.\n");
    if(hProcess != NULL) {
      fprintf(stderr,"killing pid: %ld\n",pi.dwProcessId);
      TerminateProcess(hProcess, 0);
      wait_dialog();
    } else {
      DWORD dwNtvdmId = get_ntvdm_pid();
      fprintf(stderr,"killing (ntvdm) pid: %ld\n",dwNtvdmId);
      if(dwNtvdmId!=0) {
	hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwNtvdmId);
	TerminateProcess(hProcess, 0);
      } else {
        fprintf(stderr,"killing process error\n");
      }
      
      if(get_ntvdm_pid()!=0) {
	fprintf(stderr,"killing error, ntvdm.exe still remains;");
	fprintf(stderr,"please MANUALLY kill it.");
	fflush(stderr);
	do {
	  Sleep(1000);
	} while(get_ntvdm_pid()!=0);
	fprintf(stderr,"... done\n");
	wait_dialog();
      }
    }
    if(ifsuccess != EXE_RESULT_MEMORY)
      ifsuccess = EXE_RESULT_TIMEOUT;
  }

  // check memory after terminated
  if((ifsuccess==EXE_RESULT_OK) && 
     (!check_memory_usage(pi.dwProcessId,max_mem, &actual_memory_usage))) {
    // using too much memory
    ifsuccess = EXE_RESULT_MEMORY;
  }

  // check return code
  if(ifsuccess==EXE_RESULT_OK) {
    DWORD exitcode;
    GetExitCodeProcess(pi.hProcess, &exitcode);
    if(exitcode!=0) {
      fprintf(stderr,"Exit status %d.\n", (int)exitcode);
      ifsuccess = EXE_RESULT_ERROR;
    }
  }

  wait_dialog();

  if(si.hStdInput!=NULL)
    CloseHandle(si.hStdInput);
  if(si.hStdOutput!=NULL)
    CloseHandle(si.hStdOutput);

  if(ifsuccess==EXE_RESULT_OK)
    fprintf(stderr,"OK\n");
  else if(ifsuccess==EXE_RESULT_TIMEOUT)
    fprintf(stderr,"Time limit exceeded.\n");
  else if(ifsuccess==EXE_RESULT_MEMORY)
    fprintf(stderr,"Memory limit exceeded.\n");

  double actual_time_usage = get_process_time_usage(pi.hProcess);
  /*
  if(ifsuccess==EXE_RESULT_TIMEOUT)
    actual_time_usage = t+1;
  else
    actual_time_usage = t;
  */

  report_stat(actual_time_usage,
	      (actual_memory_usage + 1023)/1024);
  
  return ifsuccess;
}

