//https://msdn.microsoft.com/en-us/library/aa366050(VS.85).aspx
//https://msdn.microsoft.com/en-us/library/windows/desktop/aa366053(v=vs.85).aspx
//program przyjmuje argumenty z CMD

#include <winsock2.h>
#include <iphlpapi.h>
#include <icmpapi.h>
#include <stdio.h>
#include <conio.h>
#include <iostream>
#include <string>
#include <fstream>
#include <ctime>
#include <sstream>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")



std::string getCurrentDateTime();
int __cdecl ping(char *Adress, int tests = 1);
void ReplyInterpreter(ULONG & Reply);

void main()
{
	std::cout << "Ping! Ip:";
	char Adress[80];
	std::cin >> Adress;
	std::cout << Adress << " at " << &Adress << std::endl;
	std::cout << "Amount of tries: ";
	int amountoftries = 0;
	std::cin >> amountoftries;
	//ping(Adress, amountoftries);  
	std::cout << ping(Adress);
	//std::cout << getCurrentDateTime();
	_getch();
	return;
}

int __cdecl ping(char *Adress, int tests)
{ //
	 // Declare and initialize variables
	HANDLE hIcmpFile;
	unsigned long ipaddr = INADDR_NONE;
	DWORD dwRetVal = 0;
	char SendData[32] = "Data Buffer";
	LPVOID ReplyBuffer = NULL;
	DWORD ReplySize = 0;

	std::ofstream  outputfile;
	//todo - utworzenie pliku lub dopisanie danych.

	ipaddr = inet_addr(Adress);
	if (ipaddr == INADDR_NONE) {
		printf("usage: %s IP address\n", Adress);
		return 1;
	}

	hIcmpFile = IcmpCreateFile();
	if (hIcmpFile == INVALID_HANDLE_VALUE) {
		printf("\tUnable to open handle.\n");
		printf("IcmpCreatefile returned error: %ld\n", GetLastError());
		return 1;
	}

	ReplySize = sizeof(ICMP_ECHO_REPLY) + sizeof(SendData);
	ReplyBuffer = (VOID*)malloc(ReplySize);
	if (ReplyBuffer == NULL) {
		printf("\tUnable to allocate memory\n");
		return 1;
	}

	for (int iterator = 0; iterator < tests; iterator++)
	{
		dwRetVal = IcmpSendEcho(hIcmpFile, ipaddr, SendData, sizeof(SendData),
			NULL, ReplyBuffer, ReplySize, 1000);
		if (dwRetVal != 0) {
			PICMP_ECHO_REPLY pEchoReply = (PICMP_ECHO_REPLY)ReplyBuffer;
			struct in_addr ReplyAddr;
			ReplyAddr.S_un.S_addr = pEchoReply->Address;
			printf("\n\tSent icmp message to %s\n", Adress);
			if (dwRetVal > 1) {
				printf("\tReceived %ld icmp message responses\n", dwRetVal);
				printf("\tInformation from the first response:\n");
			}
			else {
				printf("\tReceived %ld icmp message response\n", dwRetVal);
				printf("\tInformation from this response:\n");
			}
			std::cout << "\t  " << getCurrentDateTime() << "\n";
			printf("\t  Received from %s\n", inet_ntoa(ReplyAddr));
			//printf("\t  Status = %ld\n",
				//pEchoReply->Status);
			std::cout << "\t"; ReplyInterpreter(pEchoReply->Status); std::cout << std::endl;		//added by me
			printf("\t  Roundtrip time = %ld milliseconds\n",
				pEchoReply->RoundTripTime);
		}
		else {
			printf("\tCall to IcmpSendEcho failed.\n");
			printf("\tIcmpSendEcho returned error: %ld\n", GetLastError());
			return 1;
		}
	};
	return 0;
}

std::string getCurrentDateTime()
{
	std::stringstream currentDateTime;
	// current date/time based on current system
	time_t ttNow = time(0);
	tm * ptmNow;
	ptmNow = localtime(&ttNow);

	//day
	if (ptmNow->tm_mday < 10)
		currentDateTime << "0" << ptmNow->tm_mday << '-';
	else
		currentDateTime << ptmNow->tm_mday << '-';

	//month
	if (ptmNow->tm_mon < 9)
		//Fill in the leading 0 if less than 10
		currentDateTime << "0" << 1 + ptmNow->tm_mon << '-';
	else
		currentDateTime << (1 + ptmNow->tm_mon) << '-';

	//year
	currentDateTime << 1900 + ptmNow->tm_year << ' ';

	//hour
	if (ptmNow->tm_hour < 10)
		currentDateTime << "0" << ptmNow->tm_hour << ':';
	else
		currentDateTime << ptmNow->tm_hour << ':';

	//min
	if (ptmNow->tm_min < 10)
		currentDateTime << "0" << ptmNow->tm_min << ':';
	else
		currentDateTime << ptmNow->tm_min << ':';

	//sec
	if (ptmNow->tm_sec < 10)
		currentDateTime << "0" << ptmNow->tm_sec;
	else
		currentDateTime << ptmNow->tm_sec;


	return currentDateTime.str();
}

void ReplyInterpreter(ULONG & Reply)
{
	/*
	Type: ULONG

	The status of the echo request, in the form of an IP_STATUS code.
	The possible values for this member are defined in the Ipexport.h header file.

	0		IP_SUCCESS					The status was success.
	11001	IP_BUF_TOO_SMALL			The reply buffer was too small.
	11002	IP_DEST_NET_UNREACHABLE		The destination network was unreachable.
	11003	IP_DEST_HOST_UNREACHABLE	The destination host was unreachable.
	11004	IP_DEST_PROT_UNREACHABLE	The destination protocol was unreachable.
	11005	IP_DEST_PORT_UNREACHABLE	The destination port was unreachable.
	11006	IP_NO_RESOURCES				Insufficient IP resources were available.
	11007	IP_BAD_OPTION				A bad IP option was specified.
	11008	IP_HW_ERROR					A hardware error occurred.
	11009	IP_PACKET_TOO_BIG			The packet was too big.
	11010	IP_REQ_TIMED_OUT			The request timed out.
	11011	IP_BAD_REQ					A bad request.
	11012	IP_BAD_ROUTE				A bad route.
	11013	IP_TTL_EXPIRED_TRANSIT		The time to live (TTL) expired in transit.
	11014	IP_TTL_EXPIRED_REASSEM		The time to live expired during fragment reassembly.
	11015	IP_PARAM_PROBLEM			A parameter problem.
	11016	IP_SOURCE_QUENCH			Datagrams are arriving too fast to be processed and datagrams may have been discarded.
	11017	IP_OPTION_TOO_BIG			An IP option was too big.
	11018	IP_BAD_DESTINATION			A bad destination.
	11050	IP_GENERAL_FAILURE			A general failure. This error can be returned for some malformed ICMP packets.
	*/

	const std::string IP_ERROR[]
	{
		"IP_SUCCESS",
		"IP_BUF_TOO_SMALL",
		"IP_DEST_NET_UNREACHABLE",
		"IP_DEST_HOST_UNREACHABLE",
		"IP_DEST_PROT_UNREACHABLE",
		"IP_DEST_PORT_UNREACHABLE",
		"IP_NO_RESOURCES",
		"IP_BAD_OPTION",
		"IP_HW_ERROR",
		"IP_PACKET_TOO_BIG",
		"IP_REQ_TIMED_OUT",
		"IP_BAD_REQ",
		"IP_BAD_ROUTE",
		"IP_TTL_EXPIRED_TRANSIT",
		"IP_TTL_EXPIRED_REASSEM",
		"IP_PARAM_PROBLEM",
		"IP_SOURCE_QUENCH",
		"IP_OPTION_TOO_BIG",
		"IP_BAD_DESTINATION",
		"IP_GENERAL_FAILURE"
	};
	const std::string ERROR_meaning[]
	{
		"The status was success.",
		"The reply buffer was too small.",
		"The destination network was unreachable.",
		"The destination host was unreachable.",
		"The destination protocol was unreachable.",
		"The destination port was unreachable.",
		"Insufficient IP resources were available.",
		"A bad IP option was specified.",
		"A hardware error occurred.",
		"The packet was too big.",
		"The request timed out.",
		"A bad request.",
		"A bad route.",
		"The time to live (TTL) expired in transit.",
		"The time to live expired during fragment reassembly.",
		"A parameter problem.",
		"Datagrams are arriving too fast to be processed and datagrams may have been discarded.",
		"An IP option was too big.",
		"A bad destination.",
		"A general failure. This error can be returned for some malformed ICMP packets."
	};

	switch (Reply)
	{
	case 0: {std::cout << IP_ERROR[0] << " (" << ERROR_meaning[0] << ")"; }; break;
	case 11001: {std::cout << IP_ERROR[1] << " (" << ERROR_meaning[1] << ")"; }; break;
	case 11002: {std::cout << IP_ERROR[2] << " (" << ERROR_meaning[2] << ")"; }; break;
	case 11003: {std::cout << IP_ERROR[3] << " (" << ERROR_meaning[3] << ")"; }; break;
	case 11004: {std::cout << IP_ERROR[4] << " (" << ERROR_meaning[4] << ")"; }; break;
	case 11005: {std::cout << IP_ERROR[5] << " (" << ERROR_meaning[5] << ")"; }; break;
	case 11006: {std::cout << IP_ERROR[6] << " (" << ERROR_meaning[6] << ")"; }; break;
	case 11007: {std::cout << IP_ERROR[7] << " (" << ERROR_meaning[7] << ")"; }; break;
	case 11008: {std::cout << IP_ERROR[8] << " (" << ERROR_meaning[8] << ")"; }; break;
	case 11009: {std::cout << IP_ERROR[9] << " (" << ERROR_meaning[9] << ")"; }; break;
	case 11010: {std::cout << IP_ERROR[10] << " (" << ERROR_meaning[10] << ")"; }; break;
	case 11011: {std::cout << IP_ERROR[11] << " (" << ERROR_meaning[11] << ")"; }; break;
	case 11012: {std::cout << IP_ERROR[12] << " (" << ERROR_meaning[12] << ")"; }; break;
	case 11013: {std::cout << IP_ERROR[13] << " (" << ERROR_meaning[13] << ")"; }; break;
	case 11014: {std::cout << IP_ERROR[14] << " (" << ERROR_meaning[14] << ")"; }; break;
	case 11015: {std::cout << IP_ERROR[15] << " (" << ERROR_meaning[15] << ")"; }; break;
	case 11016: {std::cout << IP_ERROR[16] << " (" << ERROR_meaning[16] << ")"; }; break;
	case 11017: {std::cout << IP_ERROR[17] << " (" << ERROR_meaning[17] << ")"; }; break;
	case 11018: {std::cout << IP_ERROR[18] << " (" << ERROR_meaning[18] << ")"; }; break;
	case 11050: {std::cout << IP_ERROR[19] << " (" << ERROR_meaning[19] << ")"; }; break;
	default: {std::cout << "\n\aNo error found corresponding to " << Reply << "\n"; }break;
	};
	return;
};