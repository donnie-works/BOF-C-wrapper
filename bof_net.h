#ifndef PYNET_BOF_NET_H
#define PYNET_BOF_NET_H

/*
* bof_net.h - Network DFR imports and iphlpapi structs for PyNet BOFs
*
* Include AFTER bof.h (which includes winsock2.h for structs)
* This provides DFR macros to redirect socket functions to WS2_32$xxx
*/

// ============================================================================
// WS2_32 DFR Declarations and Macros
// ============================================================================
// These override winsock2.h function declarations with DFR versions

// DFR declarations
DECLSPEC_IMPORT int WINAPI WS2_32$WSAStartup(WORD, LPWSADATA);
DECLSPEC_IMPORT int WINAPI WS2_32$WSACleanup(void);
DECLSPEC_IMPORT int WINAPI WS2_32$WSAGetLastError(void);
DECLSPEC_IMPORT SOCKET WINAPI WS2_32$socket(int, int, int);
DECLSPEC_IMPORT int WINAPI WS2_32$connect(SOCKET, const struct sockaddr*, int);
DECLSPEC_IMPORT int WINAPI WS2_32$send(SOCKET, const char*, int, int);
DECLSPEC_IMPORT int WINAPI WS2_32$recv(SOCKET, char*, int, int);
DECLSPEC_IMPORT int WINAPI WS2_32$closesocket(SOCKET);
DECLSPEC_IMPORT int WINAPI WS2_32$select(int, fd_set*, fd_set*, fd_set*, const struct timeval*);
DECLSPEC_IMPORT int WINAPI WS2_32$ioctlsocket(SOCKET, long, u_long*);
DECLSPEC_IMPORT u_short WINAPI WS2_32$htons(u_short);
DECLSPEC_IMPORT u_long WINAPI WS2_32$htonl(u_long);
DECLSPEC_IMPORT u_short WINAPI WS2_32$ntohs(u_short);
DECLSPEC_IMPORT u_long WINAPI WS2_32$ntohl(u_long);
DECLSPEC_IMPORT int WINAPI WS2_32$bind(SOCKET, const struct sockaddr*, int);
DECLSPEC_IMPORT int WINAPI WS2_32$listen(SOCKET, int);
DECLSPEC_IMPORT SOCKET WINAPI WS2_32$accept(SOCKET, struct sockaddr*, int*);
DECLSPEC_IMPORT int WINAPI WS2_32$getsockname(SOCKET, struct sockaddr*, int*);
DECLSPEC_IMPORT int WINAPI WS2_32$getpeername(SOCKET, struct sockaddr*, int*);
DECLSPEC_IMPORT int WINAPI WS2_32$setsockopt(SOCKET, int, int, const char*, int);
DECLSPEC_IMPORT int WINAPI WS2_32$getsockopt(SOCKET, int, int, char*, int*);
DECLSPEC_IMPORT int WINAPI WS2_32$shutdown(SOCKET, int);

// Macros to redirect function calls to DFR versions
// These MUST come after including bof.h/winsock2.h
#undef WSAStartup
#undef WSACleanup
#undef WSAGetLastError
#undef socket
#undef connect
#undef send
#undef recv
#undef closesocket
#undef select
#undef ioctlsocket
#undef htons
#undef htonl
#undef ntohs
#undef ntohl
#undef bind
#undef listen
#undef accept
#undef getsockname
#undef getpeername
#undef setsockopt
#undef getsockopt
#undef shutdown

#define WSAStartup WS2_32$WSAStartup
#define WSACleanup WS2_32$WSACleanup
#define WSAGetLastError WS2_32$WSAGetLastError
#define socket WS2_32$socket
#define connect WS2_32$connect
#define send WS2_32$send
#define recv WS2_32$recv
#define closesocket WS2_32$closesocket
#define select WS2_32$select
#define ioctlsocket WS2_32$ioctlsocket
#define htons WS2_32$htons
#define htonl WS2_32$htonl
#define ntohs WS2_32$ntohs
#define ntohl WS2_32$ntohl
#define bind WS2_32$bind
#define listen WS2_32$listen
#define accept WS2_32$accept
#define getsockname WS2_32$getsockname
#define getpeername WS2_32$getpeername
#define setsockopt WS2_32$setsockopt
#define getsockopt WS2_32$getsockopt
#define shutdown WS2_32$shutdown

// ============================================================================
// iphlpapi Structs (not in winsock2.h)
// ============================================================================

// Constants
#ifndef MAX_HOSTNAME_LEN
#define MAX_HOSTNAME_LEN               128
#endif
#ifndef MAX_DOMAIN_NAME_LEN
#define MAX_DOMAIN_NAME_LEN            128
#endif
#define MAX_SCOPE_ID_LEN               256
#define MAX_ADAPTER_NAME_LENGTH        256
#define MAX_ADAPTER_DESCRIPTION_LENGTH 128
#define MAX_ADAPTER_ADDRESS_LENGTH     8

// Adapter types
#define MIB_IF_TYPE_ETHERNET  6
#define MIB_IF_TYPE_WIFI      71
#define MIB_IF_TYPE_LOOPBACK  24
#define MIB_IF_TYPE_PPP       23

// Table class enum values
#define TCP_TABLE_OWNER_PID_ALL 5
#define UDP_TABLE_OWNER_PID     1

#ifndef ANY_SIZE
#define ANY_SIZE 1
#endif

// Structs
typedef struct {
	char String[16];
} IP_ADDRESS_STRING, IP_MASK_STRING;

typedef struct _IP_ADDR_STRING {
	struct _IP_ADDR_STRING* Next;
	IP_ADDRESS_STRING IpAddress;
	IP_MASK_STRING IpMask;
	DWORD Context;
} IP_ADDR_STRING, *PIP_ADDR_STRING;

typedef struct _FIXED_INFO {
	char HostName[MAX_HOSTNAME_LEN + 4];
	char DomainName[MAX_DOMAIN_NAME_LEN + 4];
	PIP_ADDR_STRING CurrentDnsServer;
	IP_ADDR_STRING DnsServerList;
	UINT NodeType;
	char ScopeId[MAX_SCOPE_ID_LEN + 4];
	UINT EnableRouting;
	UINT EnableProxy;
	UINT EnableDns;
} FIXED_INFO, *PFIXED_INFO;

typedef struct _IP_ADAPTER_INFO {
	struct _IP_ADAPTER_INFO* Next;
	DWORD ComboIndex;
	char AdapterName[MAX_ADAPTER_NAME_LENGTH + 4];
	char Description[MAX_ADAPTER_DESCRIPTION_LENGTH + 4];
	UINT AddressLength;
	BYTE Address[MAX_ADAPTER_ADDRESS_LENGTH];
	DWORD Index;
	UINT Type;
	UINT DhcpEnabled;
	PIP_ADDR_STRING CurrentIpAddress;
	IP_ADDR_STRING IpAddressList;
	IP_ADDR_STRING GatewayList;
	IP_ADDR_STRING DhcpServer;
	BOOL HaveWins;
	IP_ADDR_STRING PrimaryWinsServer;
	IP_ADDR_STRING SecondaryWinsServer;
} IP_ADAPTER_INFO, *PIP_ADAPTER_INFO;

// TCP state constants
#define MIB_TCP_STATE_CLOSED     1
#define MIB_TCP_STATE_LISTEN     2
#define MIB_TCP_STATE_SYN_SENT   3
#define MIB_TCP_STATE_SYN_RCVD   4
#define MIB_TCP_STATE_ESTAB      5
#define MIB_TCP_STATE_FIN_WAIT1  6
#define MIB_TCP_STATE_FIN_WAIT2  7
#define MIB_TCP_STATE_CLOSE_WAIT 8
#define MIB_TCP_STATE_CLOSING    9
#define MIB_TCP_STATE_LAST_ACK   10
#define MIB_TCP_STATE_TIME_WAIT  11
#define MIB_TCP_STATE_DELETE_TCB 12

typedef struct _MIB_TCPROW_OWNER_PID {
	DWORD dwState;
	DWORD dwLocalAddr;
	DWORD dwLocalPort;
	DWORD dwRemoteAddr;
	DWORD dwRemotePort;
	DWORD dwOwningPid;
} MIB_TCPROW_OWNER_PID, *PMIB_TCPROW_OWNER_PID;

// TCP Table
typedef struct _MIB_TCPTABLE_OWNER_PID {
	DWORD dwNumEntries;
	MIB_TCPROW_OWNER_PID table[ANY_SIZE];
} MIB_TCPTABLE_OWNER_PID, *PMIB_TCPTABLE_OWNER_PID;

// UDP Table
typedef struct _MIB_UDPROW_OWNER_PID {
	DWORD dwLocalAddr;
	DWORD dwLocalPort;
	DWORD dwOwningPid;
} MIB_UDPROW_OWNER_PID, *PMIB_UDPROW_OWNER_PID;

typedef struct _MIB_UDPTABLE_OWNER_PID {
	DWORD                dwNumEntries;
	MIB_UDPROW_OWNER_PID table[ANY_SIZE];
} MIB_UDPTABLE_OWNER_PID, *PMIB_UDPTABLE_OWNER_PID;

#endif /* PYNET_BOF_NET_H */
