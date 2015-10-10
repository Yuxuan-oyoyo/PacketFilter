


#ifndef _PACKETFILTER_H_
#define _PACKETFILTER_H_



#include <stdio.h>
#include <conio.h>

// include winsock.h before windows.h
#include <Winsock2.h>
#include <windows.h>

#include <strsafe.h>
#include <fwpmu.h>
#include <list>

// Firewall sub-layer names.
#define FIREWALL_SUBLAYER_NAME  "MyVistaFirewall"
#define FIREWALL_SUBLAYER_NAMEW "MyVistaFirewall"
#define FIREWALL_SERVICE_NAMEW  FIREWALL_SUBLAYER_NAMEW

// Byte array IP address length
#define BYTE_IPADDR_ARRLEN    4

// String format IP address length
#define STR_IPADDR_LEN        32

// Vista subnet mask
#define VISTA_SUBNET_MASK   0xffffffff

#define BYTE_IPADDR_ARRLEN	4


typedef struct _IPFILTERINFO
{
	BYTE bIpAddrToBlock[BYTE_IPADDR_ARRLEN];
	ULONG uHexAddrToBlock;
	UINT64 u64VistaFilterId;
} IPFILTERINFO, *PIPFILTERINFO;

// a variable which stores the address of another variable is a pointer
// pointers are said to "point to" the variable whose address they store.
// by preceding the pointer with a deference operator(*). the pointer can be used to access the variable they point to 
// bar = *foo
// "baz equal to value pointed too by foo"
// foo refers to an address while *foo refers to the value stored in the address

// the asterisk (*) used when declaring a pointer only means that it is a pointer
// should not be confused with the dereference operator
// they are 2 different things represented with the same sign

typedef std::list<IPFILTERINFO> IPFILTERINFOLIST;

class PacketFilter
{
	private:
		// Filtering engine handle
		HANDLE m_hEngineHandle;

		// sublayer Guid
		GUID m_subLayerGUID;

		// List of filters
		IPFILTERINFOLIST m_lstFilters;
	
		// Method to get byte array format and hex format IP address from string format
		bool ParseIPAddrString(const char* szIpAddr, UINT nStrLen, BYTE* pbHostOrdr, UINT nByteLen, ULONG &uHexAddr);

		// method to create/delete packet filter interface
		DWORD CreateDeleteInterface(bool bCreate);

		// method to bind/unbind to/from packet filter interface
		DWORD BindUnbindInterface(bool bBind);

		// method to add/remove filter
		DWORD AddTcpFilter(bool bAdd);

		// method to add RST filter
		DWORD AddRstFilter(bool bAdd);

		// method to add ICMP filter
		DWORD AddIcmpFilter(bool bAdd);

	public:
		
		// constructor
		PacketFilter();

		// destructor
		~PacketFilter();

		// method to add ip to m_lstFilters list
		void AddToBlockList(const char* szIpAddrToBlock);

		// method to start packet filter
		BOOL StartPacketSniffer(bool nt, bool rst, bool icmp);

		// method to stop packet filter
		BOOL StopPacketSniffer();
};


#endif