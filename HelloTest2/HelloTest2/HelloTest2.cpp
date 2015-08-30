// HelloTest2.cpp : Defines the entry point for the console application.
//



#include "stdafx.h"
#include "HelloTest2.h"


/*
	Constructor
*/
PacketFilter::PacketFilter()
{
	try
	{
		m_hEngineHandle = NULL;
		::ZeroMemory(&m_subLayerGUID, sizeof(GUID));


	}
	catch (...)
	{
		printf("\nPacketFilter instance created\n");
	}
}

/*
	Destructor
*/
PacketFilter::~PacketFilter()
{
	try
	{
		StopPacketSniffer();
	}
	catch (...)
	{
	}
}

/*
	ParseIPAddrString is a utility method
	This method was not written by our team and copied from an online source
*/
bool PacketFilter::ParseIPAddrString(char* szIpAddr, UINT nStrLen, BYTE* pbHostOrdr, UINT nByteLen, ULONG& uHexAddr)
{
	bool bRet = true;
	try
	{
		UINT i = 0;
		UINT j = 0;
		UINT nPack = 0;
		char szTemp[2];

		// Build byte array format from string format.
		for (; (i < nStrLen) && (j < nByteLen); )
		{
			if ('.' != szIpAddr[i])
			{
				::StringCchPrintf(szTemp, 2, "%c", szIpAddr[i]);
				nPack = (nPack * 10) + ::atoi(szTemp);
			}
			else
			{
				pbHostOrdr[j] = nPack;
				nPack = 0;
				j++;
			}
			i++;
		}
		if (j < nByteLen)
		{
			pbHostOrdr[j] = nPack;

			// Build hex format from byte array format.
			for (j = 0; j < nByteLen; j++)
			{
				uHexAddr = (uHexAddr << 8) + pbHostOrdr[j];
			}
		}
		printf("\nPacketFilter instance created\n");
	}
	catch (...)
	{
		printf("\nPacketFilter instance created\n");
	}
	return bRet;
}


// checkout difference in bool vs BOOL

void PacketFilter::AddToBlockList(char* szIpAddrToBlock)
{
	try
	{
		if (szIpAddrToBlock != NULL)
		{
			IPFILTERINFO stIPFilter = { 0 };
			// Aggregate initialization:
			// An aggregate is an array or a class with no user-declared constructors
			
			// convert char to byte n hex
			ParseIPAddrString(szIpAddrToBlock,
				::lstrlen(szIpAddrToBlock),
				stIPFilter.bIpAddrToBlock,
				BYTE_IPADDR_ARRLEN,
				stIPFilter.uHexAddrToBlock);

			// push ip addr into list
			m_lstFilters.push_back(stIPFilter);

		}
	}
	catch (...)
	{
	}
}

DWORD PacketFilter::BindUnbindInterface(bool bBind)
{
	DWORD dwFwAPIRETCode = ERROR_BAD_COMMAND;

	try
	{
		if (bBind)
		{
			// the handler returned from fwmpengineopen0 defined as the "interface"
			// 2. Next interface must be bound to a sublayer that is attached to the engine using FwpmSubLayeradd0
			printf("\nUnbind Break 1\n");
			RPC_STATUS rpcStatus = { 0 };

			// The FWPM_SUBLAYER0 structure stores the state associated with a sublayer.
			FWPM_SUBLAYER0 SubLayer = { 0 };

			// Sublayer is given a GUID for any future operations providing the program a way to identify 
			// the sublayer from any others implemented in the engine

			rpcStatus = ::UuidCreate(&SubLayer.subLayerKey);

			// need to add "Fwpuclnt.lib Rpcrt4.lib" to Linker
			printf("\nUnbind break 2\n");
			if (rpcStatus == NO_ERROR)
			{

				// save GUID
				::CopyMemory(&m_subLayerGUID,
					&SubLayer.subLayerKey,
					sizeof(SubLayer.subLayerKey));
				
				// FWPM_ACTRL_ADD_LINK

				printf("\nUnbind Break 3\n");
				// Populate packet filter layer information.
				SubLayer.displayData.name = L"MyFirewallSublayer";
				SubLayer.displayData.description = L"My filter sublayer";
				SubLayer.flags = 0;
				SubLayer.weight = 0x100;

				dwFwAPIRETCode = ::FwpmSubLayerAdd0(m_hEngineHandle,
													&SubLayer,
													NULL);
				if (dwFwAPIRETCode != ERROR_SUCCESS)
				{
					printf("\nFwpmSubLayerAdd failed (%d).\n", dwFwAPIRETCode);
				}
				printf("\nUnbind Break 4\n");
			}
		}
		else
		{
			//dwFwAPIRETCode = ::FwpmSubLayerDeleteByKey0(m_hEngineHandle,
				//										&m_subLayerGUID);

			//::ZeroMemory(&m_subLayerGUID, sizeof(GUID));
		}
	}
	catch(...)
	{ 
		printf("\nUnbind Break 6\n");
	}
	printf("\nUnbind Break 5: %X\n", dwFwAPIRETCode);
	
	return dwFwAPIRETCode;
}

DWORD PacketFilter::CreateDeleteInterface(bool bCreate)
{
	DWORD dwFwAPIRetCode = ERROR_BAD_COMMAND;
	try
	{
		if (bCreate)
		{
			// if session.flags is set to FWPM_SESSION_FLAG_DYNAMIC, any WFP objects added during the
			// session are automatically deleted when the session ends.
			// Else, the caller needs to explictily delete all WP objects added during the session
			
			FWPM_SESSION0 session;
			memset(&session, 0, sizeof(session));
			session.flags = FWPM_SESSION_FLAG_DYNAMIC;


			// 1. Program must open a session with the filtering engine by calling FwpmEngineOpen0, which returns a handle to the engine.
			//	  The handle is some obscure reference to the engine : interface to the engine.
			//	  Declared within the PacketFilter class :: HANDLE m_hEngineHandle;
			dwFwAPIRetCode = ::FwpmEngineOpen0(NULL,
				RPC_C_AUTHN_WINNT,
				NULL,
				&session,
				&m_hEngineHandle);

			printf("\nCreateDeleteInterface (%d).\n", dwFwAPIRetCode);
		}
		else
		{
			if (m_hEngineHandle != NULL)
			{
				dwFwAPIRetCode = ::FwpmEngineClose0(m_hEngineHandle);
				m_hEngineHandle = NULL;
			}
		}
	}
	catch(...)
	{ }
	

	return dwFwAPIRetCode;

}
/*
	AddRemoveFilter
	try
		if(true)
			add filters
		else 
			delete filters
	catch

*/

DWORD PacketFilter::AddRemoveFilter(bool bAdd)
{
	DWORD dwFwAPiRetCode = ERROR_BAD_COMMAND;

	try
	{
		if (bAdd)
		{
			FWPM_FILTER0 filter = { 0 };


			filter.displayData.name = L"WFPSampler's basic scenario filter";
			filter.flags = FWPM_FILTER_FLAG_NONE;
			filter.layerKey = FWPM_LAYER_INBOUND_TRANSPORT_V4;
			filter.subLayerKey = m_subLayerGUID;

		}
	}
	catch (...)
	{	}
	
	return dwFwAPiRetCode;
}


BOOL PacketFilter::StartPacketSniffer()
{

	BOOL bStarted = FALSE;
	try
	{
		// Create packet filter interface
		if (CreateDeleteInterface(true) == ERROR_SUCCESS)
		{

			// Bind to packet filter interface
			if (BindUnbindInterface(true) == ERROR_SUCCESS)
			{
				printf("\Start Firewall 2\n");
				AddRemoveFilter(true);
				bStarted = TRUE;
			}
		}
	}
	catch (...)
	{
	}
	return bStarted;
}

BOOL PacketFilter::StopPacketSniffer()
{
	BOOL bSTopped = FALSE;

	return TRUE;
}

int main()
{
	printf("hello world\n");



	PacketFilter pktFilter;


	//pktFilter.AddToBlockList("192.167.0.1");

	if (pktFilter.StartPacketSniffer())
	{
		printf("\nNetwork Sniffer started.. \n");
	}
	else
	{
		printf("\nError starting the Network sniffer. GetLastError() 0x%x", ::GetLastError());
	}
	

	getch();
	return 0;

}

