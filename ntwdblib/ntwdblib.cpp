#include "pch.h"

#include "ntwdblib.h"
#include <WinSock2.h>
#include <nb30.h>

//#include <excpt.h>

#pragma warning (disable : 4996)
#pragma comment(lib, "Netapi32.lib")

#define  DBCURSOR  cursor_t   // cursor record type
#define  DBHANDLE  void   // generic handle

LPSTR __cdecl GetConnectionError(PDBPROCESS dbproc, int* lpErr, char** a3);
BOOL __stdcall FreeMemory(PDBPROCESS dbproc, LPVOID lpMem);
int __stdcall GeneralError(PDBPROCESS dbproc, int dbErrCode);
LPVOID __stdcall AllocateHeapMemory(int op, PDBPROCESS dbproc, size_t dwBytes, int zero);
char* __stdcall dberrstr(unsigned __int16 dbErrCode);
BOOL __stdcall LibMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved);
void __stdcall tidyproc(PDBPROCESS dbproc);
void __stdcall free_rowbuffer(PDBPROCESS dbproc);
int __stdcall CheckEntry(PDBPROCESS dbproc);
retval_t* __stdcall ReturnRequestedRetval(PDBPROCESS dbproc, int length);
BOOL __cdecl ConvertNumericDecimalToDouble(DBNUMERIC* Src, double* lpValue);
int __stdcall bcpRead(PDBPROCESS dbproc, bcp_t* bcp, size_t Size, void* lpBuffer);
int __stdcall bcpInsert(PDBPROCESS dbproc);
int __stdcall bcpLengthConversion(char type, int length, char usertype, int direction);
char* __stdcall CursorWriteBuf(PDBPROCESS dbproc, int ColumnType, int length, void* Src);
int __cdecl PrepareFullName(PDBPROCESS dbproc, bcp_info_t* bcpinfo, int b);
int __cdecl bcpCmd(PDBPROCESS dbproc, const char* Src, ...);
int __stdcall CursorBuildKeysetSelect(DBCURSOR* hcursor);
int __stdcall CursorVerify(DBCURSOR* cursor, PDBPROCESS dbproc);
int __cdecl InitLocal(HINSTANCE hInstance);
void __cdecl clntcomn_init();
void __cdecl clntcomn_cleanup();
// Netapi32.lib


BYTE ver60[] = { 6,0,0,0,0,0,0,0 };
SecEntry g_SecEntrys = { (DBPROCESS* )-1 ,0,0};
DWORD TlsErrIndex = -1;
HANDLE hGlobalHeap = 0;
int g_fSSPIInit = 0;
char null_string[4] = { 0 };
int bDtm = 0;
short UsDefaultTimeFlags = 0;
short UsDefaultMnyFlags = 0;
HINSTANCE DbHandle = 0;
int DbTimeOut = 0;
PDBPROCESS* DbProcArray = 0;
DBERRHANDLE_PROC DbErrHandler = 0;
DBMSGHANDLE_PROC DbMsgHandler = 0;
PDBPROCESS validdbproc = 0;
short word_7335B844 = 0;
char byte_7335B848[32] = { 0 };
LPCVOID pMemMap = 0;
int debug_no_entry = 0;
CRITICAL_SECTION CriticalSection = { 0 };
HKEY hKey = 0;
PSecurityFunctionTableA g_pSecFunctionTable = 0;
CRITICAL_SECTION sspiSection = { 0 };
HMODULE hModule = 0;
DTC_GET_TRANSACTION_MANAGER fnGetTranMan = 0;
CRITICAL_SECTION ErrSem = { 0 };
CRITICAL_SECTION MsgSem = { 0 };
char DeciSep[8] = { 0 };
char SMonths[12][7] = {0};
char byte_7335B954[12] = { 0 };
CRITICAL_SECTION OptionSem = { 0 };
CRITICAL_SECTION bcpCmdSem = { 0 };
int UseClientCursors = 0;
CRITICAL_SECTION DbProcSem = { 0 };
char ThouSep[8] = { 0 };
char MnySign[32] = { 0 };
CRITICAL_SECTION UseSem = { 0 };
__int16 DTM_FORMAT = 0;
DWORD DataReadySleep = 0;
__int16 DefaultTimeFlags = 0;
char DefaultThouSep[32] = { 0 };
char TimeSep[32] = { 0 };
char szCol[32] = { 0 };
char DateSep[32] = { 0 };
char szSkip[32] = { 0 };
char TimeStrAm[32] = { 0 };
char DefaultSMonthsFE[13][7] = {0};
char DefaultDeciSep[32] = { 0 };
__int16 DefaultMnyFlags = 0;
char szRow[32] = { 0 };
char DefaultSMonths[13][7] = { 0 };
char TimeStrPm[32] = { 0 };
__int16 DefaultDateFlags = 0;
char DefaultMnySign[32] = { 0 };
int fNTIsRunning = 0;
ULONG g_cbMaxToken = 0;

char ProgVersion[] = { 1,2,0,0,0};

BYTE moneys[] = {2, 3, 0, 1};
int mnyradix[] = { 10000, 1000, 100, 10, 0 };
char DblibName[] = "MSDBLIB";
char TdsVer[] = { 4,2,0,0 };
char dbon[] = " on ";
char dboff[] = " off ";
int MonthDay[] = { 0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334, 366 };
char DefaultUsSMonths[][6] = { "Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec" };
char DefaultUsSMonthsFE[][6] = { "01","02","03","04","05","06","07","08","09","10","11","12" };
char UsDefaultDateFlags[] = "J";
char UsDefaultMnySign[] = "$";
char UsDefaultDeciSep[] = ".";
char UsDefaultThouSep[] = ",";
int ArC[] = { 6,3,5,5,6,0,0,0,0,0,0,0,0,0,0,0,0,0,0 };
int ArB[] = { 6,9,2,7,6,9,4,9,2,4,0,0,0,0,0,0,0,0,0 };
int ArA[] = { 6,5,6,0,1,7,6,7,9,4,7,4,1,8,2,0,0,0,0 };
char Offsets[][10] = {"select","from","table","order","compute","statement","procedure","execute","param"};
char ConvertArray[256] = {
	1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
	1,1,1,1,1,1,1,1,1,1,0,1,1,0,1,1,1,1,1,1,1,1,1,1,1,1,0,1,1,0,1,1,
	1,1,1,1,1,1,1,1,1,1,0,1,1,0,1,1,1,1,1,1,1,1,1,1,1,1,0,1,1,0,1,1,
	1,1,1,1,1,1,1,1,1,1,0,1,1,0,1,1,1,1,1,1,1,1,1,1,1,1,0,1,1,0,1,1,
	1,1,1,1,1,1,1,1,1,0,0,1,0,0,1,1,1,1,1,1,1,1,1,1,1,1,0,1,1,0,1,1,
	1,1,1,1,0,0,0,0,0,0,1,0,0,1,0,0,1,1,1,1,1,1,1,1,1,1,0,1,1,0,1,1,
	1,1,1,1,1,1,1,1,1,1,0,1,1,0,1,1,1,1,1,1,0,0,0,0,0,0,1,0,0,1,0,0,
	1,1,1,1,1,1,1,1,1,1,0,1,1,0,1,1,1,1,1,1,1,1,1,1,1,1,0,1,1,0,1,1
};
option_t OptionDict[] = {
	{   0, 0x11, (char*)"",           0,      0},
	{   1,    9, (char*)"offsets",    0,      0},
	{   2,    1, (char*)"rowcount",   0,      0},
	{   3,    9, (char*)"statistics", 0,      0},
	{   4,    1, (char*)"textlimit",  0,      0},
	{   5,    1, (char*)"textsize",   0,      0},
	{   6,    2, (char*)"arithabort", 0,      0},
	{   7,    2, (char*)"arithignore",0,      0},
	{   8,    2, (char*)"",           0,      0}, // CMD ?
	{   9,    2, (char*)"nocount",    0,      0},
	{  10,    2, (char*)"noexec",     0,      0},
	{  11,    2, (char*)"parseonly",  0,      0},
	{  12,    2, (char*)"showplan",   0,      0},
	{  13,    2, (char*)"procid",     0,      0},
	{  14,    2, (char*)"",           0,      0},
	{  15,    2, (char*)"",           0,      0},
	{  16,    2, (char*)"",           0,      0},
	{  18,    2, (char*)"quoted_identifier",0,0},
	{  17, 0x11, (char*)"",           0,      0}

};
const char * prtypes[] = {
	"tinyint",
	"smallint",
	"int",
	"money",
	"float",
	"datetime",
	"bit",
	"char",
	"varchar",
	"text",
	"binary",
	"varbinary",
	"image",
	"int-null",
	"datetime-null",
	"money-null",
	"float-null",
	"sum",
	"avg",
	"count",
	"min",
	"max",
	"smalldatetime",
	"smallmoney",
	"real",
	"numeric",
	"decimal"
};
const char* bcpdatatypes[] =
{
	"SQLBIT",
	"SQLINT",
	"SQLCHAR",
	"SQLFLT8",
	"SQLFLT4",
	"SQLMONEY",
	"SQLBINARY",
	"SQLMONEY4",
	"SQLTINYINT",
	"SQLSMALLINT",
	"SQLVARYCHAR",
	"SQLVARYBIN",
	"SQLDATETIME",
	"SQLDATETIM4",
	"SQLNUMERIC",
	"SQLDECIMAL"
};
const char *szAutoAnsiToOem = "AutoAnsiToOem";
const char *getansiid = "exec sp_server_info 18";
const char *VersionString = "select @@version";
const char* MicrosoftVersionString = "select @@microsoftversion";
const char *szSqlLocalizationFile = "SqlLocalizationFile";
LPCSTR FunctionName[] =
{
	"ConnectionObjectSize",
	"ConnectionRead",
	"ConnectionWrite",
	"ConnectionTransact",
	"ConnectionWriteOOB",
	"ConnectionMode",
	"ConnectionStatus",
	"ConnectionOpen",
	"ConnectionClose",
	"ConnectionCheckForData",
	null_string,
	"ConnectionError"
};
LPCSTR DSQUERY = "DSQUERY";
int DbLoginTime = 60;
short DbMaxProcs = 25;

/*
*   dbnetlib version 10.0.19041.844
*   USHORT ConnectionObjectSize(void)
*	{
*	  return 1432;
*	}
*/

struct c_ParamStruct { // size = 0xD3C
	int c_tcpKeepAliveTim;
	int c_tcpPort;
	char c_tcpHost[256];
	char field_108[1300];
	char vendor[256]; // "QLogic"
	char c_ComputeName[1280];
	char c_szSvr[256]; // 0xB1C
	int c_currProto;
	char connect_string[256];
	char* connstr; // tcp,np,lpc,via
	char c_userProtocol[16]; // 0xD24
	BOOL fCachedInfo;// 0xD34
	BYTE field_D38;
	BYTE field_D39;
	BYTE field_D3A;
	BYTE field_D3E;
};
struct ConnectionObject {// sizeof = 0x598 (1432) 
	SOCKET socket;
	int field_4;
	int field_8;
	int field_C;
	int field_10;
	short port;
	short usNetError; 
	short usMapErrno;
	short field_1A;
	const char* funcname; // "ConnectionOpen"
	char szErrMsg[256];
	char wszErrMsg[512];
	int Credentials;
	int field_324;
	int SecContext;
	int field_32C;
	int field_330;
	int field_334;
	int field_338;
	int field_33C;
	int field_340;
	int field_344;
	int field_348;
	int field_34C;
	int field_350;
	int field_354;
	int field_358;
	BOOL fEncryptOn   ;
	BOOL fEncryptLogin;
	int field_364;
	int field_368;
	int field_36C;
	BOOL fwrapper;
	int field_374;
	/*
		"ConnectionObjectSize"
		"ConnectionRead"
		"ConnectionWrite"
		"ConnectionClose"
		"ConnectionWriteOOB"
		"ConnectionOpen"
		"ConnectionServerEnum"
		"ConnectionCheckForData"
	*/
	void** NetlibFuncs;
	int c_currProto;
	c_ParamStruct* cParams;
	BOOL gfprotAlias;
	char gszaliasParam[256];
	char field_488[256];
	int field_588;
	int field_58C;
	int field_590;
	int field_594;
};

BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
)
{
	void* lpTlsValue;

	_OSVERSIONINFOA VersionInformation;
	DWORD LastError;
	
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
	{
		InitLocal(hModule);
		fNTIsRunning = 0;
		VersionInformation.dwOSVersionInfoSize = sizeof(_OSVERSIONINFOA);
		GetVersionExA(&VersionInformation);
		if (VersionInformation.dwPlatformId == 2)
			fNTIsRunning = 1;
		if (!hGlobalHeap)
		{
			hGlobalHeap = HeapCreate(0, 0x8000u, 0); // grow heap
			if (!hGlobalHeap)
			{
				LastError = GetLastError();
				return 0;
			}
		}
		InitializeCriticalSection(&UseSem);
		InitializeCriticalSection(&ErrSem);
		InitializeCriticalSection(&MsgSem);
		InitializeCriticalSection(&DbProcSem);
		InitializeCriticalSection(&OptionSem);
		InitializeCriticalSection(&bcpCmdSem);
		clntcomn_init();
		TlsErrIndex = TlsAlloc();
		if (!TlsErrIndex || (lpTlsValue = HeapAlloc(hGlobalHeap, 0, 0x100u)) == 0)
		{
			LastError = GetLastError();
			return 0;
		}
		TlsSetValue(TlsErrIndex, lpTlsValue);
	}
	break;
	case DLL_THREAD_ATTACH:
		lpTlsValue = HeapAlloc(hGlobalHeap, 0, 0x100u);
		if (!lpTlsValue)
		{
			LastError = GetLastError();
			return 0;
		}
		TlsSetValue(TlsErrIndex, lpTlsValue);
		break;
	case DLL_THREAD_DETACH:
		lpTlsValue = TlsGetValue(TlsErrIndex);
		if (lpTlsValue)
			FreeMemory(0, lpTlsValue);
		break;
	case DLL_PROCESS_DETACH:
		DeleteCriticalSection(&UseSem);
		DeleteCriticalSection(&ErrSem);
		DeleteCriticalSection(&MsgSem);
		DeleteCriticalSection(&DbProcSem);
		DeleteCriticalSection(&OptionSem);
		DeleteCriticalSection(&bcpCmdSem);
		clntcomn_cleanup();
		if (TlsErrIndex)
		{
			lpTlsValue = TlsGetValue(TlsErrIndex);
			if (lpTlsValue)
				FreeMemory(0, lpTlsValue);
			TlsFree(TlsErrIndex);
			TlsErrIndex = 0;
		}
		if (hGlobalHeap)
		{
			HeapDestroy(hGlobalHeap);
			hGlobalHeap = 0;
		}
		break;
	}
	DbHandle = hModule;
	return TRUE;
}



BOOL __cdecl IS_N_CHAR_DBCS(const char* Src, unsigned int N)
{
	unsigned int l1; 
	unsigned int i; 

	l1 = strlen(Src) + 1;
	for (i = 0; i < N && i < l1 - 1; ++i)
	{
		if (IsDBCSLeadByte(Src[i]))
			++i;
	}
	return N < i;
}
void __cdecl memset32(uint32_t* ptr, uint32_t value, size_t num) {
	for (size_t i = 0; i < num; ++i) {
		ptr[i] = value;
	}
}
int __stdcall DbCheckConnectionForData(PDBPROCESS dbproc,int *lpDataLength)
{
	int Err;
	if (dbproc->CommLayer->ConnectionCheckForData(dbproc->conn_object, lpDataLength,&Err))
		return SUCCEED;
	if (Err)
		GeneralError(dbproc, SQLESEOF); // "Unexpected EOF from SQL Server."
	return 0;
}
int __stdcall DbOpenConnection(PDBPROCESS dbproc, LPVOID pConnObj, char* servername) {
	int result;
	assert(dbproc->CommLayer->ConnectionOpen);

	return dbproc->CommLayer->ConnectionOpen(pConnObj, servername, &result);
}
int __stdcall MyDosSleep(DWORD dwMilliseconds)
{
	Sleep(dwMilliseconds);
	return 0;
}
int __stdcall DbSleep(DWORD dwMilliseconds)
{
	return MyDosSleep(dwMilliseconds);
}

int __cdecl InitLocal(HINSTANCE hInstance)
{
	int i, j; 
	char Buffer[256]; 

	DefaultTimeFlags = 0;
	DefaultDateFlags = 0;
	DefaultMnyFlags = 0;
	for (i = 0; i < 12; ++i)
		LoadStringA(hInstance, i + 1201, DefaultSMonths[i], 6);
	for (j = 0; j < 12; ++j)
		LoadStringA(hInstance, j + 1301, DefaultSMonthsFE[j], 6);
	LoadStringA(hInstance, 1400u, Buffer, 256);
	if (!_stricmp(Buffer, "DATE_DMY"))
	{
		DefaultDateFlags |= 1u;
	}
	else if (!_stricmp(Buffer, "DATE_MDY"))
	{
		DefaultDateFlags |= 2u;
	}
	else
	{
		DefaultDateFlags |= 3u;
	}
	LoadStringA(hInstance, 1410u, Buffer, 256);
	if (!_stricmp(Buffer, "TIME_12"))
		DefaultTimeFlags = 0;
	else
		DefaultTimeFlags = 4;
	LoadStringA(hInstance, 1420u, Buffer, 256);
	if (_stricmp(Buffer, "CENT_Y2"))
		DefaultDateFlags |= 8u;
	LoadStringA(hInstance, 1430u, Buffer, 256);
	if (_stricmp(Buffer, "MFMT_SHORT"))
		DefaultDateFlags |= 0x10u;
	LoadStringA(hInstance, 1440u, Buffer, 256);
	if (!_stricmp(Buffer, "MNY_PREFIX"))
		DefaultMnyFlags = 0;
	else
		DefaultMnyFlags = 32;
	LoadStringA(hInstance, 1450u, Buffer, 256);
	if (_stricmp(Buffer, "DATE0_ON"))
		DefaultDateFlags |= 0x40u;
	LoadStringA(hInstance, 1460u, DefaultMnySign, 32);
	LoadStringA(hInstance, 1470u, DefaultDeciSep, 32);
	LoadStringA(hInstance, 1480u, DefaultThouSep, 32);
	LoadStringA(hInstance, 1490u, DateSep, 32);
	LoadStringA(hInstance, 1500u, TimeSep, 32);
	LoadStringA(hInstance, 1510u, TimeStrAm, 32);
	LoadStringA(hInstance, 1520u, TimeStrPm, 32);
	LoadStringA(hInstance, 1530u, szSkip, 32);
	LoadStringA(hInstance, 1540u, szRow, 32);
	return LoadStringA(hInstance, 1550u, szCol, 32);
}
void __cdecl uuid_init()
{
	InitializeCriticalSection(&CriticalSection);
}
void __cdecl uuid_cleanup()
{
	DeleteCriticalSection(&CriticalSection);
}
void __cdecl sspi_init()
{
	InitializeCriticalSection(&sspiSection);
}
void __cdecl sspi_cleanup()
{
	DeleteCriticalSection(&sspiSection);
}
void __cdecl clntcomn_init()
{
	uuid_init();
	sspi_init();
}
void __cdecl clntcomn_cleanup()
{
	uuid_cleanup();
	sspi_cleanup();
}

BOOL __stdcall LibMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved)
{
	void* lpTlsValue; 
	void* lpTlsValuea;
	void* lpTlsValueb;
	void* lpTlsValuec;
	struct _OSVERSIONINFOA VersionInformation; 
	DWORD LastError; 

	if (fdwReason == DLL_PROCESS_ATTACH)
	{
		InitLocal(hinstDLL);
		fNTIsRunning = 0;
		VersionInformation.dwOSVersionInfoSize = 148;
		GetVersionExA(&VersionInformation);
		if (VersionInformation.dwPlatformId == 2)
			fNTIsRunning = 1;
		if (!hGlobalHeap)
		{
			hGlobalHeap = HeapCreate(0, 0x8000u, 0); // grow heap
			if (!hGlobalHeap)
			{
				LastError = GetLastError();
				return 0;
			}
		}
		InitializeCriticalSection(&UseSem);
		InitializeCriticalSection(&ErrSem);
		InitializeCriticalSection(&MsgSem);
		InitializeCriticalSection(&DbProcSem);
		InitializeCriticalSection(&OptionSem);
		InitializeCriticalSection(&bcpCmdSem);
		clntcomn_init();
		TlsErrIndex = TlsAlloc();
		if (!TlsErrIndex || (lpTlsValue = HeapAlloc(hGlobalHeap, 0, 0x100u)) == 0)
		{
			LastError = GetLastError();
			return 0;
		}
		TlsSetValue(TlsErrIndex, lpTlsValue);
	}
	else if (fdwReason == DLL_THREAD_ATTACH) 
	{
		lpTlsValueb = HeapAlloc(hGlobalHeap, 0, 0x100u);
		if (!lpTlsValueb)
		{
			LastError = GetLastError();
			return 0;
		}
		TlsSetValue(TlsErrIndex, lpTlsValueb);
	}
	else if (fdwReason == DLL_THREAD_DETACH)
	{
			lpTlsValuec = TlsGetValue(TlsErrIndex);
			if (lpTlsValuec)
				FreeMemory(0, lpTlsValuec);
	}
	else
	{
		DeleteCriticalSection(&UseSem);
		DeleteCriticalSection(&ErrSem);
		DeleteCriticalSection(&MsgSem);
		DeleteCriticalSection(&DbProcSem);
		DeleteCriticalSection(&OptionSem);
		DeleteCriticalSection(&bcpCmdSem);
		clntcomn_cleanup();
		if (TlsErrIndex)
		{
			lpTlsValuea = TlsGetValue(TlsErrIndex);
			if (lpTlsValuea)
				FreeMemory(0, lpTlsValuea);
			TlsFree(TlsErrIndex);
			TlsErrIndex = 0;
		}
		if (hGlobalHeap)
		{
			HeapDestroy(hGlobalHeap);
			hGlobalHeap = 0;
		}
	}
	DbHandle = hinstDLL;
	return SUCCEED;
}

UINT __cdecl LoadStringLocal(HINSTANCE hInstance, unsigned __int16 uID, LPSTR lpBuffer, unsigned __int16 cchBufferMax)
{
	UINT result; 

	LoadStringA(hInstance, uID, lpBuffer, cchBufferMax);
	result = GetConsoleCP();
	if (result)
		return CharToOemA(lpBuffer, lpBuffer);
	return result;
}
BOOL __cdecl LocalAnsiToOem(PDBPROCESS dbproc, char* pSrc)
{
	UINT result; 


	if ((dbproc->ret_status & 0x400) == 0)
	{
		result = GetConsoleCP();
		if (!result)
			return CharToOemA(pSrc, pSrc);
	}
	return 0;
}
int __stdcall dbzero(void* pbuf, unsigned int Size)
{
	int result; 

	result = 0;
	memset(pbuf, 0, Size);
	return result;
}
int __stdcall DbCloseConnection(PDBPROCESS dbproc)
{
	int lpReturn; 
	if(dbproc->CommLayer->ConnectionClose)
		return dbproc->CommLayer->ConnectionClose(dbproc->conn_object, &lpReturn);
	return 0;
}
int __stdcall DBKillConnection(PDBPROCESS dbproc)
{
	int result;

	if (dbproc)
	{
		if (dbproc->conn_object)
			result = DbCloseConnection(dbproc);
		dbproc->bclosed = 1;
	}
	return result;
}
int __stdcall dbdoerror(PDBPROCESS dbproc, int NetlibErrCode, int dbErrCode, DWORD LastError, char* lpErrString)
{
	char* p; 
	unsigned int len; 
	char* HeapMemory; 
	char* perrStr; 
	char* strBuf; 

	void* lpTlsValue; 
	int retCode; 
	int bSucc; 
	char* ppStr; 
	int result; 
	unsigned int L;
	int nError = LastError;

	ppStr = 0;
	result = 1;
	bSucc = 0;
	DBERRHANDLE_PROC errHandler = 0;
	DBERRHANDLE_PROC process = 0;
	if (!TlsGetValue(TlsErrIndex))
	{
		lpTlsValue = HeapAlloc(hGlobalHeap, 0, 0x100u);
		if (!lpTlsValue)
		{
			nError = GetLastError();
			return 2;
		}
		TlsSetValue(TlsErrIndex, lpTlsValue);
	}
	if (NetlibErrCode == NE_E_NETBUSY && dbproc && !lpErrString)
	{
		lpErrString = GetConnectionError(dbproc, &nError, &ppStr);
		if (ppStr && !*ppStr)
			ppStr = 0;
	}
	else if (nError != -1)
	{
		ppStr = dberrstr(nError);
	}
	if (dbproc && !dbproc->field_196)
		return 2;
	if (dbproc && dbproc->err_handler && !DbErrHandler || dbproc && dbproc->err_handler && DbErrHandler)
		process = dbproc->err_handler;
	else
		errHandler = DbErrHandler;
	if (lpErrString)
	{
		if (NetlibErrCode == NE_E_NETBUSY)
		{
			HeapMemory = (char*)AllocateHeapMemory(3, dbproc, strlen(lpErrString) + 1, 1);
			if (HeapMemory)
			{
				strcpy(HeapMemory, lpErrString);
				lpErrString = HeapMemory;
				bSucc = 1;
			}
		}
	}
	perrStr = dberrstr(dbErrCode);
	if (perrStr)
		len = strlen(perrStr);
	else
		len = 0;
	L = len;
	if (lpErrString)
		len = strlen(lpErrString);
	else
		len = 0;
	L += len;
	if (NetlibErrCode == NE_E_NETBUSY && (strBuf = (char*)AllocateHeapMemory(3, dbproc, L + 2, 1)) != 0)
	{
		if (perrStr)
			strcpy(strBuf, perrStr);
		if (lpErrString)
		{
			if (perrStr)
				strcat(strBuf, " ");
			strcat(strBuf, lpErrString);
			if (bSucc)
				FreeMemory(0, lpErrString);
		}
	}
	else
	{
		if (lpErrString)
			p = lpErrString;
		else
			p = perrStr;
		strBuf = p;
		result = 0;
	}
	if (dbproc && dbproc->last_err_handler && dbproc->last_err_handler(dbproc, NetlibErrCode, dbErrCode, nError, strBuf, ppStr) == 1)
	{
		if (result)
			FreeMemory(0, strBuf);
		return 2;
	}
	else if (errHandler || process)
	{
		if (errHandler)
			retCode = errHandler(dbproc, NetlibErrCode, dbErrCode, nError, strBuf, ppStr);
		else
			retCode = process(dbproc, NetlibErrCode, dbErrCode, nError, strBuf, ppStr);
		if (result)
			FreeMemory(0, strBuf);
		return retCode;
	}
	else
	{
		if (result)
			FreeMemory(0, strBuf);
		return 2;
	}
}
int __stdcall GeneralError(PDBPROCESS dbproc, int dbErrCode)
{
	int result = 0; 
	DWORD LastError = 0; 

	LastError = -1;
	switch (dbErrCode)
	{
	case SQLEMEM: // SQLEMEM
		LastError = 12;
		if (dbproc)
			DBKillConnection(dbproc);
		result = dbdoerror(dbproc, NE_E_NORESOURCE, dbErrCode, LastError, 0);
		break;
	case SQLENULL:
	case SQLECNOR:
	case SQLEICN:
	case 10019:
	case 10020:
	case 10021:
	case 10022:
	case 10023:
	case 10028:
	case 10029:
	case 10033:
	case 10034:
	case 10035:
	case 10036:
	case 10038:
	case 10039:
	case 10041:
	case 10042:
	case 10043:
	case 10044:
	case 10045:
	case 10046:
	case 10053:
	case 10054:
	case 10055:
	case 10056:
	case 10057:
	case 10058:
	case 10059:
	case 10060:
	case 10061:
	case 10062:
	case 10063:
	case 10064:
	case 10065:
	case 10066:
	case 10067:
	case 10068:
	case 10069:
	case 10070:
	case 10071:
	case 10072:
	case 10073:
	case 10074:
	case 10075:
	case 10076:
	case 10077:
	case 10078:
	case 10079:
	case 10080:
	case 10081:
	case 10082:
	case 10083:
	case 10084:
	case 10085:
	case 10086:
	case 10087:
	case 10088:
	case 10089:
	case 10090:
	case 10091:
	case 10092:
	case 10093:
	case 10094:
	case 10095:
	case 10096:
	case 10097:
	case 10098:
	case 10099:
	case 10100:
	case 10101:
	case 10102:
	case 10104:
	case 10105:
	case 10108:
		return dbdoerror(dbproc, NE_E_NETNOTSTARTED, dbErrCode, -1, 0);
	case SQLEPWD: // SQLEPWD  "Login incorrect."
		return dbdoerror(dbproc, NE_E_NOACCESS, dbErrCode, -1, 0);
	case SQLECONN: // SQLECONN
	case 10018: // SQLECLOS
	case 10040: // SQLENONET
	case 10110: // SQLECONNFB
		return dbdoerror(dbproc, NE_E_NETBUSY, dbErrCode, -1, 0);
	case SQLEDDNE:
	case 10049:
	case 10050:
	case 10051:
		return dbdoerror(dbproc, NE_E_NOMEMORY, dbErrCode, -1, 0);
	case SQLESMSG: // SQLESMSG
		return dbdoerror(dbproc, NE_E_TOOMANYCONN, dbErrCode, -1, 0);
	case SQLEBTOK: // SQLEBTOK "Possible network error: Bad token from SQL Server: Datastream processing out of sync."
	case SQLEREAD: // SQLEREAD
	case 10025: // SQLEWRIT
	case 10026: // SQLEMODE
	case 10027: // SQLEOOB
	case SQLESEOF: // SQLESEOF
		if (dbproc)
			DBKillConnection(dbproc);
		return dbdoerror(dbproc, NE_E_NETBUSY, dbErrCode, -1, 0);
	case SQLENSPE: // SQLENSPE
		if (dbproc)
			DBKillConnection(dbproc);
		return dbdoerror(dbproc, NE_E_NETNOTSTARTED, dbErrCode, -1, 0);
	case SQLECOFL: // SQLECOFL
	case 10016: // SQLERDCN
		return dbdoerror(dbproc, NE_E_CONNBROKEN, dbErrCode, -1, 0);
	case 10024: // SQLETIME
		return dbdoerror(dbproc, NE_E_SERVERNOTFOUND, dbErrCode, -1, 0);
	case 10103: // SQLEBWFF
		result = dbdoerror(dbproc, NE_E_NORESOURCE, dbErrCode, LastError, 0);
		break;
	case 10107: // SQLEDTC
		LastError = GetLastError();
		if (!LastError)
			LastError = -1;
		result = dbdoerror(dbproc, NE_E_NORESOURCE, dbErrCode, LastError, 0);
		break;
	default:
		result = dbdoerror(dbproc, NE_E_GENERAL, dbErrCode, LastError, 0);
		break;
	}
	return result;
}
LPVOID __stdcall AllocateHeapMemory(int op, PDBPROCESS dbproc, size_t dwBytes, int zero)
{
	LPVOID pbuf = 0; 
	int op_ = op;
	//assert(HeapValidate(hGlobalHeap, 0, 0) != 0);
	if (op_ == 4)
	{
		if (dbproc)
			op_ = 2;
		else
			op_ = 1;
	}
	if (op_ == 1 || op_ == 3)
		pbuf = HeapAlloc(hGlobalHeap, 0, dwBytes);
	else // op == 2
		pbuf = HeapAlloc(dbproc->hHeap, HEAP_NO_SERIALIZE, dwBytes);

	
	if (pbuf)
	{
		if (zero)
			dbzero(pbuf, dwBytes);
		return pbuf;
	}
	else
	{
		if (op_ == 2 || op_ == 3)
			GeneralError(dbproc, SQLEMEM);
		else
			GeneralError(0, SQLEMEM);
		return 0;
	}
}
LPVOID __stdcall ReallocMemory(PDBPROCESS dbproc, LPVOID lpMem, size_t dwBytes)
{
	if (dbproc)
		return HeapReAlloc(dbproc->hHeap, HEAP_NO_SERIALIZE, lpMem, dwBytes);
	else
		return HeapReAlloc(hGlobalHeap, 0, lpMem, dwBytes);
}
BOOL __stdcall FreeMemory(PDBPROCESS dbproc, LPVOID lpMem)
{
	if (dbproc)
		return HeapFree(dbproc->hHeap, HEAP_NO_SERIALIZE, lpMem);
	else
		return HeapFree(hGlobalHeap, 0, lpMem);
}

void* __stdcall dbmove(void* Src, void* Dst, size_t Size)
{

	if (Size && Dst)
	{
		if (Src)
			return memmove(Dst, Src, Size);
	}
	return 0;
}
void __stdcall free_tabnames(PDBPROCESS dbproc)
{
	int i = 0;
	char** lpMem = 0;

	lpMem = dbproc->tabnames;
	if (lpMem)
	{
		for (i = 0; i < dbproc->ntab; ++i)
		{
			if (lpMem[i])
				FreeMemory(dbproc, lpMem[i]);
		}
		FreeMemory(dbproc, lpMem);
		dbproc->tabnames = 0;
	}
	dbproc->ntab = 0;

}
void __stdcall free_offset(PDBPROCESS dbproc)
{
	int i = 0;
	offset_t* next = 0;
	void* lpMem = 0;
	next = dbproc->offsets;
	while (next)
	{
		lpMem = (void*)next;
		next = next->next;
		FreeMemory(dbproc, lpMem);
	}
	dbproc->offsets = 0;

}
int __stdcall CheckForValidDbproc(PDBPROCESS dbproc)
{
	int i = 0;

	EnterCriticalSection(&DbProcSem);
	if (DbProcArray)
	{
		if (dbproc == validdbproc)
		{
			LeaveCriticalSection(&DbProcSem);
			return SUCCEED;
		}
		for (i = 0; i < DbMaxProcs; ++i)
		{
			if (dbproc == DbProcArray[i])
			{
				validdbproc = dbproc;
				LeaveCriticalSection(&DbProcSem);
				return SUCCEED;
			}
		}
	}
	LeaveCriticalSection(&DbProcSem);
	return 0;
}

char* __stdcall dberrstr(unsigned __int16 dbErrCode)
{
	char* lpBuffer = 0; 

	lpBuffer = (char*)TlsGetValue(TlsErrIndex);
	LoadStringLocal(DbHandle, dbErrCode, lpBuffer, 0xFFu);
	return lpBuffer;
}
int __cdecl GetOptIndex(int index)
{
	int i = 0; 

	for (i = 0; i < 19; ++i)
	{
		if (OptionDict[i].index == index)
			return i;
	}
	return -1;
}
const char* __cdecl DBCS_STRLWR(const char* Str)
{
	int L; 
	BYTE* p = 0; 

	L = strlen(Str);
	p = (BYTE*)Str;
	while (*p && L)
	{
		if (IsDBCSLeadByte(*p))
		{
			p += 2;
			L -= 2;
		}
		else
		{
			*p = _tolower((char)*p);
			++p;
			--L;
		}
	}
	return Str;
}
int __stdcall IsOption(PDBPROCESS dbproc, int index, const char* optName)
{
	int result = 0; 
	int oIndex = 0; 
	int i = 0; 
	char szname[12] = {0};
	db_option* dbopt = 0; 

	oIndex = GetOptIndex(index);
	if (optName && *optName || (OptionDict[oIndex].optmask & 1) == 0 || (OptionDict[oIndex].optmask & 0x10) != 0)
	{
		dbopt = &dbproc->option[oIndex];
		if ((dbopt->opt & 1) != 0)
		{
			switch (index)
			{
			case 0:
				if (dbproc->nbufrow <= 1u)
					result = 0;
				else
					result = 1;
				break;
			case 1:
				if (strlen(optName) > 9)
					result = 0;
				else{
					strcpy(szname, optName);
					DBCS_STRLWR(szname);
					for (i = 0; ; ++i)
					{
						if (i >= 9)
						{
							result = 0;
							break;
						}

						if (((1 << i) & dbopt->mask) != 0 && !strcmp(Offsets[i], szname))
							break;


					}
					result = 1;
				}
				break;
			case 2:
			case 4:
			case 5:
				if (!dbopt->name || strcmp(optName, dbopt->name))
					result = 0;
				else
					result = 1;
				break;
			case 3:
				if (strlen(optName) > 9)
				{
					result = 0;
				}
				else 
				{
					strcpy(szname, optName);
					DBCS_STRLWR(szname);
					if ((dbopt->mask & 1) != 0)
					{
						if (strcmp(szname, "time"))
						{
							result = 0;

						}
						else
							result = 1;
					}
					else
					{
						if ((dbopt->mask & 2) == 0 || strcmp(szname, "io"))
							result = 0;
						else
							result = 1;
					}
				}
				break;
			case 6:
			case 7:
			case 8:
			case 9:
			case 10:
			case 11:
			case 12:
			case 13:
			case 14:
			case 15:
			case 16:
			case 17:
			case 18:
				result = 1;
				break;
			default:
				result = 0;
				break;
			}
		}
		else
		{
			return 0;
		}
	}
	else
	{
		GeneralError(dbproc, 10033);
		return 0;
	}
	return result;
}
// int (__cdecl* ConnectionClose)(void*,NETERR UNALIGNED*);
int __stdcall FreeOnError(LPVOID lpMem, PDBPROCESS dbproc)
{

	if (lpMem)
		FreeMemory(dbproc, lpMem);
	if (dbproc)
	{
		tidyproc(dbproc);
		if (DbCloseConnection(dbproc) == 1)
		{
			if (dbproc->conn_object)
				FreeMemory(0, dbproc->conn_object);
			dbproc->conn_object = 0;
			dbproc->token = 0;
			DBKillConnection(dbproc);
			if (dbproc->CommLayer)
			{
				if (dbproc->CommLayer->buffer_0)
					FreeMemory(0, dbproc->CommLayer->buffer_0);
				if (dbproc->CommLayer->buffer_1)
					FreeMemory(0, dbproc->CommLayer->buffer_1);
				FreeMemory(0, dbproc->CommLayer);
				dbproc->CommLayer = 0;
			}
		}
	}
	return 0;
}
int __stdcall SetParam(PDBPROCESS dbproc, int index, char** pparname, LPCSTR optName)
{
	int SZ = 0; 
	int idx = 0; 
	int Size = 0; 
	char* pbuf = 0; 

	SZ = strlen(optName) + 1;
	Size = SZ - 1;
	idx = GetOptIndex(index);

	if (dbproc->option[idx].name)
	{
		FreeMemory(dbproc, dbproc->option[idx].name);
		dbproc->option[idx].name = 0;
	}
	pbuf = (char*)AllocateHeapMemory(4, dbproc, SZ, 0);
	if (!pbuf)
		return FreeOnError(0, dbproc);
	dbmove((void*)optName, pbuf, Size);
	*((BYTE*)pbuf + Size) = 0;
	*pparname = pbuf;
	return SUCCEED;
}

int __stdcall SetUsDtmDefaults()
{
	char* p = 0; 
	int result = 0;
	int i = 0;

	for (i = 0; i < 12; ++i)
	{
		if (IsDBCSLeadByte(0xF0u))
			p = DefaultUsSMonthsFE[i];
		else
			p = DefaultUsSMonths[i];
		strcpy(SMonths[i], p);
	}
	DTM_FORMAT = UsDefaultMnyFlags | UsDefaultTimeFlags | *(WORD*)UsDefaultDateFlags;
	strcpy(MnySign, UsDefaultMnySign);
	strcpy(DeciSep, UsDefaultDeciSep);
	result = strlen(UsDefaultThouSep) + 1;
	qmemcpy(ThouSep, UsDefaultThouSep, result);
	return result;
}

int __stdcall SetOptionParam(PDBPROCESS dbproc, int index, const char* optname, const char* parm)
{
	char* lpMem = 0; 

	lpMem = (char*)AllocateHeapMemory(4, dbproc, 80u, 1);
	if (!lpMem)
		return 0;
	strcpy(lpMem, " set ");
	strcat(lpMem, OptionDict[GetOptIndex(index)].parmname);
	if (optname)
	{
		strcat(lpMem, " ");
		strcat(lpMem, optname);
	}
	if (parm)
		strcat(lpMem, parm);
	strcat(lpMem, " ");
	if (dbcmd(dbproc, lpMem))
	{
		FreeMemory(dbproc, lpMem);
		return SUCCEED;
	}
	else
	{
		FreeMemory(dbproc, lpMem);
		return 0;
	}
}
void __stdcall free_cmdbuffer(PDBPROCESS dbproc)
{
	void* lpMem = 0;
	buf_node_t* next = 0;

	next = dbproc->cmdbuffer;
	while (next)
	{
		if (next->data)
			FreeMemory(dbproc, next->data);
		lpMem = next;
		next = next->next;
		FreeMemory(dbproc, lpMem);
	}
	dbproc->cmdbuffer = 0;

}
void __stdcall free_rpcbuffer(PDBPROCESS dbproc)
{

	buf_node_t* cmdbuffer = 0; 

	cmdbuffer = dbproc->cmdbuffer;
	dbproc->cmdbuffer = dbproc->rpcbuffer;
	free_cmdbuffer(dbproc);

	dbproc->rpcbuffer = 0;
	dbproc->cmdbuffer = cmdbuffer;

}
int __stdcall free_options(PDBPROCESS dbproc)
{
	int result = 0; 
	int i = 0;

	for (i = 0; i < 19; ++i)
	{
		if (dbproc->option[i].name)
		{
			FreeMemory(dbproc, dbproc->option[i].name);
			dbproc->option[i].name = 0;
		}
		result = i + 1;
	}
	return result;
}

BOOL __stdcall dbWinConvToServer(PDBPROCESS dbproc, char* Source, size_t Count)
{
	BOOL result = 0;
	char* pSrc = 0; 
	char* Destination = 0; 

	if ((dbproc->option[14].opt & 1) != 0 && Count)
	{
		Destination = (char*)AllocateHeapMemory(4, dbproc, Count + 1, 1);
		strncpy(Destination, Source, Count);
		Destination[Count] = 0;
		CharToOemA(Destination, Destination);
		strncpy(Source, Destination, Count);
		result = FreeMemory(dbproc, Destination);
	}
	if ((dbproc->option[15].opt & 1) != 0)
	{
		if (Count)
		{
			pSrc = (char*)AllocateHeapMemory(4, dbproc, Count + 1, 1);
			strncpy(pSrc, Source, Count);
			pSrc[Count] = 0;
			OemToCharA(pSrc, pSrc);
			strncpy(Source, pSrc, Count);
			return FreeMemory(dbproc, pSrc);
		}
	}
	return result;
}

int __stdcall ClearOption(PDBPROCESS dbproc, int index, const char* name)
{
	int result = 0; 
	int i = 0; 
	char Str[12] = { 0 };
	db_option* opt = 0;

	if (name && *name || (OptionDict[GetOptIndex(index)].optmask & 8) == 0)
	{
		opt = &dbproc->option[GetOptIndex(index)];
		if ((opt->opt & 1) != 0 || index == 1 || index == 3)
		{
			switch (index)
			{
			case 0:
				if (dbproc->severity_level != EXINFO)
					goto LABEL_15;
				return 0;
			case 1:
				if (strlen(name) > 9)
					goto LABEL_33;
				strcpy(Str, name);
				DBCS_STRLWR(Str);
				i = 0;
				while (2)
				{
					if (i >= 9)
						goto LABEL_43;
					if (strcmp(Str, Offsets[i]))
					{
						++i;
						continue;
					}
					break;
				}
				if (((1 << i) & opt->mask) == 0)
					return 0;
				if (SetOptionParam(dbproc, index, Str, dboff))
				{
					opt->mask ^= 1 << i;
				LABEL_43:
					if (i == 9)
						goto LABEL_44;
					if (!opt->mask)
						opt->opt ^= 1u;
					goto LABEL_62;
				}
				return 0;
			case 2:
			case 4:
			case 5:
			LABEL_15:
				if (opt->name)
				{
					FreeMemory(dbproc, opt->name);
					opt->name = 0;
				}
				if (index == 4)
				{
					dbproc->textlimit_size = 4096;
				}
				else if (index)
				{
					if (!SetOptionParam(dbproc, index, "0", 0))
						return 0;
				}
				else
				{
					if (dbproc->nbufrow > 1u)
					{
						if (dbproc->rowbuffer)
							free_rowbuffer(dbproc);
					}
					dbproc->nbufrow = 0;
				}
				opt->opt ^= 1u;
				goto LABEL_62;
			case 3:
				if (strlen(name) > 4)
					goto LABEL_33;
				strcpy(Str, name);
				DBCS_STRLWR(Str);
				if (!strcmp(Str, "time"))
				{
					if ((opt->mask & 1) == 0)
						return 0;
					opt->mask ^= 1u;
					Str[4] = 0;
				}
				else
				{
					if (strcmp(Str, "io"))
					{
					LABEL_44:
						GeneralError(dbproc, 10034);
						return 0;
					}
					if ((opt->mask & 2) == 0)
						return 0;
					opt->mask ^= 2u;
					Str[2] = 0;
				}
				if (!SetOptionParam(dbproc, index, Str, dboff))
					return 0;
				if (!opt->mask)
					opt->opt ^= 1u;
				goto LABEL_62;
			case 6:
			case 7:
			case 9:
			case 10:
			case 11:
			case 12:
			case 13:
			case 18:
				if (SetOptionParam(dbproc, index, 0, dboff))
				{
					opt->opt ^= 1u;
				LABEL_62:
					result = 1;
				}
				else
				{
					result = 0;
				}
				break;
			case 8:
			case 14:
			case 15:
			case 16:
				opt->opt ^= 1u;
				goto LABEL_62;
			case 17:
				dbproc->timeout = -1;
				if (opt->name)
				{
					FreeMemory(dbproc, opt->name);
					opt->name = 0;
				}
				opt->opt ^= 1u;
				goto LABEL_62;
			default:
			LABEL_33:
				GeneralError(dbproc, 10034);
				return 0;
			}
		}
		else
		{
			return SUCCEED;
		}
	}
	else
	{
		GeneralError(dbproc, 10033);
		return 0;
	}
	return result;
}

int __stdcall SetDBOption(PDBPROCESS dbproc, int index, LPCSTR strOptValue)
{
	int result = 0; 
	ushort mask = 0; 
	int val = 0; 
	int i = 0; 
	char strTmp[12] = { 0 };
	const char* Src = 0; 
	db_option* opt = 0; 

	if (strOptValue && *strOptValue || (OptionDict[GetOptIndex(index)].optmask & 1) == 0)
	{
		opt = &dbproc->option[GetOptIndex(index)];
		switch (index)
		{
		case 0:
		case 2:
		case 4:
		case 5:
			for (Src = strOptValue; ; ++Src)
			{
				if (!*Src)
					goto LABEL_12;
				if (*Src < '0' || *Src > '9')
					break;
			}
			GeneralError(dbproc, 10034); // SQLEDBOP
			result = 0;
			break;
		default:
		LABEL_12:
			switch (index)
			{
			case 0: // DBBUFFER
				val = atoi(strOptValue);
				if (dbproc->severity_level == EXINFO)
					return 0;
				if (val >= 1)
				{
					Src = strOptValue;
				}
				else
				{
					val = 100;
					Src = "100";
				}
				if (val == 1)
				{
					GeneralError(dbproc, 10034); // SQLEDBOP
					result = 0;
					break;
				}
				if (!SetParam(dbproc, index, &opt->name, (char*)Src))
					return 0;
				opt->opt |= 1u;
				if (dbproc->nbufrow > 1u || dbproc->rowbuffer)
					free_rowbuffer(dbproc);
				dbproc->nbufrow = val;
				result = 1;
				break;
			case DBOFFSET:
				if (strlen(strOptValue) > 9)
				{
					GeneralError(dbproc, 10034); // SQLEDBOP
					result = 0;
					break;
				}
				strcpy(strTmp, strOptValue);
				DBCS_STRLWR(strTmp);
				i = 0;
				while (2)
				{
					if (i >= 9)
						goto LABEL_55;
					if (strcmp(strTmp, Offsets[i]))
					{
						++i;
						continue;
					}
					break;
				}
				if (!SetOptionParam(dbproc, index, strTmp, dbon))
					return 0;
				opt->opt |= 1u;
				opt->mask |= 1 << i;
			LABEL_55:
				if (i == 9)
					goto LABEL_56;
				result = 1;
				break;
			case DBROWCOUNT:
			case DBTEXTSIZE:
				if (atol(strOptValue) < 0)
				{
					GeneralError(dbproc, 10034); // SQLEDBOP
					result = 0;
					break;
				}
				if (!SetParam(dbproc, index, &opt->name, strOptValue))
					return 0;
				if (!SetOptionParam(dbproc, index, strOptValue, 0))
					return 0;
				opt->opt |= 1u;
				result = 1;
				break;
			case DBSTAT:
				if (strlen(strOptValue) > 4)
				{
					GeneralError(dbproc, 10034); // SQLEDBOP
					result = 0;
					break;
				}
				strcpy(strTmp, strOptValue);
				DBCS_STRLWR(strTmp);
				if (!strcmp(strTmp, "time"))
				{
					opt->mask = mask | 1;
					strTmp[4] = 0;
				}
				else
				{
					if (strcmp(strTmp, "io"))
					{
					LABEL_56:
						GeneralError(dbproc, 10034);
						return 0;
					}

					opt->mask = opt->mask | 2;
					strTmp[2] = 0;
				}
				if (!SetOptionParam(dbproc, index, strTmp, dbon))
					return 0;
				opt->opt |= 1u;
				result = 1;
				break;
			case DBTEXTLIMIT:
				val = atol(strOptValue);
				if (val < 0)
				{
					GeneralError(dbproc, 10034); // SQLEDBOP
					result = 0;
					break;
				}
				if (!SetParam(dbproc, index, &opt->name, strOptValue))
					return 0;
				dbproc->textlimit_size = val;
				opt->opt |= 1u;
				result = 1;
				break;
			case DBARITHABORT:
			case DBARITHIGNORE:
			case DBNOCOUNT:
			case DBNOEXEC:
			case DBPARSEONLY:
			case DBSHOWPLAN:
			case DBSTORPROCID:
			case DBQUOTEDIDENT:
				if (!SetOptionParam(dbproc, index, 0, dbon))
					return 0;
				opt->opt |= 1u;
				result = 1;
				break;
			case DBNOAUTOFREE:
			case DBCLIENTCURSORS:
				opt->opt |= 1u;
				result = 1;
				break;
			case DBANSItoOEM:
				opt->opt |= 1u;
				dbclropt(dbproc, 15, 0);
				result = 1;
				break;
			case DBOEMtoANSI:
				opt->opt |= 1u;
				dbclropt(dbproc, 14, 0);
				result = 1;
				break;
			case DBSETTIME:
				val = atol(strOptValue);
				if (val != -1 && val >= 1201)
				{
					GeneralError(dbproc, 10034); // SQLEDBOP
					result = 0;
					break;
				}
				if (SetParam(dbproc, index, &opt->name, strOptValue))
				{
					dbproc->timeout = val;
					opt->opt |= 1u;
					result = 1;
				}
				else
				{
					result = 0;
				}
				break;
			default:
				GeneralError(dbproc, 10034); // SQLEDBOP
				result = 0;
				break;
			}
			break;
		}
	}
	else
	{
		GeneralError(dbproc, 10033);
		return 0;
	}
	return result;
}

DBERRHANDLE_PROC __cdecl dbprocerrhandle(PDBPROCESS dbproc, DBERRHANDLE_PROC handle)
{
	if (!dbproc)
		return 0;
	if (CheckForValidDbproc(dbproc))
	{
		if (CheckEntry(dbproc))
		{
			dbproc->err_handler = handle;
			return dbproc->err_handler;
		}
		else
		{
			return 0;
		}
	}
	else if (dbproc->field_7C == 3 && dbproc->field_7D == 1)
	{
		*(DWORD*)&dbproc->dbnetlib[115] = (DWORD)handle;
		return handle;
	}
	else
	{
		return 0;
	}
}
/*
* Install a user function to handle DB-Library errors.
* 
* handler
* A pointer to the user function that will be called whenever DB-Library 
* determines that an error has occurred. 
* int err_handler(dbproc, severity, dberr, oserr, dberrstr, oserrstr)
*/
DBERRHANDLE_PROC __cdecl dberrhandle(DBERRHANDLE_PROC handle)
{
	int i = 0; 
	PDBPROCESS dbproc = 0;
	EnterCriticalSection(&ErrSem);

	DbErrHandler = handle;
	if (DbProcArray)
	{
		for (i = 0; i < DbMaxProcs; ++i)
		{
			dbproc = DbProcArray[i];
			if (dbproc && !dbproc->bclosed && dbproc->err_handler == DbErrHandler)
				dbprocerrhandle(dbproc, handle);
		}
	}
	LeaveCriticalSection(&ErrSem);
	return DbErrHandler;
}
int __cdecl dbprocmsghandle_super(PDBPROCESS dbproc, DBMSGHANDLE_PROC handler, char opt)
{
	DBMSGHANDLE_PROC proc = 0;

	if (!CheckEntry(dbproc))
		return 0;
	if (opt != 1 && opt != 2 && opt != 4)
		return 0;
	switch (opt)
	{
	case 1:
		proc = dbproc->last_msg_handler;
		dbproc->last_msg_handler = handler;
		return (int)proc;
	case 2:
		dbproc->field_19A = 0;
		return SUCCEED;
	case 4:
		dbproc->field_19A = 1;
		return SUCCEED;
	default:
		return 0;
	}
}
int __cdecl dbprocerrhandle_super(PDBPROCESS dbproc, DBERRHANDLE_PROC handler, char opt)
{
	DBERRHANDLE_PROC old = 0;

	if (!CheckEntry(dbproc))
		return 0;
	if (opt != 1 && opt != 2 && opt != 4)
		return 0;
	switch (opt)
	{
	case 1:
		old = dbproc->last_err_handler;
		dbproc->last_err_handler = handler;
		return (int)old;
	case 2:
		dbproc->field_196 = 0;
		return SUCCEED;
	case 4:
		dbproc->field_196 = 1;
		return SUCCEED;
	default:
		return 0;
	}
}
DBMSGHANDLE_PROC __cdecl dbprocmsghandle(PDBPROCESS dbproc, DBMSGHANDLE_PROC handle)
{

	if (!dbproc)
		return 0;
	if (CheckForValidDbproc(dbproc))
	{
		if (CheckEntry(dbproc))
		{
			dbproc->msg_handler = handle;
			return dbproc->msg_handler;
		}
		else
		{
			return 0;
		}
	}
	else if (dbproc->field_7C == 3 && dbproc->field_7D == 1)
	{
		*(DWORD*)&dbproc->dbnetlib[119] = (DWORD)handle;
		return handle;
	}
	else
	{
		return 0;
	}
}
/*
* Install a user function to handle server messages. 
* 
* handler
* A pointer to the user function that will be called whenever DB-Library 
* receives an error or informational message from the server. DB-Library calls
* this function with eight parameters listed in Table 2-21.
* 
* int msg_handler(dbproc, msgno, msgstate, severity, msgtext, srvname, procname, line) 
*/
DBMSGHANDLE_PROC __cdecl dbmsghandle(DBMSGHANDLE_PROC handle)
{
	int i = 0; 
	PDBPROCESS dbproc = 0;

	EnterCriticalSection(&MsgSem);

	DbMsgHandler = handle;
	if (DbProcArray)
	{
		for (i = 0; i < DbMaxProcs; ++i)
		{
			dbproc = DbProcArray[i];
			if (dbproc && !dbproc->bclosed && dbproc->msg_handler == DbMsgHandler)
				dbprocmsghandle(dbproc, handle);
		}
	}
	LeaveCriticalSection(&MsgSem);
	return DbMsgHandler;
}
int __cdecl SetDBNETLIB(char* old, char* nname, char* lpString)
{
	int result = 0; 
	char* p = 0;

	strcpy(lpString, "DBNETLIB.DLL");
	if (old)
		p = old;
	else
		p = null_string;
	result = strlen(p) + 1;
	qmemcpy(nname, p, result);
	return result;
}
/*
* SQL Server connect name
* 返回 TCP: OUMP-D,1433
*/
int __stdcall ResolveName(char* server, char* newname, char* lpLibFileName)
{
	const char* p =0 ;
	char* p1 = 0;
	BYTE* lpData = 0;
	BYTE* pSrc = 0;
	const char* pStr = 0; 
	DWORD cbData = 0; 
	int bSucc = 0; 
	LPCSTR lpValueName = 0; 
	char Buffer[32] = { 0 };
	LSTATUS result = 0; 
	HKEY phkResult = 0; 
	DWORD nSize = 0; 

	nSize = 30;
	lpValueName = server;
	*lpLibFileName = 0;
	*newname = 0;
	if (!_stricmp(server, "."))
	{
		server = null_string;
	}
	else if (GetComputerNameA(Buffer, &nSize) && !_stricmp(server, Buffer))
	{
		server = null_string;
	}
	result = RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\MSSQLServer\\Client\\ConnectTo", 0, 0x20019u, &phkResult);
	if (result == ERROR_SUCCESS)
	{
		bSucc = 0;
		result = RegQueryValueExA(phkResult, lpValueName, 0, 0, 0, &cbData);
		if (result != ERROR_SUCCESS && result != ERROR_MORE_DATA || cbData == 1)
		{
			lpValueName = DSQUERY;
			result = RegQueryValueExA(phkResult, DSQUERY, 0, 0, 0, &cbData);
			if (result == ERROR_SUCCESS || result == ERROR_MORE_DATA)
				bSucc = 1;
		}
		if (result == ERROR_SUCCESS || result == ERROR_MORE_DATA)
		{
			lpData = (BYTE*)AllocateHeapMemory(4, 0, cbData + 1, 1);
			if (!lpData)
				return 0;
			/*
			* DBMSSOCN,OUMP-D,1433
			*/
			result = RegQueryValueExA(phkResult, lpValueName, 0, 0, lpData, &cbData);
			if (result == ERROR_SUCCESS)
			{
				strcpy(lpLibFileName, "DBNETLIB");
				if (bSucc)
				{
					if (server)
						p1 = server;
					else
						p1 = null_string;
					strcpy(newname, p1);
				}
				else
				{
					lpData[cbData] = 0;
					for (pSrc = lpData; *pSrc && *pSrc != ',' && *pSrc != ' ' && *pSrc != '\r' && *pSrc != '\n'; ++pSrc)
						;
					*pSrc = 0;
					if (!_stricmp((const char*)lpData, "DBMSSPXN"))
					{
						strcpy(newname, "spx:");
					}
					else if (!_stricmp((const char*)lpData, "DBMSADSN"))
					{
						strcpy(newname, "adsp:");
					}
					else if (!_stricmp((const char*)lpData, "DBMSSOCN"))
					{
						strcpy(newname, "tcp:");
					}
					else if (!_stricmp((const char*)lpData, "DBNMPNTW"))
					{
						strcpy(newname,"np:");
					}
					else if (!_stricmp((const char*)lpData, "DBMSVINN"))
					{
						strcpy(newname, "bv:");
					}
					for (pStr = (const char*)(pSrc + 1); *pStr && *pStr == ' '; ++pStr)
						;
					if (*pStr)
						p = pStr;
					else
						p = server;
					strcat(newname, p);
				}
			}
			FreeMemory(0, lpData);
		}
		RegCloseKey(phkResult);
	}
	if (result)
		SetDBNETLIB(server, newname, lpLibFileName);
	return SUCCEED;
}
HMODULE __stdcall LoadCommLayer(char* server, void** pCommLayerFunc, char* servername, char* lpLibFileName)
{
	int i = 0; 
	HMODULE hModule = 0;

	if (!ResolveName(server, servername, lpLibFileName))
		return 0;
	hModule = LoadLibraryA(lpLibFileName);
	if (!hModule)
		return 0;
	for (i = 0; i < 12; ++i)
	{
		pCommLayerFunc[i] = GetProcAddress(hModule, FunctionName[i]);
		if (!pCommLayerFunc[i] && i < 9)
		{
			FreeLibrary(hModule);
			return 0;
		}
	}
	return hModule;
}
void __stdcall free_binds(PDBPROCESS dbproc)
{

	int i = 0; 
	if (dbproc->binds)
	{
		for (i = 0; i < dbproc->numcols; ++i)
		{
			if (dbproc->binds[i])
				FreeMemory(dbproc, dbproc->binds[i]);
		}
		FreeMemory(dbproc, dbproc->binds);

		dbproc->binds = 0;
	}

}

void __stdcall free_rowdata(PDBPROCESS dbproc, int bfreebuf)
{
	blob_t* ptxt = 0;
	BYTE* pdata = 0;
	BYTE token = 0;
	int i = 0; 

	if (dbproc->columns_data)
	{
		for (i = 0; ; ++i)
		{
			if (i >= dbproc->ncols)
				break;
			if (dbproc->columns_data[i])
			{
				token = dbproc->columns_info[i]->coltype;
				pdata = dbproc->columns_data[i]->data;
				if (pdata)
				{
					if (token == SQLTEXT || token == SQLIMAGE) // SQLTEXT , SQLIMAGE
					{
						ptxt = (blob_t*)pdata;
						if (ptxt->txptr)
							FreeMemory(dbproc, ptxt->txptr);
						if (ptxt->data)
							FreeMemory(dbproc, ptxt->data);
					}
					FreeMemory(dbproc, pdata);
				}
				dbproc->columns_data[i]->data = 0;
				dbproc->columns_data[i]->len = -1;
			}
		}
		if (bfreebuf)
		{
			free_binds(dbproc);
			for (i = 0; i < dbproc->ncols; ++i)
			{
				if (dbproc->columns_data[i])
					FreeMemory(dbproc, dbproc->columns_data[i]);
			}
			FreeMemory(dbproc, dbproc->columns_data);
			dbproc->columns_data = 0;
		}
	}

}
void __stdcall free_altrowdata(PDBPROCESS dbproc)
{

	int i = 0; 
	column_data_t** pvdata = 0;
	alt_column_data_t* lpMem = 0;

	if (dbproc->altrowdata)
	{
		for (i = 0; i < dbproc->n_compute_row; ++i)
		{
			lpMem = dbproc->altrowdata[i];
			if (lpMem && lpMem->columnsdata)
			{
				pvdata = lpMem->columnsdata;
				for (i = 0; i < lpMem->ncol; ++i)
				{
					if (pvdata[i])
					{
						if (pvdata[i]->data)
							FreeMemory(dbproc, pvdata[i]->data);
						FreeMemory(dbproc, pvdata[i]);
					}
				}
				FreeMemory(dbproc, lpMem->columnsdata);
				FreeMemory(dbproc, lpMem);
			}
		}
		FreeMemory(dbproc, dbproc->altrowdata);
	}

	dbproc->altrowdata = 0;

}
void __stdcall free_rowbuffer(PDBPROCESS dbproc)
{

	rowbuffer_t* rbuf = 0;

	if (dbproc->rowbuffer)
	{
		for (rbuf = dbproc->rowbuffer; rbuf < &dbproc->rowbuffer[dbproc->nbufrow]; ++rbuf)
		{
			dbproc->columns_data = rbuf->columnsdata;
			if (dbproc->columns_data)
				free_rowdata(dbproc, 1);
			dbproc->altrowdata = rbuf->altcoldata;
			if (dbproc->altrowdata)
				free_altrowdata(dbproc);
		}
		dbproc->columns_data = 0;
		dbproc->altrowdata = 0;
		FreeMemory(dbproc, dbproc->rowbuffer);
		dbproc->rowbuffer = 0;
	}

}
void __stdcall free_coldata(PDBPROCESS dbproc)
{

	int i = 0;

	if (dbproc->columns_info)
	{
		for (i = 0; i < dbproc->ncols; ++i)
		{
			if (dbproc->columns_info[i])
			{
				if (dbproc->columns_info[i]->format)
					FreeMemory(dbproc, dbproc->columns_info[i]->format);
				if (dbproc->columns_info[i]->actualname)
					FreeMemory(dbproc, dbproc->columns_info[i]->actualname);
				FreeMemory(dbproc, dbproc->columns_info[i]);
			}
		}
		FreeMemory(dbproc, dbproc->columns_info);
	}
	dbproc->columns_info = 0;
	if (dbproc->control_info)
	{
		FreeMemory(dbproc, dbproc->control_info);
		dbproc->control_info = 0;
	}
	dbproc->ncols = 0;

}
void __stdcall free_altcolinfo(PDBPROCESS dbproc)
{
	int i = 0;
	altcol_link_t* next = 0;

	while (dbproc->altcolinfo)
	{
		altcol_link_t* lpMem = next;
		next = next->next;
		if (lpMem->altcols)
		{

			for (i = 0; i < lpMem->n_alts; ++i)
			{
				if (lpMem->altcols[i])
				{
					if (lpMem->altcols[i]->name)
						FreeMemory(dbproc, lpMem->altcols[i]->name);
					FreeMemory(dbproc, lpMem->altcols[i]);
				}
			}
			FreeMemory(dbproc, lpMem->altcols);
		}
		if (lpMem->altbinds)
		{
			for (i = 0; i < lpMem->n_alts; ++i)
			{
				if (lpMem->altbinds[i])
					FreeMemory(dbproc, lpMem->altbinds[i]);
			}
			FreeMemory(dbproc, lpMem->altbinds);
		}
		if (lpMem->databuffer)
			FreeMemory(dbproc, (LPVOID)lpMem->databuffer);
		FreeMemory(dbproc, lpMem);
	}
	free_altrowdata(dbproc);
	dbproc->altcolinfo = 0;
	dbproc->n_compute_row = 0;

}
void __stdcall free_retvals(PDBPROCESS dbproc)
{
	int i = 0;

	if (dbproc->retvals)
	{
		for (i = 0; i < dbproc->nretval; ++i)
		{
			if (dbproc->retvals[i]->name)
				FreeMemory(dbproc, dbproc->retvals[i]->name);
			if (dbproc->retvals[i]->retlen)
				FreeMemory(dbproc, dbproc->retvals[i]->values);
			FreeMemory(dbproc, dbproc->retvals[i]);
		}
		FreeMemory(dbproc, dbproc->retvals);
		dbproc->retvals = 0;

		dbproc->numrets = 0;
		dbproc->nretval = 0;
	}

}
/*
* 整理 db_process
*/
void __stdcall tidyproc(PDBPROCESS dbproc)
{

	if (dbproc)
	{
		if (dbproc->nbufrow > 1u && dbproc->rowbuffer || dbproc->columns_data)
		{
			if (dbproc->nbufrow <= 1u)
				free_rowdata(dbproc, 1);
			else
				free_rowbuffer(dbproc);
		}
		free_coldata(dbproc);
		free_altcolinfo(dbproc);
		free_offset(dbproc);
		free_tabnames(dbproc);
		dbproc->proc_id = 0;
		if (dbproc->ordercols)
		{
			FreeMemory(dbproc, dbproc->ordercols);
			dbproc->ordercols = 0;
		}
		free_retvals(dbproc);
		if (dbproc->CommLayer)
		{
			if ((dbproc->opmask & 4) == 0)
			{
				dbzero(dbproc->CommLayer->buffer1, dbproc->CommLayer->bufsize);
				dbproc->CommLayer->packet_size = 8;
			}
		}
		dbproc->n_orders = 0;
		dbproc->nrows = 0;
		dbproc->firstrow = 0;
		dbproc->lastrow = 0;
		dbproc->currow = 0;
		dbproc->nextrowidx = 0;
		dbproc->rowidx = 0;
		dbproc->rowtype = NO_MORE_ROWS;
		dbproc->numcols = 0;
		dbproc->return_status = 0;
		dbproc->opmask &= 4u;
		dbproc->DoneRowCount = 0;
	}

}
void __cdecl swapbuffer(PDBPROCESS dbproc, __int16 size)
{

	BYTE* buffer0 = 0; 

	dbproc->CommLayer->length = size;
	dbproc->CommLayer->rbytes = 0;
	buffer0 = dbproc->CommLayer->buffer0;
	dbproc->CommLayer->buffer0 = dbproc->CommLayer->buffer1;
	dbproc->CommLayer->buffer1 = buffer0;
	dbproc->opmask &= ~4u; // and 0FBh

}
int __stdcall sendattention(PDBPROCESS dbproc)
{
	ushort Size = 0; 
	BYTE buf[8] = { 0 };
	int sta = 0; 

	buf[0] = 6;
	buf[1] = 1;
	*(ushort*)&buf[2] = 2048;
	*(ushort*)&buf[4] = 0;
	buf[6] = 1;
	buf[7] = 0;
	if (dbproc->ver >= 0x40u)
	{
		Size = 8;
	}
	else
	{
		buf[0] = 65;
		Size = 1;
	}
	if (dbproc->CommLayer->ConnectionWriteOOB(
		dbproc->conn_object,
		buf,
		Size,
		&sta) == Size)
	{
		dbproc->cmd_flag |= 2u;
		return SUCCEED;
	}
	else if (sta == SQLFLTN)
	{
		return SUCCEED;
	}
	else
	{
		GeneralError(dbproc, SQLEOOB);
		return 0;
	}
}
int __stdcall getbytes_internal(PDBPROCESS dbproc, BYTE* lpBuffer, int size)
{
	int result = 0;
	int timeout,time0 = 0; 
	ushort wbytes = 0; 
	int bufsize0,bufsize, bufsize1;
	int length = 0;
	int readsize = 0;
	int E = 0;
	int STOP = 0;
	int err,rsiz = 0;
	BYTE* pReadBuf = 0;
	while (1)
	{
		while (1)
		{
		LABEL_2:
			if (length >= size)
				return 1;
			if (dbproc->CommLayer->rbytes < (int)dbproc->CommLayer->length)
				break;
			if (size - length >= dbproc->CommLayer->bufsize)
				bufsize = dbproc->CommLayer->bufsize;
			else
				bufsize = size - length;
			bufsize1 = bufsize;
			if (!dbproc->CommLayer->wbytes)
			{
				if (bufsize <= 8u)
					bufsize0 = 8;
				else
					bufsize0 = bufsize;
				bufsize1 = bufsize0;
			}
			if (dbproc->CommLayer->status == 3 || dbproc->CommLayer->status == 1)
			{
				if (!E)
				{
					if (dbproc->CommLayer->status == 1)
						swapbuffer(dbproc, readsize);
					dbproc->CommLayer->status = 0;
				}
			LABEL_31:
				if (!E && dbproc->ver >= 0x40u && dbproc->CommLayer->field_58 != 1 && dbproc->CommLayer->field_58)
				{
					if (dbproc)
					{
						if (dbisopt(dbproc, DBSETTIME, 0))
							timeout = dbproc->timeout;
						else
							timeout = DbTimeOut;
						time0 = timeout;
					}
					else
					{
						time0 = DbTimeOut;
					}
					readsize = dbproc->CommLayer->ConnectionRead(
						dbproc->conn_object,
						dbproc->CommLayer->buffer1,
						dbproc->CommLayer->bufsize,
						dbproc->CommLayer->bufsize,
						time0,
						&E);
					dbproc->opmask |= 4u;
					dbproc->CommLayer->status = 1;
				}
				if (readsize >= size - length)
					break;
				if (E != NO_MORE_ROWS)
					goto LABEL_53;
				if (STOP)
				{
					dbproc->opmask &= ~8u;
					DBKillConnection(dbproc);
					return 0;
				}
				err = GeneralError(dbproc, 10024);
				if (err != 1)
				{
					if (err == 2)
					{
						if ((dbproc->cmd_flag & 2) == 0 && !sendattention(dbproc))
							return 0;
						dbproc->opmask |= 8u;
						STOP = 1;
					}
					else
					{
					LABEL_53:
						if (!E)
							break;
						if (STOP || E != -233 || GeneralError(dbproc, SQLESEOF) != 1 && GeneralError(dbproc, SQLEREAD) != 1)
							return 0;
					}
				}
			}
			else
			{
				dbproc->CommLayer->status = 1;
				if (dbproc)
				{
					if (dbisopt(dbproc, DBSETTIME, 0))
						time0 = dbproc->timeout;
					else
						time0 = DbTimeOut;
				}
				else
				{
					time0 = DbTimeOut;
				}
				readsize = dbproc->CommLayer->ConnectionRead(
					dbproc->conn_object,
					dbproc->CommLayer->buffer1,
					bufsize1,
					dbproc->CommLayer->bufsize,
					time0,
					&E);
				dbproc->opmask |= 4u;
				if (!readsize && E)
				{
					dbproc->CommLayer->status = 0;
					goto LABEL_31;
				}
				if (STOP)
				{
					swapbuffer(dbproc, readsize);
					dbproc->CommLayer->status = 0;
					goto LABEL_31;
				}
			}
		}
		if (dbproc->CommLayer->wbytes)
			goto LABEL_108;
		if (dbproc->CommLayer->length - dbproc->CommLayer->rbytes < 8)
		{
			if (dbproc->CommLayer->rbytes)
			{
				if (dbproc->CommLayer->length != dbproc->CommLayer->rbytes && dbproc->CommLayer->buffer0 && &dbproc->CommLayer->buffer0[dbproc->CommLayer->rbytes])
					memmove(dbproc->CommLayer->buffer0, &dbproc->CommLayer->buffer0[dbproc->CommLayer->rbytes], dbproc->CommLayer->length - dbproc->CommLayer->rbytes);
				dbproc->CommLayer->length -= dbproc->CommLayer->rbytes;
				dbproc->CommLayer->rbytes = 0;
			}
			rsiz = 8 - dbproc->CommLayer->length;
			readsize = dbproc->CommLayer->ConnectionRead(
				dbproc->conn_object,
				&dbproc->CommLayer->buffer0[dbproc->CommLayer->length],
				rsiz,
				rsiz,
				0,
				&E);
			if (!readsize && E)
			{
				if (!STOP)
					GeneralError(dbproc, SQLEREAD);
				return 0;
			}
			if (readsize < rsiz)
			{
				if (!STOP)
					GeneralError(dbproc, SQLEREAD);
				return 0;
			}
			dbproc->CommLayer->length += rsiz;
		}
		dbproc->CommLayer->field_58 = dbproc->CommLayer->buffer0[dbproc->CommLayer->rbytes + 1];
		pReadBuf = &dbproc->CommLayer->buffer0[dbproc->CommLayer->rbytes];
		if (*pReadBuf && *pReadBuf <= 31u)
		{
			if (dbproc->ver >= 0x42u)
			{
				if (dbproc->ver != 0x34 && dbproc->ver != 0x40u && dbproc->ver != 0x42u)
					dbproc->ver = 0x40u;
			}
			else
			{
				dbproc->ver = 0x40u;
			}
		}
		else
		{
			dbproc->ver = 0x34;
		}
		if (dbproc->ver >= 0x40u)
			break;
	LABEL_92:
		dbproc->CommLayer->wbytes = ((*(WORD*)&dbproc->CommLayer->buffer0[dbproc->CommLayer->rbytes + 2] << 8) | (BYTE)HIBYTE(*(WORD*)&dbproc->CommLayer->buffer0[dbproc->CommLayer->rbytes + 2]))
			- 8;
		if (dbproc->CommLayer->wbytes > dbproc->CommLayer->bufsize - 8)
		{
			if (!STOP)
				GeneralError(dbproc, SQLEREAD);
			return 0;
		}
		if (dbproc->CommLayer->length < dbproc->CommLayer->wbytes + 8)
		{
			rsiz = dbproc->CommLayer->wbytes + 8 - dbproc->CommLayer->length;
			readsize = dbproc->CommLayer->ConnectionRead(
				dbproc->conn_object,
				&dbproc->CommLayer->buffer0[dbproc->CommLayer->length],
				rsiz,
				rsiz,
				0,
				&E);

			if (!readsize && E)
			{
				if (!STOP)
					GeneralError(dbproc, SQLEREAD);
				return 0;
			}
			if (readsize < rsiz)
			{
				if (!STOP)
					GeneralError(dbproc, SQLEREAD);
				return 0;
			}
			dbproc->CommLayer->length += rsiz;
		}
		dbproc->CommLayer->rbytes += 8;
	LABEL_108:
		wbytes = dbproc->CommLayer->length - dbproc->CommLayer->rbytes;
		if (size - length <= wbytes)
			wbytes = size - length;
		if (dbproc->CommLayer->wbytes < (int)wbytes)
			wbytes = dbproc->CommLayer->wbytes;
		if (wbytes && &lpBuffer[length] && &dbproc->CommLayer->buffer0[dbproc->CommLayer->rbytes])
			memmove(&lpBuffer[length], &dbproc->CommLayer->buffer0[dbproc->CommLayer->rbytes], wbytes);
		dbproc->CommLayer->rbytes += wbytes;
		dbproc->CommLayer->wbytes -= wbytes;
		length += wbytes;
	}
	switch (*pReadBuf)
	{
	case 4u:
	case 5u:
		goto LABEL_92;
	case 0xAu:
		result = 0;
		break;
	case 0xBu:
		dbproc->cmd_flag &= ~2u;
		goto LABEL_2;
	default:
		result = 0;
		break;
	}
	return result;
}
BYTE __stdcall getbyte(PDBPROCESS dbproc, BYTE* done)
{

	int pos = 0;
	BYTE rb = 0;

	*(int*)done = 1;

	if (dbproc->CommLayer->rbytes
		&& dbproc->CommLayer->wbytes
		&& (pos = dbproc->CommLayer->rbytes,dbproc->CommLayer->length - pos >= 1))
	{
		memmove(&rb, (char*)&dbproc->CommLayer->buffer0[dbproc->CommLayer->rbytes], 1u);
		++dbproc->CommLayer->rbytes;
		--dbproc->CommLayer->wbytes;
		return rb;
	}
	else
	{
		if (!getbytes_internal(dbproc, &rb, 1))
			*(int*)done = 0;
		return rb;
	}
}

int __stdcall gettokenlen(PDBPROCESS dbproc, BYTE token, BYTE* lpBuffer)
{
	int result = 0; 
	int Size = 0;

	*(_DWORD*)lpBuffer = 0;
	if ((token & SQLINT1) == SQLINT1)
	{
		*(_DWORD*)lpBuffer = 1 << ((token & 0xC) >> 2);
	}
	else if ((token & 0x20) != 0)
	{
		if ((token & 0x80) != 0 || token == SQLCOLFMT || token == OLD_SQLCOLFMT)
			Size = 2;
		else
			Size = (token & 8) != 0 || (token & 4) != 0 ? 1 : 4;
		if (dbproc->CommLayer->rbytes
			&& Size <= dbproc->CommLayer->wbytes
			&& Size <= dbproc->CommLayer->length - dbproc->CommLayer->rbytes)
		{
			memmove(lpBuffer, &dbproc->CommLayer->buffer0[dbproc->CommLayer->rbytes], Size);
			dbproc->CommLayer->rbytes += Size;
			dbproc->CommLayer->wbytes -= Size;
			result = 1;
		}
		else
		{
			result = getbytes_internal(dbproc, (BYTE*)lpBuffer, Size);
		}
		if (!result)
			return 0;
	}
	return SUCCEED;
}
/*
<DONE>
    <TokenType>
    <BYTE>FD </BYTE>
    </TokenType>
    <Status>
    <USHORT>00 00 </USHORT>
    </Status>
    <CurCmd>
    <USHORT>00 00 </USHORT>
    </CurCmd>
    <DoneRowCount>
    <LONG>00 00 00 00 </LONG>
    </DoneRowCount>
</DONE>
*/
int __stdcall HandleDoneToken(PDBPROCESS dbproc, size_t Size, BYTE token, BYTE mask)
{
	int result = 0; 
	int* doneBuf = 0; 
	int retcode = 0;
	short val = 0;
	result = 1;

	doneBuf = (int*)AllocateHeapMemory(4, dbproc, Size, 1);
	if (!doneBuf)
	{
		FreeOnError(0, dbproc);
		return 0;
	}
	if (dbproc->CommLayer->rbytes
		&& dbproc->CommLayer->wbytes >= 8u
		&& dbproc->CommLayer->length - dbproc->CommLayer->rbytes >= 8)
	{
		memmove(doneBuf, &dbproc->CommLayer->buffer0[dbproc->CommLayer->rbytes], 8u);
		dbproc->CommLayer->rbytes += 8;
		dbproc->CommLayer->wbytes -= 8;
		retcode = 1;
	}
	else
	{
		retcode = getbytes_internal(dbproc, (BYTE*)doneBuf, 8);
	}
	if (!retcode)
	{
		FreeOnError(doneBuf, dbproc);
		return 0;
	}
	if ((*(WORD*)doneBuf & 0x80) != 0) // Status
	{
		dbproc->ret_status |= 0x20;
	}
	if ((*(WORD*)doneBuf & 0x10) != 0)
	{
		dbproc->DoneRowCount = doneBuf[1]; // DoneRowCount
		dbproc->opmask |= 1u;
	}
	else if ((mask & 2) == 0)
	{
		dbproc->opmask &= ~1u;
	}
	if ((mask & 1) == 0)
		dbproc->severity_level = 0;
	if ((*(WORD*)doneBuf & 2) != 0)
	{
		if ((*(WORD*)doneBuf & 0x10) != 0 || !doneBuf[1])
		{
			// "General SQL Server error: Check messages from the SQL Server."
			GeneralError(dbproc, SQLESMSG);
			result = 0;
		}
		else
		{
			result = 1;
			dbproc->severity_level = EXUSER;
		}
	}
	if ((*(WORD*)doneBuf & 1) == 0)
	{
		dbproc->cmd_flag &= ~0x10u;
		if ((dbproc->cmd_flag & 2) != 0)
		{
			dbproc->cmd_flag |= 8u;
			dbproc->severity_level = 0;
		}
		else
		{
			dbproc->severity_level = EXUSER;
			dbproc->cmd_flag |= 4u;
		}
	}
	if ((*(WORD*)doneBuf & 0x20) != 0)
	{
		dbproc->cmd_flag &= ~2u;
		if ((dbproc->cmd_flag & 8) != 0)
		{
			dbproc->cmd_flag &= ~8u;
			if ((mask & 1) != 0 || (*(WORD*)doneBuf & 1) == 0)
			{
				dbproc->cmd_flag |= 4u;
				dbproc->severity_level = EXUSER;
			}
			if ((mask & 1) == 1)
				dbproc->cmd_flag &= ~0x10u;
			if (!result || (mask & 1) == 1)
			{
				FreeMemory(dbproc, doneBuf);
				return result;
			}
		}
	}
	if ((*(WORD*)doneBuf & 1) != 0)
	{
		dbproc->cmd_flag |= 0x10u;
		if ((mask & 1) == 0)
		{
			dbproc->cmd_flag &= ~4u;
			if ((*(WORD*)doneBuf & 0x20) != 0 && (dbproc->cmd_flag & 8) == 0)
				dbproc->cmd_flag |= 8u;
		}
		if (token != SQLDONE)
		{
			FreeMemory(dbproc, doneBuf);
			return -5;
		}
		if (!result || (mask & 1) == 1)
		{
			FreeMemory(dbproc, doneBuf);
			return result;
		}
	}
	if (!result)
	{
		FreeMemory(dbproc, doneBuf);
		return 0;
	}
	if (dbproc->severity_level != EXUSER && ((mask & 1) != 0 || token != SQLDONE))
	{
		FreeMemory(dbproc, doneBuf);
		return -5;
	}
	FreeMemory(dbproc, doneBuf);
	if ((mask & 1) == 1)
		return 1;
	if (dbproc->nbufrow <= 1u)
		free_rowdata(dbproc, 0);
	return NO_MORE_ROWS;
}
column_data_t** __stdcall AllocateRowData(PDBPROCESS dbproc, column_data_t** rows, unsigned int row)
{
	unsigned int i; 

	for (i = 0; i < row; ++i)
	{
		rows[i] = (column_data_t*)AllocateHeapMemory(4, dbproc, 8u, 1);
		if (!rows[i])
		{
			FreeOnError(0, dbproc);
			return 0;
		}
		rows[i]->len = -1;
	}
	return rows;
}
/*
* 
COLFMT A1 length = 0x5b

	  a1 5b 00 02 00 08 00 27 3c 02 00 08 00 27  up?[.....'<....'
28 07 00 08 00 38 02 00 09 00 27 80 02 00 09 00  (....8....'�....
27 ff 06 00 08 00 34 06 00 08 00 34 06 00 08 00  '.....4....4....
34 06 00 08 00 34 01 00 08 00 2f 01 02 00 09 00  4....4..../.....
27 50 0d 00 09 00 26 02 0d 00 09 00 26 02 0d 00  'P....&.....&...
09 00 26 02 0d 00 09 00 26 02 02 00 09 00 27 28

<COLFMT>
 <TokenType>
 <BYTE>A1 </BYTE>
 </TokenType>
 <Length>
 <USHORT>05 00 </USHORT>
 </Length>
 <ColumnData>
 <UserType>
 <USHORT>07 00 </USHORT>
 </UserType>
 <Flags>
 <USHORT>08 00 </USHORT>
 </Flags>
 <TYPE_INFO>
 <FIXEDLENTYPE>
 <BYTE>38 </BYTE>
 </FIXEDLENTYPE>
 </TYPE_INFO>
 </ColumnData>
 </COLFMT>

*/
int __stdcall GetColFormat(PDBPROCESS dbproc, int Size)
{
	int result = 0;
	int I, i_1b, i_1,i_1a;
	int i = 0; 

	rowbuffer_t* prowbuffer = 0; 
	int SiZ = 0; 
	BYTE* lpMem = 0; 

	I = 0;
	i = 0;
	lpMem = (BYTE*)AllocateHeapMemory(4, dbproc, Size, 0);
	if (!lpMem)
		return FreeOnError(0, dbproc);
	if (dbproc->CommLayer->rbytes
		&& Size <= dbproc->CommLayer->wbytes
		&& Size <= dbproc->CommLayer->length - dbproc->CommLayer->rbytes)
	{
		memmove(lpMem, &dbproc->CommLayer->buffer0[dbproc->CommLayer->rbytes], Size);
		dbproc->CommLayer->rbytes += Size;
		dbproc->CommLayer->wbytes -= Size;
		result = 1;
	}
	else
	{
		result = getbytes_internal(dbproc, (BYTE*)lpMem, Size);
	}
	if (!result)
		return FreeOnError(lpMem, dbproc);

	while (true)
	{
		if (I < Size)
		{
			if (dbproc->bServerType == 1 && dbproc->ServerMajor >= 5u)
				dbmove(&lpMem[I], &dbproc->columns_info[i]->usertype, 4u);
			else
				dbproc->columns_info[i]->usertype = *(_DWORD*)&lpMem[I];
			dbproc->columns_info[i]->coltype = lpMem[I + 4];
			switch (dbproc->columns_info[i]->coltype)
			{
			case SQLIMAGE:
			case SQLTEXT:
				dbproc->columns_info[i]->collen = *(_DWORD*)&lpMem[I + 5];
				i_1b = I + 9;
				SiZ = *(WORD*)&lpMem[i_1b];
				i_1 = i_1b + 2; 
				dbproc->columns_info[i]->format = (char*)AllocateHeapMemory(4, dbproc, SiZ + 1, 0);
				if (!dbproc->columns_info[i]->format)
					return FreeOnError(lpMem, dbproc);
				strncpy(dbproc->columns_info[i]->format, (char*)&lpMem[i_1], SiZ);
				dbproc->columns_info[i]->format[SiZ] = 0;
				I = SiZ + i_1;
				break;
			case SQLVARBINARY:
			case SQLINTN:
			case SQLFLTN:
			case SQLMONEYN:
			case SQLDATETIMN:
				dbproc->columns_info[i]->varlength = 1;
				dbproc->columns_info[i]->collen = (BYTE)lpMem[I + 5];
				I += 6;
				break;
			case SQLVARCHAR:
			case SQLBINARY:
			case SQLCHAR:
				dbproc->columns_info[i]->collen = (BYTE)lpMem[I + 5];
				I += 6;
				break;
			case SQLINT1:
			case SQLBIT:
				dbproc->columns_info[i]->collen = 1;
				I += 5;
				break;
			case SQLINT2:
				dbproc->columns_info[i]->collen = 2;
				I += 5;
				break;
			case SQLINT4:
			case SQLDATETIM4:
			case SQLFLT4:
			case SQLMONEY4:
				dbproc->columns_info[i]->collen = 4;
				I += 5;
				break;
			case SQLMONEY:
			case SQLDATETIME:
			case SQLFLT8:
				dbproc->columns_info[i]->collen = 8;
				I += 5;
				break;
			case SQLDECIMAL:
			case SQLNUMERIC:
				dbproc->columns_info[i]->collen = 19;
				dbproc->columns_info[i]->precision = lpMem[I + 6];
				dbproc->columns_info[i]->scale = lpMem[I + 7];
				I += 8;
				break;
			default:
				// "Possible network error: Bad token from SQL Server: Datastream processing out of sync."
				GeneralError(dbproc, SQLEBTOK);
				return FreeOnError(lpMem, dbproc);
			}
			++i;
		}else
			break;
	}
	FreeMemory(dbproc, lpMem);
	if (dbproc->nbufrow > 1u)
	{
		prowbuffer = (rowbuffer_t*)AllocateHeapMemory(4, dbproc, 12 * dbproc->nbufrow, 1);
		if (prowbuffer)
		{
			dbproc->rowbuffer = prowbuffer;
			for (i_1a = 0; i_1a < dbproc->nbufrow; ++i_1a)
			{
				prowbuffer[i_1a].columnsdata = (column_data_t**)AllocateHeapMemory(4, dbproc, 4 * i, 1);
				if (!prowbuffer[i_1a].columnsdata)
					return FreeOnError(0, dbproc);
				if (!AllocateRowData(dbproc, prowbuffer[i_1a].columnsdata, i))
					return 0;
			}
			dbproc->columns_data = dbproc->rowbuffer->columnsdata;
			dbproc->nextrowidx = 0;
			dbproc->rowidx = 1;
			return 1;
		}
		return FreeOnError(0, dbproc);
	}
	dbproc->columns_data = (column_data_t**)AllocateHeapMemory(4, dbproc, 4 * i, 1);
	if (!dbproc->columns_data)
		return FreeOnError(0, dbproc);

	return AllocateRowData(dbproc, dbproc->columns_data, i) != 0;
}
/*
* 其实只处理了缓存大小改变
*/
int __stdcall HandlerEnvChange(PDBPROCESS dbproc, BYTE token, int Size)
{
	int result = 0;
	char Destination[20] = { 0 };
	void* lpMem = 0; 
	BYTE Siz = 0; 
	BYTE buf[16] = { 0 };
	Siz = 4;
	if (token == SQLENVCHANGE_42)
	{
		if (dbproc->CommLayer->rbytes
			&& Siz <= (int)dbproc->CommLayer->wbytes
			&& Siz <= dbproc->CommLayer->length - dbproc->CommLayer->rbytes)
		{
			memmove(buf, &dbproc->CommLayer->buffer0[dbproc->CommLayer->rbytes], Siz);
			dbproc->CommLayer->rbytes += Siz;
			dbproc->CommLayer->wbytes -= Siz;
			result = 1;
		}
		else
		{
			result = getbytes_internal(dbproc, (BYTE*)buf, Siz);
		}
		if (!result)
			return 0;
	}
	else
	{
		if (token != SQLENVCHANGE)
			return 0;
		lpMem = AllocateHeapMemory(4, dbproc, Size, 0);
		if (!lpMem)
			return 0;
		if (dbproc->CommLayer->rbytes
			&& Size <= dbproc->CommLayer->wbytes
			&& Size <= dbproc->CommLayer->length - dbproc->CommLayer->rbytes)
		{
			memmove(lpMem, &dbproc->CommLayer->buffer0[dbproc->CommLayer->rbytes], Size);
			dbproc->CommLayer->rbytes += Size;
			dbproc->CommLayer->wbytes -= Size;
			result = 1;
		}
		else
		{
			result = getbytes_internal(dbproc, (BYTE*)lpMem, Size);
		}
		if (!result)
		{
			FreeMemory(dbproc, lpMem);
			return 0;
		}
		if (*(BYTE*)lpMem == 4)
		{
			strncpy(Destination, (const char*)lpMem + 2, *((BYTE*)lpMem + 1));
			Destination[*((BYTE*)lpMem + 1)] = 0;
			dbproc->CommLayer->lastbufsize = atoi(Destination);
		}
		FreeMemory(dbproc, lpMem);
	}
	return SUCCEED;
}
/*
* Token Stream-Specific Rules:
* TokenType = BYTE
* Identifier = USHORT
* OffSetLen = USHORT
* The offset in the SQL text buffer received by the server of the identifier. The SQL text buffer begins 
* with an OffSetLen value of 0 (MOD 64 kilobytes if the value of OffSet is greater than 64 kilobytes).
*/
int __stdcall GetOffsetInfo(PDBPROCESS dbproc)
{
	int result = 0; 
	offset_t* next = 0;
	offset_t* pnext = 0;
	offset_t* poff = 0;
	int Identifier = 0;

	if (dbproc->CommLayer->rbytes
		&& dbproc->CommLayer->wbytes >= 4u
		&& dbproc->CommLayer->length - dbproc->CommLayer->rbytes >= 4)
	{
		memmove(&Identifier, &dbproc->CommLayer->buffer0[dbproc->CommLayer->rbytes], 4u);
		dbproc->CommLayer->rbytes += 4;
		dbproc->CommLayer->wbytes -= 4;
		result = 1;
	}
	else
	{
		result = getbytes_internal(dbproc, (BYTE*)&Identifier, 4);
	}
	if (!result)
		return 0;
	for (next = dbproc->offsets; next && next->next; next = next->next)
		;
	poff = (offset_t*)AllocateHeapMemory(4, dbproc, 8u, 1);
	if (!poff)
		return FreeOnError(0, dbproc);
	if (next)
	{
		next->next = poff;
		pnext = next->next;
	}
	else
	{
		pnext = poff;
		if (!dbproc->offsets)
			dbproc->offsets = poff;
	}
	/*
	* 4字节包含 Identifier 和 OffSetLen
	*/
	*(_DWORD*)&pnext->index = Identifier;
	return 1;
}
/*
* Token Stream-Specific Rules
* TokenType = BYTE
* Value = LONG
* The return status value determined by the remote procedure. The return status MUST NOT be NULL
*/
int __stdcall GetReturnStatus(PDBPROCESS dbproc, int Size)
{
	int result = 0; 
	int Status = 0;

	if (dbproc->CommLayer->rbytes
		&& Size <= dbproc->CommLayer->wbytes
		&& Size <= dbproc->CommLayer->length - dbproc->CommLayer->rbytes)
	{
		memmove(&Status, &dbproc->CommLayer->buffer0[dbproc->CommLayer->rbytes], Size);
		dbproc->CommLayer->rbytes += Size;
		dbproc->CommLayer->wbytes -= Size;
		result = 1;
	}
	else
	{
		result = getbytes_internal(dbproc, (BYTE*)&Status, Size);
	}
	if (!result)
		return 0;
	dbproc->return_status = Status;
	dbproc->opmask |= 2u;
	return 1;
}
int __stdcall GetProcID(PDBPROCESS dbproc)
{
	int result = 0; 
	int ID[2] = { 0 };

	if (dbproc->CommLayer->rbytes
		&& dbproc->CommLayer->wbytes >= 8u
		&& dbproc->CommLayer->length - dbproc->CommLayer->rbytes >= 8)
	{
		memmove(ID, &dbproc->CommLayer->buffer0[dbproc->CommLayer->rbytes], 8u);
		dbproc->CommLayer->rbytes += 8;
		dbproc->CommLayer->wbytes -= 8;
		result = 1;
	}
	else
	{
		result = getbytes_internal(dbproc, (BYTE*)ID, 8);
	}
	if (!result)
		return 0;
	dbproc->proc_id = ID[0];
	return 1;
}
char* __stdcall dbWinConvFromServer(PDBPROCESS dbproc, char* name, unsigned int namlen)
{
	char* result = 0;
	char* pSrc = 0; 
	char* pSrca = 0; 
	char Str[256] = { 0 };

	if ((dbproc->option[14].opt & 1) != 0 && namlen)
	{
		if (namlen <= 0xFF)
		{
			pSrc = Str;
		}
		else
		{
			result = (char*)AllocateHeapMemory(4, dbproc, namlen + 1, 1);
			pSrc = result;
			if (!result)
				return result;
		}
		qmemcpy(pSrc, name, namlen);
		pSrc[namlen] = 0;
		OemToCharA(pSrc, pSrc);
		qmemcpy(name, pSrc, namlen);
		if (namlen > 0xFF)
			FreeMemory(dbproc, pSrc);
	}

	if ((dbproc->option[15].opt & 1) != 0 && namlen)
	{
		if (namlen <= 0xFF)
		{
			pSrca = Str;
		}
		else
		{
			result = (char*)AllocateHeapMemory(4, dbproc, namlen + 1, 1);
			pSrca = result;
			if (!result)
				return result;
		}
		qmemcpy(pSrca, name, namlen);
		pSrca[namlen] = 0;
		CharToOemA(pSrca, pSrca);
		result = (char*)namlen;
		qmemcpy(name, pSrca, namlen);
		if (namlen > 0xFF)
			return (char*)FreeMemory(dbproc, pSrca);
	}
	return result;
}
int __stdcall GetColNameInfo(PDBPROCESS dbproc, int Size)
{
	int result = 0;
	BYTE* Src = 0;
	column_info_t** lpMem = 0;
	BYTE* pbuf = 0; 

	pbuf = (BYTE*)AllocateHeapMemory(4, dbproc, Size, 0);
	if (!pbuf)
		return FreeOnError(0, dbproc);
	if (dbproc->CommLayer->rbytes
		&& Size <= dbproc->CommLayer->wbytes
		&& Size <= dbproc->CommLayer->length - dbproc->CommLayer->rbytes)
	{
		memmove(pbuf, &dbproc->CommLayer->buffer0[dbproc->CommLayer->rbytes], Size);
		dbproc->CommLayer->rbytes += Size;
		dbproc->CommLayer->wbytes -= Size;
		result = 1;
	}
	else
	{
		result = getbytes_internal(dbproc, pbuf, Size);
	}
	if (!result)
		return FreeOnError(pbuf, dbproc);
	Src = pbuf;
	int i = 0;
	int Siz = 0;
	while (i < Size)
	{
		i += *Src + 1;
		Src += *Src + 1;
		++Siz;
	}
	lpMem = (column_info_t**)AllocateHeapMemory(4, dbproc, 4 * Siz, 1);
	if (!lpMem)
		return FreeOnError(pbuf, dbproc);
	i = 0;
	BYTE *Srca = (BYTE*)pbuf;
	BYTE* Srcb = 0;
	while (1)
	{
		if (i >= Siz)
		{
			dbproc->columns_info = lpMem;
			dbproc->ncols = Siz;
			dbproc->numcols = Siz;
			FreeMemory(dbproc, pbuf);
			return 1;
		}
		lpMem[i] = (column_info_t*)AllocateHeapMemory(4, dbproc, 0x3C, 1);
		if (!lpMem[i])
			break;
		lpMem[i]->namlen = *Srca;
		Srcb = Srca + 1;

		if (lpMem[i]->namlen > 30u)
			lpMem[i]->namlen = 30;
		dbmove(Srcb, lpMem[i], lpMem[i]->namlen);
		lpMem[i]->name[lpMem[i]->namlen] = 0;
		dbWinConvFromServer(dbproc, lpMem[i]->name, lpMem[i]->namlen);
		Srca = &Srcb[lpMem[i]->namlen];
		++i;
	}
	while (i)
		FreeMemory(dbproc, lpMem[--i]);
	FreeMemory(dbproc, lpMem);
	return FreeOnError(pbuf, dbproc);
}
int __stdcall GetTabName(PDBPROCESS dbproc, int Size)
{
	int result = 0; 
	BYTE C = 0; 
	int i = 0; 
	char** tabs = 0;
	int Count = 0; 
	BYTE* lpMem = 0;
	BYTE* Src = 0; 
	BYTE* Srca = 0; 

	Count = 0;
	int Siz = Size;
	free_tabnames(dbproc);
	if (!Size)
		return 1;
	lpMem = (BYTE*)AllocateHeapMemory(4, dbproc, Size, 0);
	if (!lpMem)
		return FreeOnError(0, dbproc);
	if (dbproc->CommLayer->rbytes
		&& Size <= dbproc->CommLayer->wbytes
		&& Size <= dbproc->CommLayer->length - dbproc->CommLayer->rbytes)
	{
		memmove(lpMem, &dbproc->CommLayer->buffer0[dbproc->CommLayer->rbytes], Size);
		dbproc->CommLayer->rbytes += Size;
		dbproc->CommLayer->wbytes -= Size;
		result = 1;
	}
	else
	{
		result = getbytes_internal(dbproc, lpMem, Size);
	}
	if (!result)
		return FreeOnError(lpMem, dbproc);
	Src = lpMem;
	while (Siz > 0)
	{
		C = *Src;
		Src += C + 1;
		Siz -= C + 1;
		++Count;
	}
	tabs = (char**)AllocateHeapMemory(4, dbproc, 4 * Count, 1);
	if (!tabs)
		return FreeOnError(lpMem, dbproc);
	Srca = lpMem;
	for (i = 0; i < Count; ++i)
	{
		C = *Srca++;
		if (C)
		{
			tabs[i] = (char*)AllocateHeapMemory(4, dbproc, C + 1, 0);
			if (!tabs[i])
				return FreeOnError(lpMem, dbproc);
			dbmove(Srca, tabs[i], C);
			tabs[i][C] = 0;
			dbWinConvFromServer(dbproc, tabs[i], C);
			Srca += C;
		}
	}
	dbproc->tabnames = tabs;
	dbproc->ntab = Count;
	FreeMemory(dbproc, lpMem);
	return 1;
}
int __stdcall GetBrowseColumnInfo(PDBPROCESS dbproc, signed int Size)
{
	int result = 0;
	BYTE C,C1 = 0;
	column_info_t* colfmt = 0;
	int i = 0;
	LPVOID lpMem = 0; 
	BYTE* Src = 0; 
	BYTE* Srcb = 0;
	BYTE* Srca = 0;

	i = 0;
	lpMem = AllocateHeapMemory(4, dbproc, Size, 0);
	if (!lpMem)
		return FreeOnError(0, dbproc);
	if (dbproc->CommLayer->rbytes
		&& Size <= dbproc->CommLayer->wbytes
		&& Size <= dbproc->CommLayer->length - dbproc->CommLayer->rbytes)
	{
		memmove(lpMem, &dbproc->CommLayer->buffer0[dbproc->CommLayer->rbytes], Size);
		dbproc->CommLayer->rbytes += Size;
		dbproc->CommLayer->wbytes -= Size;
		result = 1;
	}
	else
	{
		result = getbytes_internal(dbproc, (BYTE*)lpMem, Size);
	}
	if (!result)
		return FreeOnError(lpMem, dbproc);
	Src = (BYTE*)lpMem;
	while (i < Size)
	{
		C1 = *Src;
		Srcb = Src + 1;
		colfmt = dbproc->columns_info[C1 - 1];
		colfmt->ntab = *Srcb++;
		colfmt->type = *Srcb;
		Src = Srcb + 1; 
		i += 3;
		if ((colfmt->type & 0x20) != 0)
		{
			C = *Src;
			Srca = Src + 1;
			colfmt->actualname = (char*)AllocateHeapMemory(4, dbproc, C + 1, 0);
			if (!colfmt->actualname)
				return FreeOnError(lpMem, dbproc);
			dbmove(Srca, colfmt->actualname, C);
			colfmt->actualname[C] = 0;
			dbWinConvFromServer(dbproc, (char*)colfmt->actualname, C);
			i += C + 1;
			Src = &Srca[C];
		}
		if ((colfmt->type & 0x10) != 0)
			--dbproc->numcols;
	}
	FreeMemory(dbproc, lpMem);
	return 1;
}
int __stdcall GetAltColNameInfo(PDBPROCESS dbproc, int Size)
{
	int result = 0; 
	ushort Siz = 0;
	altcol_link_t* next = 0; 
	BYTE* lpMem = 0; 
	int i, j; 
	altcol_t** pnames = 0;
	int C = 0; 
	int Count = 0; 
	BYTE* Src = 0;
	BYTE* Srca = 0;

	Count = 0;
	lpMem = (BYTE*)AllocateHeapMemory(4, dbproc, Size, 0);
	if (!lpMem)
		return FreeOnError(0, dbproc);
	if (dbproc->CommLayer->rbytes
		&& Size <= dbproc->CommLayer->wbytes
		&& Size <= dbproc->CommLayer->length - dbproc->CommLayer->rbytes)
	{
		memmove(lpMem, &dbproc->CommLayer->buffer0[dbproc->CommLayer->rbytes], Size);
		dbproc->CommLayer->rbytes += Size;
		dbproc->CommLayer->wbytes -= Size;
		result = 1;
	}
	else
	{
		result = getbytes_internal(dbproc, lpMem, Size);
	}
	if (!result)
		return FreeOnError(lpMem, dbproc);
	Siz = *(WORD*)lpMem;
	Src = lpMem + 2;
	i = 2;
	while (i < Size)
	{
		C = *Src;
		i += C + 1;
		Src += C + 1;
		++Count;
	}
	for (next = dbproc->altcolinfo; next && next->next; next = next->next)
		;
	if (next)
	{
		next->next = (altcol_link_t*)AllocateHeapMemory(4, dbproc, 0x16u, 1);
		if (!next->next)
			return FreeOnError(lpMem, dbproc);
		next = next->next;
	}
	else
	{
		next = (altcol_link_t*)AllocateHeapMemory(4, dbproc, 0x16u, 1);
		if (!next)
			return FreeOnError(lpMem, dbproc);
		dbproc->altcolinfo = next;
	}
	next->n_alts = Count;
	Srca = (BYTE*)(lpMem + 2);
	next->altcols = (altcol_t**)AllocateHeapMemory(4, dbproc, 4 * Count, 1);
	if (!next->altcols)
		return FreeOnError(lpMem, dbproc);
	pnames = next->altcols;
	next->nrow = Siz;
	for (j = 0; j < Count; ++j)
	{
		pnames[j] = (altcol_t*)AllocateHeapMemory(4, dbproc, 0x12u, 1);
		if (!pnames[j])
			return FreeOnError(lpMem, dbproc);
		pnames[j]->len = *Srca++;
		if (pnames[j]->len)
		{
			pnames[j]->name = (char*)AllocateHeapMemory(4, dbproc, pnames[j]->len + 1, 0);
			if (!pnames[j]->name)
				return FreeOnError(lpMem, dbproc);
			dbmove(Srca, pnames[j]->name, pnames[j]->len);
			pnames[j]->name[pnames[j]->len] = 0;
			dbWinConvFromServer(dbproc, pnames[j]->name, pnames[j]->len);
			Srca += pnames[j]->len;
		}
	}
	FreeMemory(dbproc, lpMem);
	++dbproc->n_compute_row;
	return 1;
}
BYTE* __stdcall GetColLength(BYTE* Src, BYTE token, DWORD* lpLength)
{
	BYTE* pnext = Src;
	switch (token)
	{
	case SQLIMAGE:
	case SQLTEXT:
		*lpLength = *(int*)Src;
		pnext += 4;
		break;
	case SQLVARBINARY:
	case SQLINTN:
	case SQLVARCHAR:
	case SQLBINARY:
	case SQLCHAR:
	case SQLDECIMAL:
	case SQLNUMERIC:
	case SQLFLTN:
	case SQLMONEYN:
	case SQLDATETIMN:
		*lpLength = *Src;
		pnext += 1;
		break;
	case SQLINT1:
	case SQLBIT:
		*lpLength = 1;
		break;
	case SQLINT2:
		*lpLength = 2;
		break;
	case SQLINT4:
	case SQLDATETIM4:
	case SQLFLT4:
	case SQLMONEY4:
		*lpLength = 4;
		break;
	case SQLMONEY:
	case SQLDATETIME:
	case SQLFLT8:
		*lpLength = 8;
		break;
	default:
		return pnext;
	}
	return pnext;
}
/*
* Token Stream-Specific Rules
*     TokenType = BYTE
*     Length    = USHORT
*     Id        = USHORT
*     CAltCols  = BYTE
*     ByCols    = BYTE
*     Op        = BYTE
*     Operand   = BYTE
*     UserType  = USHORT
*     Flags = fNullable
*             fCaseSen
*             usUpdateable
*             fIdentity
*             FRESERVEDBIT
*             usReservedODBC
*             8 FRESERVEDBIT
*     TableName   = B_VARCHAR
*     ColNum      = BYTE
*     ComputeData = Op
*                   Operand
*                   UserType
*                   Flags
*                   TYPE_INFO
*                   [TableName]
* 
*    ALTFMT = TokenType
*             Length
*             Id
*             CAltCols - The number of column data in the data stream.
*             <CAltCols>ComputeData
*             ByCols
*             <ByCols>ColNum
*/
int __stdcall GetAltColFormat(PDBPROCESS dbproc, int Size)
{
	int result = 0; 
	int Id = 0; 
	altcol_link_t* next = 0;
	altcol_t** acols = 0;
	int i_2,i,i_2a = 0; 
	BYTE* lpBufSrc,* pComputeData; 
	BYTE* pbufb,* pbuf,* pbufc,* pbufa;
	int i_1 = 0;

	i_2 = 0;
	lpBufSrc = (BYTE*)AllocateHeapMemory(4, dbproc, Size, 0);
	if (!lpBufSrc)
		return FreeOnError(0, dbproc);
	if (dbproc->CommLayer->rbytes
		&& Size <= dbproc->CommLayer->wbytes
		&& Size <= dbproc->CommLayer->length - dbproc->CommLayer->rbytes)
	{
		memmove(lpBufSrc, &dbproc->CommLayer->buffer0[dbproc->CommLayer->rbytes], Size);
		dbproc->CommLayer->rbytes += Size;
		dbproc->CommLayer->wbytes -= Size;
		result = 1;
	}
	else
	{
		result = getbytes_internal(dbproc, lpBufSrc, Size);
	}
	if (!result)
		return FreeOnError(lpBufSrc, dbproc);
	/*
	* The ID of the SQL statement to which the total column formats apply. This ID lets the client 
    * correctly interpret later ALTROW data streams. 
	*/
	Id = *(WORD*)lpBufSrc; 
	next = dbproc->altcolinfo;
	while (i_2 < Id - 1)
	{
		if (!next)
		{
			//"Invalid computeid or compute column number."
			GeneralError(dbproc, SQLEICN);
			return FreeOnError(lpBufSrc, dbproc);
		}
		next = next->next;
		++i_2;
	}
	if (next->nrow != Id || (next->caltcols = lpBufSrc[2], pComputeData = lpBufSrc + 3, (acols = next->altcols) == 0))
	{
		GeneralError(dbproc, SQLEICN);
		return FreeOnError(lpBufSrc, dbproc);
	}
	for (i = 0; i < next->n_alts; ++i)
	{
		if (!acols[i])
		{
			GeneralError(dbproc, SQLEICN);
			return FreeOnError(lpBufSrc, dbproc);
		}
		acols[i]->top = *pComputeData;
		pbufb = (pComputeData + 1);
		acols[i]->Operand = *pbufb++;
		acols[i]->UserType = *(unsigned __int16*)pbufb;
		pbuf = pbufb + 4;
		if (dbproc->ver < 0x40u)
		{
			i_1 = acols[i]->Operand - 1;
			if (i_1 < dbproc->ncols)
				acols[i]->UserType = (unsigned __int16)dbproc->columns_info[i_1]->usertype;
		}
		acols[i]->token = *pbuf; // TableName ( B_VARCHAR )

		pComputeData = (BYTE*)GetColLength(pbuf + 1, acols[i]->token, (DWORD*)&acols[i]->length);
		if (acols[i]->token == SQLNUMERIC || acols[i]->token == SQLDECIMAL)
		{
			acols[i]->precision = *pComputeData;
			pbufc = pComputeData + 1;
			acols[i]->scale = *pbufc;
			pComputeData = pbufc + 1;
			acols[i]->length = 19;
		}
	}
	next->data_length = *pComputeData;
	pbufa = (pComputeData + 1);
	if (next->data_length)
	{
		next->databuffer = (BYTE*)AllocateHeapMemory(4, dbproc, next->data_length, 0);
		if (!next->databuffer)
			return FreeOnError(lpBufSrc, dbproc);
	}
	for (i_2a = 0; i_2a < next->data_length; ++i_2a)
		next->databuffer[i_2a] = *pbufa++;
	FreeMemory(dbproc, lpBufSrc);
	return 1;
}
/*
* TokenType = BYTE
* Length = USHORT
* ColNum = *BYTE
*/
int __stdcall GetOrderbys(PDBPROCESS dbproc, int Size)
{
	int result = 0;
	LPVOID lpMem = 0;

	if (dbproc->ordercols)
		FreeMemory(dbproc, dbproc->ordercols);
	if (Size)
	{
		lpMem = AllocateHeapMemory(4, dbproc, Size, 0);
		if (lpMem)
		{
			if (dbproc->CommLayer->rbytes
				&& Size <= dbproc->CommLayer->wbytes
				&& Size <= dbproc->CommLayer->length - dbproc->CommLayer->rbytes)
			{
				memmove(lpMem, &dbproc->CommLayer->buffer0[dbproc->CommLayer->rbytes], Size);
				dbproc->CommLayer->rbytes += Size;
				dbproc->CommLayer->wbytes -= Size;
				result = 1;
			}
			else
			{
				result = getbytes_internal(dbproc, (BYTE*)lpMem, Size);
			}
			if (result)
			{
				dbproc->ordercols = (BYTE*)lpMem;
				dbproc->n_orders = Size;
				return 1;
			}
			else
			{
				return FreeOnError(lpMem, dbproc);
			}
		}
		else
		{
			return FreeOnError(0, dbproc);
		}
	}
	else
	{
		dbproc->n_orders = 0;
		dbproc->ordercols = 0;
		return 1;
	}
}
char* __stdcall ChangeName(PDBPROCESS dbproc, const char* Src)
{
	char* result = 0;
	int L = 0; 
	int Count = 0; 
	char* Source = 0;
	char* Sourcea = 0;

	Count = 0;
	for (Source = (char*)&Src[strlen(Src) - 1]; *Source != '\''; --Source)
		;
	for (Sourcea = Source - 1; *Sourcea != '\''; --Sourcea)
		++Count;
	if (Count <= 30)
		L = Count;
	else
		L = 30;
	result = strncpy(dbproc->name, Sourcea + 1, L);
	dbproc->name[L] = 0;
	dbproc->change_dirty = 1;
	return result;
}
int __stdcall dbdomessage(PDBPROCESS dbproc, int Number, int Class, int State, char* MsgText, char* ServerName, char* ProcName, __int16 LineNumber)
{
	if (dbproc
		&& dbproc->last_msg_handler
		&& (dbproc->last_msg_handler(dbproc, Number, State, Class, MsgText, ServerName, ProcName, LineNumber) == 1))
	{
		return 0;
	}
	if (dbproc && dbproc->field_19A == 0)
		return 0;
	if (!DbMsgHandler && (!dbproc || !dbproc->msg_handler))
		return 0;

	DBMSGHANDLE_PROC msghandler = 0;
	DBMSGHANDLE_PROC msghandler1 = 0;
	if (dbproc && dbproc->msg_handler && !DbMsgHandler || dbproc && dbproc->msg_handler && DbMsgHandler)
	{
		msghandler =  dbproc->msg_handler;
	}
	else
	{
		msghandler1 = DbMsgHandler;
	}
	if (msghandler1 == 0)
		return msghandler(dbproc, Number, State, Class, MsgText, ServerName, ProcName, LineNumber);

	return msghandler1(dbproc, Number, State, Class, MsgText, ServerName, ProcName, LineNumber);
}
/*

45 16 00 00 02 00 24 00 d2 d1 bd ab ca fd be dd  E.....$.????????
bf e2 c9 cf cf c2 ce c4 b8 fc b8 c4 ce aa 20 27  ?????????????? '
61 64 76 61 6e 74 61 67 65 27 a1 a3 06 4f 55 4d  advantage'??.OUM
50 2d 44 00 01 00

   <INFO>
	 <TokenType>
	   <BYTE>AB </BYTE>
	 </TokenType>
	 <Length>
	   <USHORT>36 00 </USHORT>
	 </Length>
	 <Number>
	   <LONG>45 16 00 00 </LONG>
	 </Number>
	 <State>
	   <BYTE>02 </BYTE>
	 </State>
	 <Class>
	   <BYTE>00 </BYTE>
	 </Class>
	 <MsgText>
	   <US_VARCHAR>
		 <USHORT>24 00 </USHORT>
		 <BYTES ascii="已将数据库上下文更改为 'advantage'。">d2 d1 bd ab ca fd be dd bf e2 c9 cf cf c2 ce c4 b8 fc b8 c4 ce aa 20 27 61 64 76 61 6e 74 61 67 65 27 a1 a3 </BYTES>
	   </US_VARCHAR>
	 </MsgText>
	 <ServerName>
	   <B_VARCHAR>
		 <BYTE>06 </BYTE>
		 <BYTES ascii="OUMP-D">4f 55 4d 50 2d 44</BYTES>
	   </B_VARCHAR>
	 </ServerName>
	 <ProcName>
	   <B_VARCHAR>
		 <BYTE>00 </BYTE>
		 <BYTES ascii="">
		 </BYTES>
	   </B_VARCHAR>
	 </ProcName>
	 <LineNumber>
	   <USHORT>01 00 </USHORT>
	 </LineNumber>
   </INFO>
*/
int __stdcall PrintMessage(PDBPROCESS dbproc, char* sqlinfo, int Size)
{
	int Number = 0; 
	__int16 State = 0; 
	int L = 0;
	__int16 Class = 0; 
	char* MsgText = 0;
	int Count = 0;
	char* ProcName = 0; 
	char* ServerName = 0;
	__int16 LineNumber = 0;
	char* Source,* Sourceb,* Sourcea; 
	int l1; 
	LineNumber = 0;
	Number = *(_DWORD*)sqlinfo;
	State = sqlinfo[4];
	Class = sqlinfo[5];
	Count = Size - 6;
	if (dbproc->ver >= 0x40u)
		Count = *((__int16*)sqlinfo + 3);
	MsgText = (char*)AllocateHeapMemory(3, dbproc, Count + 1, 0);
	if (!MsgText)
		return FreeOnError(0, dbproc);
	if (dbproc->ver >= 0x40u)
	{
		strncpy(MsgText, (char*)sqlinfo + 8, Count);
		l1 = sqlinfo[Count + 8];
		Source = (char*)&sqlinfo[Count + 9];
		ServerName = (char*)AllocateHeapMemory(3, dbproc, l1 + 1, 0);
		if (ServerName)
		{
			strncpy(ServerName, Source, l1);
			ServerName[l1] = 0;
			strncpy(dbproc->backupserver, ServerName, 31u);
			dbWinConvFromServer(dbproc, ServerName, l1);
			Sourceb = &Source[l1];
			L = *Sourceb;
			Sourcea = Sourceb + 1;
			if (L > 0)
			{
				ProcName = (char*)AllocateHeapMemory(3, dbproc, L + 1, 0);
			}
			else
			{
				ProcName = 0;
			}
			if (ProcName)
			{
				strncpy(ProcName, Sourcea, L);
				ProcName[L] = 0;
				dbWinConvFromServer(dbproc, ProcName, L);
			}
			LineNumber = *(WORD*)&Sourcea[L];
		}else
			return FreeOnError(0, dbproc);
	}
	else
	{
		strncpy(MsgText, (char*)sqlinfo + 6, Count);
		ServerName = (char*)AllocateHeapMemory(3, dbproc, 1u, 0);
		if (!ServerName)
			return FreeOnError(0, dbproc);
		ProcName = (char*)AllocateHeapMemory(3, dbproc, 1u, 0);
		if (!ProcName)
			return FreeOnError(0, dbproc);
		*ServerName = 0;
		*ProcName = 0;
	}


	MsgText[Count] = 0;
	if (Count > 0 && MsgText[Count - 1] == 10)
		MsgText[Count - 1] = 0;
	dbWinConvFromServer(dbproc, MsgText, Count);
	if (Number == 5701)
		ChangeName(dbproc, MsgText);
	if (Number != 5703)
		dbdomessage(dbproc, Number, Class, State, MsgText, ServerName, ProcName, LineNumber);
	FreeMemory(0, ServerName);
	if (ProcName)
		FreeMemory(0, ProcName);
	return FreeMemory(0, MsgText);
}
/*
AB
45 16 00 00 02 00 24 00 d2 d1 bd ab ca fd be dd  E.....$.????????
bf e2 c9 cf cf c2 ce c4 b8 fc b8 c4 ce aa 20 27  ?????????????? '
61 64 76 61 6e 74 61 67 65 27 a1 a3 06 4f 55 4d  advantage'??.OUM
50 2d 44 00 01 00

*/
int __stdcall HandleInfoToken(PDBPROCESS dbproc, int Size)
{
	int result = 0; 
	char* lpMsg = 0;

	lpMsg = (char*)AllocateHeapMemory(4, dbproc, Size, 1);
	if (!lpMsg)
		return 0;
	if (dbproc->CommLayer->rbytes
		&& Size <= dbproc->CommLayer->wbytes
		&& Size <= dbproc->CommLayer->length - dbproc->CommLayer->rbytes)
	{
		memmove(lpMsg, &dbproc->CommLayer->buffer0[dbproc->CommLayer->rbytes], Size);
		dbproc->CommLayer->rbytes += Size;
		dbproc->CommLayer->wbytes -= Size;
		result = 1;
	}
	else
	{
		result = getbytes_internal(dbproc, (BYTE*)lpMsg, Size);
	}
	if (!result)
		return FreeOnError(lpMsg, 0);
	PrintMessage(dbproc, lpMsg, Size);
	/*
	* Event ID 
	* 4002  Sybase Login failed.
	* 18450 - 18457 SQL Server Login failed. 
	* 
	* 17809 Could not connect because the maximum number of user connections has already been reached
	*/
	if ((dbproc->ret_status & 0x800) != 0 && (*(int*)lpMsg == 4002 || *(int*)lpMsg >= 18450 && *(int*)lpMsg <= 18457 || *(int*)lpMsg == 17809))
	{
		// "Login incorrect."
		GeneralError(dbproc, SQLEPWD);
		FreeMemory(dbproc, lpMsg);
		return 0;
	}
	else
	{
		FreeMemory(dbproc, lpMsg);
		return 1;
	}
}
BYTE* __stdcall GetReturnValueLen(BYTE* Src, BYTE token, DWORD* lpLength, DWORD* lpReturn)
{
	BYTE* next = Src;

	switch (token)
	{
	case SQLIMAGE:
	case SQLTEXT:
		*lpReturn = *(DWORD*)Src;
		*lpLength = *((DWORD*)Src + 1);
		next = Src + 8;
		break;
	case SQLVARBINARY:
	case SQLINTN:
	case SQLVARCHAR:
	case SQLBINARY:
	case SQLCHAR:
	case SQLFLTN:
	case SQLMONEYN:
	case SQLDATETIMN:
		*lpReturn = *Src;
		*lpLength = *(Src + 1);
		next = Src + 2;
		break;
	case SQLINT1:
	case SQLBIT:
		*lpLength = 1;
		*lpReturn = 1;
		break;
	case SQLINT2:
		*lpLength = 2;
		*lpReturn = 2;
		break;
	case SQLINT4:
	case SQLDATETIM4:
	case SQLFLT4:
	case SQLMONEY4:
		*lpLength = 4;
		*lpReturn = 4;
		break;
	case SQLMONEY:
	case SQLDATETIME:
	case SQLFLT8:
		*lpLength = 8;
		*lpReturn = 8;
		break;
	case SQLDECIMAL: // SQLDECIMAL
	case SQLNUMERIC: // SQLNUMERIC

		*lpReturn = Src[2] + 1000 * Src[1];
		*lpLength = Src[4];
		next = Src + 5;
		break;
	default:
		return next;
	}
	return next;
}
/*
* The token value is 0xAC.
* Token Stream-Specific Rules
*     TokenType = BYTE
*     ParamName = B_VARCHAR       The parameter name length and parameter name (within B_VARCHAR)
*     Length    = USHORT
*     Status    = BYTE            0x01: corresponds to OUTPUT parametter of a stored procedure; 0x02:corresponds to UDF
*     UserType  = USHORT
*     fNullable = BIT
*     fCaseSen  = BIT
*     usUpdateable = 2BIT ; 0 = ReadOnly
*                         ; 1 = Read/Write
*                         ; 2 = Unused
*     fIdentity  = BIT
*     usReservedODBC = 2BIT
*     Flags     = 0   - fNullable
*                 1   - fCaseSen
*                 2,3 - usUpdateable
*                 4   - fIdentity
*                 5   - FRESERVEDBIT
*                 6,7 - usReservedODBC
*                 8-15   - FRESERVEDBIT
*     TypeInfo = TYPE_INFO        The TYPE_INFO for the message.
*     Value = TYPE_VARBYTE        The type-dependent data for the parameter (within TYPE_VARBYTE).
*/
int __stdcall GetReturnVal(PDBPROCESS dbproc, int Size)
{
	int result = 0;
	BYTE* values = 0;
	BYTE* pnext = 0;
	BYTE l0, l1, l2, token, byt1;
	DWORD length,val = 0;
	int i, Count, nretval, nvalue;
	void* lpMem,* Src;
	BOOL STOP = 0;

	nvalue = dbproc->numrets;
	nretval = dbproc->nretval;
	Count = 0;
	length = 0;
	STOP = 0;
	if (!Size)
		return 1;
	lpMem = AllocateHeapMemory(4, dbproc, Size, 0);
	if (!lpMem)
		return FreeOnError(0, dbproc);
	if (dbproc->CommLayer->rbytes
		&& Size <= dbproc->CommLayer->wbytes
		&& Size <= dbproc->CommLayer->length - dbproc->CommLayer->rbytes)
	{
		memmove(lpMem, &dbproc->CommLayer->buffer0[dbproc->CommLayer->rbytes], Size);
		dbproc->CommLayer->rbytes += Size;
		dbproc->CommLayer->wbytes -= Size;
		result = 1;
	}
	else
	{
		result = getbytes_internal(dbproc, (BYTE*)lpMem, Size);
	}
	if (!result)
		return FreeOnError(lpMem, dbproc);
	Src = lpMem;
	if (dbproc->ver < 0x40u)
	{
		while (Count < Size)
		{
			l0 = *(BYTE*)Src;
			Src = (char*)Src + 1;
			Src = (char*)Src + l0;
			Count += l0 + 1;
			if (Count >= Size)
			{
				STOP = 1;
			}
			else
			{
				token = *(BYTE*)Src;
				Src = (char*)Src + 1;
				switch (token)
				{
				case SQLIMAGE:
				case SQLTEXT:
				case SQLVARBINARY:
				case SQLINTN:
				case SQLVARCHAR:
				case SQLBINARY:
				case SQLCHAR:
				case SQLINT1:
				case SQLBIT:
				case SQLINT2:
				case SQLINT4:
				case SQLMONEY:
				case SQLDATETIME:
				case SQLFLT8:
				case SQLFLTN:
				case SQLMONEYN:
				case SQLDATETIMN:
					pnext = GetColLength((BYTE*)Src, token, &length);
					break;
				default:
					STOP = 1;
					break;
				}
			}
			if (STOP)
			{
				Src = lpMem;
				Count = 0;
				length = 0;
				break;
			}
			Count += pnext - (BYTE*)Src + 1;
			Src = &pnext[length];
			Count += length;
			++nretval;
			++nvalue;
		}
		if (Count > Size)
		{
			STOP = 1;
			Src = lpMem;
			Count = 0;
			length = 0;
		}
	}
	else
	{
		STOP = 1;
	}
	if (STOP)
	{
		nvalue = dbproc->numrets;
		nretval = dbproc->nretval;
		while (Count < Size)
		{
			l1 = *(BYTE*)Src;
			Src = (char*)Src + 1;
			Src = (char*)Src + l1;
			Count += l1 + 1;
			byt1 = *(BYTE*)Src;
			Src = (char*)Src + 1;
			++Count;
			Src = (char*)Src + 4;
			Count += 4;
			token = *(BYTE*)Src;
			Src = (char*)Src + 1;
			pnext = GetReturnValueLen((BYTE*)Src, token, &length, &val);
			Count += pnext - (BYTE*)Src + 1;
			Src = &pnext[length];
			Count += length;
			++nretval;
			if (byt1)
				++nvalue;
		}
	}
	if (Count > Size)
	{
		// "Possible network error: Bad token from SQL Server: Datastream processing out of sync."
		GeneralError(dbproc, SQLEBTOK);
		return 0;
	}
	if (dbproc->retvals)
	{
		Src = ReallocMemory(dbproc, dbproc->retvals, 4 * nretval);
		if (!Src)
			return FreeOnError(0, dbproc);
		dbproc->retvals = (retval_t**)Src;
	}
	else
	{
		dbproc->retvals = (retval_t**)AllocateHeapMemory(4, dbproc, 4 * nretval, 1);
		if (!dbproc->retvals)
			return FreeOnError(lpMem, dbproc);
	}

	Src = lpMem;
	for (i = dbproc->nretval; i < nretval; ++i)
	{
		dbproc->retvals[i] = (retval_t*)AllocateHeapMemory(4, dbproc, 0x10u, 1);
		if (!dbproc->retvals[i])
			return FreeOnError(lpMem, dbproc);
		l2 = *(BYTE*)Src;
		Src = (char*)Src + 1;
		if (l2)
		{
			dbproc->retvals[i]->name = (char*)AllocateHeapMemory(4, dbproc, l2 + 1, 0);
			if (!dbproc->retvals[i]->name)
				return FreeOnError(lpMem, dbproc);
			dbmove(Src, dbproc->retvals[i]->name, l2);
			dbproc->retvals[i]->name[l2] = 0;
			Src = (char*)Src + l2;
		}
		if (STOP)
		{
			dbproc->retvals[i]->Status = *(BYTE*)Src;
			Src = (char*)Src + 1;
			Src = (char*)Src + 4;
		}
		else
		{
			dbproc->retvals[i]->Status = 0;
		}
		dbproc->retvals[i]->type = *(BYTE*)Src;
		Src = (char*)Src + 1;
		if (STOP)
			Src = GetReturnValueLen((BYTE*)Src, dbproc->retvals[i]->type, (DWORD*)&dbproc->retvals[i]->retlen, &val);
		else
			Src = GetColLength((BYTE*)Src, dbproc->retvals[i]->type, (DWORD*)&dbproc->retvals[i]->retlen);
		if (dbproc->retvals[i]->retlen > 0)
		{
			if (dbproc->retvals[i]->type == SQLNUMERIC || dbproc->retvals[i]->type == SQLDECIMAL)
			{
				dbproc->retvals[i]->values = (BYTE*)AllocateHeapMemory(4, dbproc, 19u, 0);

				if (!dbproc->retvals[i]->values)
					return FreeOnError(lpMem, dbproc);
				values = dbproc->retvals[i]->values;
				values[0] = (BYTE)(val / 1000);
				values[1] = (BYTE)(val % 1000);
				values[2] = *(BYTE*)Src;
				dbzero(values + 3, 0x10u);
				dbmove((char*)Src + 1, values + 3, dbproc->retvals[i]->retlen - 1);
			}
			else
			{
				dbproc->retvals[i]->values = (BYTE*)AllocateHeapMemory(4, dbproc, dbproc->retvals[i]->retlen, 0);

				if (!dbproc->retvals[i]->values)
					return FreeOnError(lpMem, dbproc);
				dbmove(Src, dbproc->retvals[i]->values, dbproc->retvals[i]->retlen);
				if (dbproc->retvals[i]->type == SQLCHAR 
					|| dbproc->retvals[i]->type == SQLVARCHAR 
					|| dbproc->retvals[i]->type == SQLTEXT)
					dbWinConvFromServer(dbproc, (char*)dbproc->retvals[i]->values, dbproc->retvals[i]->retlen);
			}
			Src = (char*)Src + dbproc->retvals[i]->retlen;
		}
	}
	FreeMemory(dbproc, lpMem);
	dbproc->numrets = nvalue;
	dbproc->nretval = nretval;
	return 1; 
}
int __stdcall GetControlInfo(PDBPROCESS dbproc, int Size)
{
	int result = 0; 
	LPVOID lpMem = 0; 

	if (dbproc->control_info)
		FreeMemory(dbproc, dbproc->control_info);
	if (Size > 0)
	{
		lpMem = AllocateHeapMemory(4, dbproc, Size + 1, 0);
		if (!lpMem)
			return FreeOnError(0, dbproc);
		if (dbproc->CommLayer->rbytes
			&& Size <= dbproc->CommLayer->wbytes
			&& Size <= dbproc->CommLayer->length - dbproc->CommLayer->rbytes)
		{
			memmove(lpMem, &dbproc->CommLayer->buffer0[dbproc->CommLayer->rbytes], Size);
			dbproc->CommLayer->rbytes += Size;
			dbproc->CommLayer->wbytes -= Size;
			result = 1;
		}
		else
		{
			result = getbytes_internal(dbproc, (BYTE*)lpMem, Size);
		}
		if (!result)
			return FreeOnError(lpMem, dbproc);
		*((BYTE*)lpMem + Size) = 0;
		dbproc->control_info = lpMem;
	}
	return 1;
}
int __stdcall GetAltControlInfo(PDBPROCESS dbproc, int Size)
{
	int result = 0; 
	LPVOID lpMem = 0; 

	lpMem = AllocateHeapMemory(4, dbproc, Size, 0);
	if (!lpMem)
		return FreeOnError(0, dbproc);
	if (dbproc->CommLayer->rbytes
		&& Size <= dbproc->CommLayer->wbytes
		&& Size <= dbproc->CommLayer->length - dbproc->CommLayer->rbytes)
	{
		memmove(lpMem, &dbproc->CommLayer->buffer0[dbproc->CommLayer->rbytes], Size);
		dbproc->CommLayer->rbytes += Size;
		dbproc->CommLayer->wbytes -= Size;
		result = 1;
	}
	else
	{
		result = getbytes_internal(dbproc, (BYTE*)lpMem, Size);
	}
	if (!result)
		return FreeOnError(lpMem, dbproc);
	FreeMemory(dbproc, lpMem);
	return 1;
}

int __cdecl InitSSPIPackage(DWORD* lpToken)
{
	UINT eMode = 0;
	const char* dllname = 0;
	const char* pszPackageName = 0;

	int cbMaxToken = 0;
	PSecPkgInfoA PkgInfo = 0,pOld = 0,pNext = 0;
	unsigned long pcPackages = 0;
	_OSVERSIONINFOA VersionInformation ; 
	VersionInformation.dwOSVersionInfoSize = sizeof(_OSVERSIONINFOA); // 148;
	GetVersionExA(&VersionInformation);
	eMode = SetErrorMode(0x8000u);
	dllname = "secur32.dll";
	if ((VersionInformation.dwPlatformId & 1) == 0)
		dllname = "security.dll";
	hModule = LoadLibraryA(dllname);
	SetErrorMode(eMode);

	if (hModule)
	{
		INITSECURITYINTERFACE InitSecurityInterface_ = (INITSECURITYINTERFACE)GetProcAddress(hModule, "InitSecurityInterfaceA");
		if (InitSecurityInterface_)
		{
			g_pSecFunctionTable = InitSecurityInterface_();
			if (g_pSecFunctionTable)
			{
				pszPackageName = "NTLM";
				if (VersionInformation.dwMajorVersion >= 5)
					pszPackageName = "negotiate";
				if (g_pSecFunctionTable->QuerySecurityPackageInfoA((char*)pszPackageName, (PSecPkgInfoA*)&PkgInfo) < 0)
				{
					pOld = PkgInfo;
					pNext = PkgInfo;
					if (g_pSecFunctionTable->EnumerateSecurityPackagesA(&pcPackages, (PSecPkgInfoA*)&PkgInfo) < 0)
						return 0;
					int Count = pcPackages;
					if (pcPackages > 0)
					{
						do
						{
							if (pNext->wRPCID == 10)
								break;
							--Count;
							pNext++;
							pcPackages = Count;
						} while (Count > 0);
		
					}
					assert(Count == 0);
					//assert("Count", "../src/sqlsspi.c", 119);
				}
				cbMaxToken = pNext->cbMaxToken;
				g_cbMaxToken = cbMaxToken;
				if (VersionInformation.dwMajorVersion >= 5)
				{
					g_pSecFunctionTable->FreeContextBuffer(pOld);
					if (g_pSecFunctionTable->QuerySecurityPackageInfoA((char*)"NTLM", (PSecPkgInfoA*)&PkgInfo) < 0)
						return 0;
					pOld = PkgInfo;
					cbMaxToken = g_cbMaxToken;
					if (PkgInfo->cbMaxToken > g_cbMaxToken)
					{
						g_cbMaxToken = PkgInfo->cbMaxToken;
					}
				}
				*lpToken = cbMaxToken;
				g_pSecFunctionTable->FreeContextBuffer(pOld);
				return 1;
			}
		}
	}
	return 0;
}
int __cdecl AddEntry(PDBPROCESS dbproc, SecSession* Ses)
{
	SecEntry* result = 0;
	SecEntry* Sec = 0;

	result = (SecEntry*)malloc(0xCu);
	Sec = result;
	if (result)
	{
		result->dbproc = dbproc;
		result->session = Ses;
		EnterCriticalSection(&sspiSection);
		Sec->next = g_SecEntrys.next;
		g_SecEntrys.next = Sec;
		LeaveCriticalSection(&sspiSection);
		return 1;
	}
	return 0;
}
BOOL __cdecl GetEntry(PDBPROCESS dbproc, SecSession** ppSec)
{
	SecEntry* next = 0; 

	EnterCriticalSection(&sspiSection);
	next = g_SecEntrys.next;
	if (next)
	{
		while (dbproc != next->dbproc)
		{
			next = next->next;
			if (!next)
			{
				LeaveCriticalSection(&sspiSection);
				return 0;
			}
		}
		*ppSec = next->session;
	}
	LeaveCriticalSection(&sspiSection);
	return next != 0;
}

int __cdecl InitSession(PDBPROCESS dbproc)
{
	SecSession* pSes = 0;
	int result = 0;
	const char* p = 0;
	_OSVERSIONINFOA VersionInformation ; 

	VersionInformation.dwOSVersionInfoSize = sizeof(_OSVERSIONINFOA); // 148;
	GetVersionExA(&VersionInformation);
	pSes = (SecSession*)malloc(0x20u);
	result = 0;
	if (pSes)
	{
		pSes->first_time = 1;
		pSes->have_credential = 0;
		pSes->have_securitycontext = 0;
		if (VersionInformation.dwMajorVersion < 5 || (p = "negotiate", (VersionInformation.dwPlatformId & 1) != 0))
			p = "NTLM";
		pSes->authentication = p;
		if (AddEntry(dbproc, pSes))
		{
			return 1;
		}
		else
		{
			free(pSes);
			return 0;
		}
	}
	return 0;
}

BOOL __cdecl DeleteEntry(PDBPROCESS dbproc, SecSession** ppSes)
{
	SecEntry* next = 0; 
	SecEntry* entry = 0;

	EnterCriticalSection(&sspiSection);
	next = g_SecEntrys.next;
	entry = &g_SecEntrys;
	if (next)
	{
		while (dbproc != next->dbproc)
		{
			entry = next;
			next = next->next;
			if (!next)
			{
				LeaveCriticalSection(&sspiSection);
				return 0;
			}
		}
		entry->next = next->next;
		*ppSes = next->session;
		free(next);
	}
	LeaveCriticalSection(&sspiSection);
	return next != 0;
}
int __cdecl TermSession(PDBPROCESS dbproc)
{
	int result = 0; 
	SecSession* pSes = 0;

	result = DeleteEntry(dbproc, &pSes);
	if (result)
	{

		if (pSes->have_securitycontext)
		{
			g_pSecFunctionTable->DeleteSecurityContext((PCtxtHandle)&pSes->secHandle);
		}
		if (pSes->have_credential)
		{
			g_pSecFunctionTable->FreeCredentialsHandle((PCredHandle)&pSes->CredHandle);
		}
		free(pSes);
		return 1;
	}
	return result;
}
int __cdecl GenClientContext(
	PDBPROCESS dbproc,
	BYTE* strId,
	int Size,
	BYTE* Src,
	DWORD* lpSize,
	DWORD* lpReturn,
	SEC_CHAR* sec_char)
{
	SecSession* pSec = 0;
	_SecHandle* phContext = 0;
	int result = 0;
	unsigned long* pfContextAttr = 0;
	LARGE_INTEGER timeStamp ;
	_SecBufferDesc Output;
	SecBuffer OutputBuf;
	SecBuffer InputBuf;
	SecBufferDesc Input;

	if (!GetEntry(dbproc, &pSec))
		return 0;


	if (!pSec->first_time && !Size)
	{
		TermSession(dbproc);
		if (!InitSession(dbproc) || !GetEntry(dbproc, &pSec))
			return 0;
		pSec->authentication = "NTLM";

	}
	if (pSec->first_time)
	{
		if (g_pSecFunctionTable->AcquireCredentialsHandleA(
			0,
			(SEC_CHAR*)pSec->authentication,
			2u,
			0,
			0,
			0,
			0,
			(PCredHandle)&pSec->CredHandle,
			&timeStamp) < 0)
			return 0;
		pSec->have_credential = 1;

	}

	Output.pBuffers = &OutputBuf;
	Output.ulVersion = 0;
	Output.cBuffers = 1;
	OutputBuf.cbBuffer = *lpSize;
	OutputBuf.BufferType = 2;
	OutputBuf.pvBuffer = Src;
	if (pSec->first_time == 0)
	{
		Input.cBuffers = 1;
		Input.ulVersion = 0;
		Input.pBuffers = &InputBuf;
		InputBuf.cbBuffer = Size;
		InputBuf.BufferType = 2;
		InputBuf.pvBuffer = strId;
	}
	if (pSec->first_time)
		phContext = 0;
	else
		phContext = &pSec->secHandle;
	result = g_pSecFunctionTable->InitializeSecurityContextA(
		(PCredHandle)&pSec->CredHandle,
		phContext,
		sec_char,
		ISC_REQ_DELEGATE | ISC_REQ_MUTUAL_AUTH,
		0,
		SECURITY_NATIVE_DREP, // 目标上的数据表示形式，例如字节排序
		pSec->first_time == 0 ? &Input : 0,
		0,
		&pSec->secHandle, // phNewContext
		&Output,
		pfContextAttr,
		&timeStamp);
	if (result < 0)
		return 0;
	pSec->have_securitycontext = 1;

	if (result == SEC_I_COMPLETE_NEEDED || result == SEC_I_COMPLETE_AND_CONTINUE)
	{
		/*
		* SEC_I_COMPLETE_AND_CONTINUE
		* 客户端必须调用 CompleteAuthToken ，然后将输出传递给服务器。 
		* 然后，客户端等待返回的令牌，并在另一次调用中将其传递给 InitializeSecurityContext (General) 。
		* 
		* SEC_I_COMPLETE_NEEDED
		* 客户端必须完成消息的生成，然后调用 CompleteAuthToken 函数
		*/

		if (!g_pSecFunctionTable->CompleteAuthToken)
			return 0;
		result = g_pSecFunctionTable->CompleteAuthToken(&pSec->secHandle, &Output);
		if (result < 0)
			return 0;
	}
	*lpSize = OutputBuf.cbBuffer;
	if (pSec->first_time)
		pSec->first_time = 0;
	if (result == SEC_I_CONTINUE_NEEDED || result == SEC_I_COMPLETE_AND_CONTINUE)
	{
		/*
		* SEC_I_CONTINUE_NEEDED
		* 客户端必须将输出令牌发送到服务器并等待返回令牌。 
		* 然后，返回的令牌在对 InitializeSecurityContext (General) 的另一次调用中传递。 
		* 输出令牌可以为空。
		*/
		*lpReturn = 0;
		return 1;
	}
	else
	{
		result = 1;
		*lpReturn = 1;
	}
	return result;
}
/*
* 发送包数据
*/
int __stdcall sendpacket(PDBPROCESS dbproc, __int16 WriteSize, __int16 TransactSize)
{
	__int16 SiZ = 0;
	int timeout = 0;
	int to1, to2;
	int wrSize = 0;
	BYTE* buffer0 = 0;
	BYTE* bf0 = 0;
	PacketHeader* packetHeader = 0;
	int retErr = 0;

	retErr = 0;
	packetHeader = (PacketHeader*)dbproc->CommLayer->buffer1;
	if (dbproc->ver >= 0x40u)
	{
		packetHeader->Length = (WriteSize << 8) | HIBYTE(WriteSize);
		packetHeader->Status = 0;
		packetHeader->SPID = 0;
		++packetHeader->Packet;
		packetHeader->Window = 0;
		if (TransactSize)
			packetHeader->Status = PS_EOM;
	}
	else
	{
		if (packetHeader->Type == PT_LOGIN) // Login
			SiZ = (WriteSize << 8) | HIBYTE(WriteSize);
		else
			SiZ = (TransactSize << 8) | HIBYTE(TransactSize);
		packetHeader->Length = SiZ;
	}
	if (TransactSize
		&& (!dbproc ? (to1 = DbTimeOut) : (!dbisopt(dbproc, DBSETTIME, 0) ? (to2 = DbTimeOut) : (to2 = dbproc->timeout), to1 = to2),
			!to1 && dbproc->exec))
	{
		buffer0 = dbproc->CommLayer->buffer0;
		dbproc->CommLayer->buffer0 = dbproc->CommLayer->buffer1;
		dbproc->CommLayer->buffer1 = buffer0;
		if (dbproc)
		{
			if (dbisopt(dbproc, DBSETTIME, 0))
				timeout = dbproc->timeout;
			else
				timeout = DbTimeOut;
		}
		else
		{
			timeout = DbTimeOut;
		}
		// IOINT __cdecl ConnectionTransact(void* pConnectionObject, BYTE*, BYTE*WriteBuffer, IOINT WriteSize, IOINT, IOINT, TIMEINT, NETERR UNALIGNED*);
		dbproc->CommLayer->length = dbproc->CommLayer->ConnectionTransact(
			dbproc->conn_object,
			dbproc->CommLayer->buffer0,
			dbproc->CommLayer->buffer0,
			WriteSize,
			8,
			dbproc->CommLayer->bufsize,
			timeout,
			&retErr);
		if (dbproc->CommLayer->length)
			dbproc->CommLayer->status = 0;
		else
			dbproc->CommLayer->status = 3;
		dbproc->CommLayer->wbytes = 0;
		dbproc->CommLayer->rbytes = 0;
		dbproc->CommLayer->packet_size = 8;
	}
	else
	{
		// 返回 10054 - "Attempt to bulk-copy an oversized row to the SQL Server."
		wrSize = dbproc->CommLayer->ConnectionWrite(
			dbproc->conn_object,
			dbproc->CommLayer->buffer1,
			WriteSize,
			&retErr);
		dbproc->CommLayer->status = 2;
		bf0 = dbproc->CommLayer->buffer0;
		dbproc->CommLayer->buffer0 = dbproc->CommLayer->buffer1;
		dbproc->CommLayer->buffer1 = bf0;
		if (dbproc->CommLayer->buffer1 && dbproc->CommLayer->buffer0)
			memmove(dbproc->CommLayer->buffer1, dbproc->CommLayer->buffer0, 8u);
		dbproc->CommLayer->packet_size = 8;
		if (wrSize != WriteSize && retErr)
		{
			// "Possible network error: Write to SQL Server Failed."
			GeneralError(dbproc, retErr);
			return 0;
		}
	}
	if (retErr)
	{
		// "Possible network error: Write to SQL Server Failed."
		GeneralError(dbproc, 10025);
		return 0;
	}
	return 1;
}
/*
* 数据包进队列并发送
* 分成每包 512 字节发送，如果不够则只缓存不发送，除非强制发送(使用sendflush)
*/
int __stdcall queuepacket(PDBPROCESS dbproc, BYTE* Src, int TotalSize)
{

	int SiZ = 0;
	PacketHeader* packetheader = 0;

	while (TotalSize)
	{
		if (dbproc->CommLayer->packet_size == dbproc->CommLayer->bufsize)
		{
			/*
			* 缓存满，发送
			*/
			if (!sendpacket(dbproc, dbproc->CommLayer->packet_size, 0))
				return 0;
			if (dbproc->ver < 0x40u)
			{
				packetheader = (PacketHeader*)dbproc->CommLayer->buffer1;
				if (packetheader->Type == PT_LOGIN)
				{
					++packetheader->Packet;
					packetheader->Status |= PS_EOM;
				}
				else
				{
					packetheader->Type = 0;
				}
				packetheader->Type = 0;
			}
		}
		else
		{
			/*
			* 先缓存
			*/
			SiZ = dbproc->CommLayer->bufsize - dbproc->CommLayer->packet_size;
			if (TotalSize < SiZ)
				SiZ = TotalSize;
			dbmove(Src, &dbproc->CommLayer->buffer1[dbproc->CommLayer->packet_size], SiZ);
			dbproc->CommLayer->packet_size += SiZ;
			TotalSize -= SiZ;
			Src += SiZ;
		}
	}
	return 1;
}

BOOL __stdcall sendflush(PDBPROCESS dbproc)
{
	return !dbproc->CommLayer->packet_size || sendpacket(dbproc, dbproc->CommLayer->packet_size, dbproc->CommLayer->packet_size);
}

/*
* Set up the results of the next query.
* 
* Status code for dbresults(). Possible return values are
* SUCCEED, FAIL,
* NO_MORE_RESULTS 2
* NO_MORE_RPC_RESULTS 3
* 
* The typical sequence of calls for using dbresults with dbsqlexec is: 
* DBINT xvariable; 
* DBCHAR yvariable[10]; 
* int return_code; 
* // Read the query into the command buffer  
* dbcmd(dbproc, "select x = 100, y = ’hello’");
* // Send the query to Adaptive Server
* dbsqlexec(dbproc); 
* while ((return_code = dbresults(dbproc)!=NO_MORE_RESULTS){
*     dbbind(dbproc, 1, INTBIND, (DBINT) 0,  (BYTE *) &xvariable);
*     dbbind(...)
* 
*     while (dbnextrow(dbproc) != NO_MORE_ROWS){
*         ; // process row data
*     }
* }
* 
*/
int __cdecl dbresults(PDBPROCESS dbproc)
{
	int result = 0; 
	BYTE* ptkbuf = 0; 
	DWORD ret = 0;
	BYTE* sspiBuf = 0; 
	DWORD dwMaxToken = 0;
	DWORD MaxCount = 0;
	BYTE l0 = 0; 
	void* lpMem = 0; 
	int Size = 0;
	int ReturnStatus = 0; 
	int done = 0; 

	lpMem = 0;
	done = 1;
	ReturnStatus = 0;
	if (!CheckEntry(dbproc))
		return FAIL;
	if ((dbproc->ret_status & 0x20) != 0 && (dbproc->cmd_flag & 0x40) == 0 && dbproc->severity_level != EXNONFATAL)
	{
		dbproc->ret_status &= ~0x20u;
		dbproc->cmd_flag &= ~4u;
		return NO_MORE_RPC_RESULTS;
	}
	if ((dbproc->severity_level == EXUSER || dbproc->severity_level == EXNONFATAL || (dbproc->cmd_flag & 4) != 0)
		&& (dbproc->cmd_flag & 2) == 0)
	{
		if (!dbproc->curcmd && (dbproc->cmd_flag & 0x40) != 0)
		{
			++dbproc->curcmd;
			dbproc->cmd_flag &= ~0x40u;
			if (dbproc->severity_level != EXNONFATAL)
				return 1;
			dbproc->severity_level = EXUSER;
			return NO_MORE_RESULTS;
		}
		if (dbproc->curcmd && (dbproc->cmd_flag & 0x40) != 0)
		{
			dbproc->cmd_flag &= ~0x40u;
			if (dbproc->severity_level == EXUSER)
				return NO_MORE_RESULTS;
			if (dbproc->severity_level == EXNONFATAL)
				return FAIL;
		}
		if ((dbproc->cmd_flag & 2) == 0 && (dbproc->cmd_flag & 4) != 0)
			return NO_MORE_RESULTS;
	}
	if (dbproc->severity_level == EXNONFATAL && (dbproc->cmd_flag & 4) != 0)
	{
		dbproc->severity_level = EXUSER;
		return NO_MORE_RESULTS;
	}
	else if (dbproc->severity_level == EXINFO)
	{
		return FAIL;
	}
	else
	{
		dbproc->firstrow = 0;
		dbproc->lastrow = 0;
		dbproc->currow = 0;
		if (dbproc->token != SQLROW
			&& dbproc->token != SQLALTROW
			&& dbproc->token != SQLDONE)
		{
			tidyproc(dbproc);
		}
		++dbproc->curcmd;
		while (true)
		{
			if (!dbproc->token)
			{
				dbproc->token = getbyte(dbproc, (BYTE*)&done);
			}
			if (done)
			{
				if (dbproc->token == SQLCOLNAME && dbproc->columns_info)
				{
					dbproc->cmd_flag |= 0x10u;
					return SUCCEED;
				}
				else
				{
					if (gettokenlen(dbproc, dbproc->token, (BYTE*)&Size))
					{
						switch (dbproc->token)
						{
						case OLD_SQLCOLFMT:
						case SQLCOLFMT:
							if (!dbproc->columns_info || GetColFormat(dbproc, Size))
							{
								dbproc->token = 0;
								break;
							}else
								return FAIL;
						case SQLENVCHANGE_42:  
						case SQLENVCHANGE:
							if (HandlerEnvChange(dbproc, dbproc->token, Size))
							{
								dbproc->token = 0;
								break;
							}
							else
								return FAIL;
						case SQLOFFSET:
							if (GetOffsetInfo(dbproc))
							{
								dbproc->token = 0;
								break;
							}
							else
								return FAIL;
						case SQLRETURNSTATUS:
							if (GetReturnStatus(dbproc, Size))
							{
								ReturnStatus = 1;
								dbproc->token = 0;
								break;
							}else
								return FAIL;
						case SQLPROCID:
							if (GetProcID(dbproc))
							{
								dbproc->token = 0;
								break;
							}
							else
								return FAIL;
						case SQLCOLNAME:
							if (GetColNameInfo(dbproc, Size))
							{
								dbproc->token = 0;
								break;
							}
							else
								return FAIL;
						case SQLTABNAME:
							if (GetTabName(dbproc, Size))
							{
								dbproc->token = 0;
								break;
							}
							else
								return FAIL;
						case SQLCOLINFO:
							if (GetBrowseColumnInfo(dbproc, Size))
							{
								dbproc->token = 0;
								break;
							}
							else
								return FAIL;
						case SQLALTNAME:
							if (GetAltColNameInfo(dbproc, Size))
							{
								dbproc->token = 0;
								break;
							}
							else
								return FAIL;
						case SQLALTFMT:
							if (GetAltColFormat(dbproc, Size))
							{
								dbproc->token = 0;
								break;
							}
							else
								return FAIL;
						case SQLORDER:
							if (GetOrderbys(dbproc, Size))
							{
								dbproc->token = 0;
								break;
							}
							else
								return FAIL;
						case SQLERROR:
						case SQLINFO:
							if (HandleInfoToken(dbproc, Size) == 1)
							{
								dbproc->token = 0;
								break;
							}
							else
								return FreeOnError(0, dbproc);
						case SQLRETURNVALUE:
							if (GetReturnVal(dbproc, Size))
							{
								dbproc->token = 0;
								break;
							}
							else
								return FAIL;
						case SQLLOGINACK: // login ack
/*
	   <LOGINACK>
		 <TokenType>
		   <BYTE>AD </BYTE>
		 </TokenType>
		 <Length>
		   <USHORT>20 00 </USHORT>
		 </Length>
		 <Interface>
		   <BYTE>01 </BYTE>
		 </Interface>
		 <TDSVersion>
		   <DWORD>04 02 00 00 </DWORD>
		 </TDSVersion>
		 <ProgName>
		   <B_VARCHAR>
			 <BYTE>16 </BYTE>
			 <BYTES ascii="Microsoft SQL Server..">4D 69 63 72 6F 73 6F 66 74 20 53 51 4C 20 53 65 72 76 65 72 00 00 </BYTES>
		   </B_VARCHAR>
		 </ProgName>
		 <ProgVersion>
		   <DWORD>5f 0b 00 ff </DWORD>
		 </ProgVersion>
	   </LOGINACK>
*/
							lpMem = AllocateHeapMemory(4, dbproc, Size, 0);
							if (!lpMem)
								return FAIL;
							if (dbproc->CommLayer->rbytes
								&& Size <= dbproc->CommLayer->wbytes
								&& Size <= dbproc->CommLayer->length - dbproc->CommLayer->rbytes)
							{
								memmove(lpMem, &dbproc->CommLayer->buffer0[dbproc->CommLayer->rbytes], Size);
								dbproc->CommLayer->rbytes += Size;
								dbproc->CommLayer->wbytes -= Size;
								result = 1;
							}
							else
							{
								result = getbytes_internal(dbproc, (BYTE*)lpMem, Size);
							}
							if (result)
							{
								dbproc->ver = *((BYTE*)lpMem + 2) | (16 * *((BYTE*)lpMem + 1));
								l0 = *((BYTE*)lpMem + 5) + 6;
								if (*((BYTE*)lpMem + l0) == 0x5F)
								{
									dbproc->bServerType = 1;
									dbproc->ServerMajor = *((BYTE*)lpMem + l0 + 1);
									dbproc->ServerMinor = *((BYTE*)lpMem + l0 + 2);
									dbproc->ServerRevision = *((BYTE*)lpMem + l0 + 3);
								}
								else
								{
									dbproc->bServerType = 0;
								}
								FreeMemory(dbproc, lpMem);
								dbproc->token = 0;
								break;
							}else
								return FAIL;
						case SQLCONTROL:
							if (GetControlInfo(dbproc, Size))
							{
								dbproc->token = 0;
								break;
							}
							else
								return FAIL;
						case SQLALTCONTROL:
							if (GetAltControlInfo(dbproc, Size))
							{
								dbproc->token = 0;
								break;
							}
							else
								return FAIL;
						case SQLROW:
						case SQLALTROW:
							dbproc->severity_level = EXINFO;
							dbproc->cmd_flag |= 0x10u;
							dbproc->cmd_flag |= 0x20u;
							return SUCCEED;
						case 0xED: // Security Support Provider Interface
							sspiBuf = (BYTE*)AllocateHeapMemory(4, dbproc, Size, 0);
							if (!sspiBuf)
								return FAIL;
							if (dbproc->CommLayer->rbytes
								&& Size <= dbproc->CommLayer->wbytes
								&& Size <= dbproc->CommLayer->length - dbproc->CommLayer->rbytes)
							{
								memmove(sspiBuf, &dbproc->CommLayer->buffer0[dbproc->CommLayer->rbytes], Size);
								dbproc->CommLayer->rbytes += Size;
								dbproc->CommLayer->wbytes -= Size;
								result = 1;
							}
							else
							{
								result = getbytes_internal(dbproc, sspiBuf, Size);
							}
							if (!result)
							{
								FreeMemory(dbproc, sspiBuf);
								return FAIL;
							}
							if (Size != 36 || strncmp("d5bf8d50-451e-11d1-968d-e4b783000000", (char*)sspiBuf, 0x24u))
								goto LABEL_131;
							FreeMemory(dbproc, sspiBuf);
							sspiBuf = 0;
							MaxCount = 0;
							if (g_fSSPIInit)
								goto LABEL_128;
							if (InitSSPIPackage(&dwMaxToken))
							{
								g_fSSPIInit = 1;
							LABEL_128:
								if (InitSession(dbproc))
								{
									dbproc->b_security = 1;
								LABEL_131:
									dwMaxToken = g_cbMaxToken;
									ptkbuf = (BYTE*)AllocateHeapMemory(4, dbproc, g_cbMaxToken, 0);
									if (ptkbuf)
									{
										if (GenClientContext(dbproc, sspiBuf, MaxCount, ptkbuf, &dwMaxToken, &ret, null_string))
										{
											*dbproc->CommLayer->buffer1 = PT_SSPI;
											if (queuepacket(dbproc, ptkbuf, dwMaxToken))
											{
												if (sendflush(dbproc))
												{
													FreeMemory(dbproc, sspiBuf);
													FreeMemory(dbproc, ptkbuf);
													dbproc->token = 0;
													break;
												}
											}
										}
										FreeMemory(dbproc, sspiBuf);
										FreeMemory(dbproc, ptkbuf);
										result = FAIL;
									}
									else
									{
										if (sspiBuf)
											FreeMemory(dbproc, sspiBuf);
										result = FAIL;
									}
								}
								else
								{
									result = FAIL;
								}
							}
							else
							{
								result = FAIL;
							}
							return result;
						case SQLDONE:
						case SQLDONEPROC:
						case SQLDONEINPROC:
							if (ReturnStatus)
								ReturnStatus = 0;
							done = HandleDoneToken(dbproc, Size, dbproc->token, 1);
							if (done == -5)
							{
								if (dbproc->token != SQLDONEPROC || (dbproc->ret_status & 0x20) == 0)
								{
									dbproc->token = 0;
									break;
								}
								else
								{
									dbproc->token = 0;
									return SUCCEED;
								}
							}
							else
							{
								dbproc->token = 0;
								return done;
							}
						default:
							// "Possible network error: Bad token from SQL Server: Datastream processing out of sync."
							GeneralError(dbproc, SQLEBTOK);
							dbproc->severity_level = 0;
							dbproc->token = 0;
							return FAIL;
						}

					}
					else
					{
						return FAIL;
					}
				}
			}
			else
			{
				dbproc->token = 0;
				return FAIL;
			}

		}
	}
	return result;
}

LPCBYTE __cdecl dbretdata(PDBPROCESS dbproc, int retnum)
{
	retval_t* rval = 0; 

	if (!CheckEntry(dbproc))
		return 0;
	if (retnum > dbproc->numrets || retnum < 1)
		return 0;
	rval = ReturnRequestedRetval(dbproc, retnum);
	if (rval)
		return rval->values;
	else
		return 0;
}


int __cdecl dbretstatus(PDBPROCESS dbproc)
{
	if (CheckEntry(dbproc))
		return dbproc->return_status;
	else
		return -1;
}
int __cdecl dbretlen(PDBPROCESS dbproc, int retnum)
{
	retval_t* rval = 0;

	if (!CheckEntry(dbproc))
		return -1;
	if (retnum > dbproc->numrets || retnum < 1)
		return -1;
	rval = ReturnRequestedRetval(dbproc, retnum);
	if (rval)
		return rval->retlen;
	else
		return -1;
}
/*
BOOL ConnectionError(void *a1, int *lpId, char **a3, int *a4)
{
  if ( lpId )
	*lpId = *((unsigned __int16 *)a1 + 11); // 16h
  if ( a4 )
	*a4 = *((unsigned __int16 *)a1 + 12); // 18h
  if ( a3 )
	*a3 = (char *)a1 + 32; // 20h
  return 1;
}
*/
int __cdecl DbConnectionError(PDBPROCESS dbproc, int* lpId, char** lpErrString, int* lpErr)
{
	// BOOL (__cdecl* CONNECTIONERROR)(void*, NETERR*, char**, NETERR*);
	if (dbproc->CommLayer->ConnectionError)
		return dbproc->CommLayer->ConnectionError(dbproc->conn_object, lpId, lpErrString, lpErr);
	else
		return 0;
}
LPSTR __cdecl GetConnectionError(PDBPROCESS dbproc, int* lpId, char** lpErrString)
{
	int err = 0;
	LPSTR lpBuffer = 0;
	int ID = 0;

	lpBuffer = (LPSTR)TlsGetValue(TlsErrIndex);
	err = 0;
	ID = 0;
	*lpId = -1;
	*lpErrString = 0;
	if (DbConnectionError(dbproc, &ID, lpErrString, &err))
	{
		*lpId = ID;
		if (err <= 0 || err > 20)
		{
			return 0;
		}
		else
		{
			LoadStringLocal(DbHandle, err + 11000, lpBuffer, 0xFFu);
			return lpBuffer;
		}
	}
	else
	{
		*lpId = -1;
		*lpErrString = 0;
		return 0;
	}
}

int __stdcall CheckEntrySkipDead(PDBPROCESS dbproc)
{
	if (dbproc)
	{
		if (CheckForValidDbproc(dbproc))
		{
			return 1;
		}
		else
		{
			GeneralError(0, SQLEPARM);
			return 0;
		}
	}
	else
	{
		GeneralError(0, SQLENULL);
		return 0;
	}
}
int __stdcall CheckEntry(PDBPROCESS dbproc)
{
	if (!CheckEntrySkipDead(dbproc))
		return 0;
	if (!dbproc->bclosed)
		return 1;
	GeneralError(dbproc, SQLEDDNE);
	return 0;
}
BOOL __stdcall isleapyear(int yr)
{
	return !(yr % 4) && yr % 100 || !(yr % 400);
}
void __stdcall YearDayToYrMoDay(int year, int yrday, int* mon, int* monday)
{
	int i = 0;
	int d = 0;
	int m = 0;

	m = 0;
	d = 0;
	for (i = 0; i < 12; ++i)
	{
		if (yrday > MonthDay[i] && yrday <= MonthDay[i + 1])
		{
			d = yrday - MonthDay[i];
			m = i + 1;
			if (isleapyear(year))
			{
				if (i >= 2 && !--d)
				{
					m = i;
					if (i == 2) // 闰年的2月只有29天
						d = 29;
					else
						d = yrday - 1 - MonthDay[i - 1];
				}
			}
			break;
		}
	}
	*mon = m;

	*monday = d;

}
int __stdcall LeapCount(int year)
{
	if (year >= 0)
		return (((year + 52) / 100 + 1) >> 2) + (year >> 2) - (year + 52) / 100;
	else
		return 0;
}
int __stdcall DtdaysToYearDay(int dtday, int* year, int* day)
{
	int y = 0;
	int d = 0;
	int yd = 0;

	if (dtday < -53690)
		return 0;
	yd = dtday + 53690;
	for (y = yd / 365; ; --y)
	{
		d = yd - (LeapCount(y) + 365 * y);
		if (d >= 0)
			break;
	}
	*year = y + 1753;
	*day = d + 1;
	return 1;
}
/*
* DBDATETIME
* dtdays - stores the date and the valid range is -53690 (1753-01-01) to 2958463 (9999-12-31)
* dttime - stores the time and the valid range is 0 to 25919999 (1/300 second intervals in a day),
*          the maximum number of discrete values that a datetime value can store is 3012154 * 25920000 = 78075031680000.
*/
int msdblib_datecrack(DBPROCESS* dbproc, DBDATEREC* dt, DBDATETIME* datetime)
{

	int d = 0;
	int d1 = 0;

	if (!dbproc)
		return 0;
	if (!dt)
		return 0;
	if (!datetime)
		return 0;

	d = datetime->dtdays + 53690;
	if (!DtdaysToYearDay(datetime->dtdays, &dt->year, &dt->dayofyear))
		return 0;

	d1 = d - dt->dayofyear;
	dt->weekday = d % 7 + 1;

	dt->week = ((d1 + 1) % 7 + dt->dayofyear - 1) / 7 + 1;
	YearDayToYrMoDay(dt->year, dt->dayofyear, &dt->month, &dt->day);
	dt->quarter = (dt->month - 1) / 3 + 1;

	if (datetime->dttime > 25919999)
		return 0;
	dt->millisecond = (int)(10 * datetime->dttime / 3) % 1000;
	dt->second = (int)(10 * datetime->dttime / 3) / 1000 % 60;
	dt->minute = (int)(10 * datetime->dttime / 3) / 1000 / 60 % 60;
	dt->hour = (int)(10 * datetime->dttime / 3) / 1000 / 60 / 60;
	return 1;
}
BOOL __cdecl sub_7332C5F0(LCID Locale, LCTYPE LCType, LPSTR pDst, int cchData)
{
	char pSrc[1004] = { 0 };
	WCHAR LCData[1002] = { 0 };

	if (cchData > 1000)
		return 0;
	if (fNTIsRunning)
	{
		if (!GetLocaleInfoW(Locale, LCType, LCData, cchData))
			return 0;
		if (!CharToOemW(LCData, pDst))
			return 0;
	}
	else
	{
		if (!GetLocaleInfoA(Locale, LCType, pSrc, cchData))
			return 0;
		if (!CharToOemA(pSrc, pDst))
			return 0;
	}
	return GetConsoleCP() || OemToCharA(pDst, pDst);
}
int __cdecl sub_7332C6C0(LCID Locale, WORD* a2)
{
	char pDst[4] = { 0 };

	if (!sub_7332C5F0(Locale, SQLIMAGE, pDst, 2))
		return 0;
	switch (pDst[0])
	{
	case '0':
		*a2 = 2;
		break;
	case '1':
		*a2 = 1;
		break;
	case '2':
		*a2 = 3;
		break;
	}
	return 1;
}
void __stdcall SetDtmDefaults()
{
	const char* p = 0; 
	int i = 0; 

	if (!bDtm)
	{
		bDtm = 1;
		for (i = 0; i < 12; ++i)
		{
			if (IsDBCSLeadByte(0xF0u))
				p = DefaultSMonthsFE[i];
			else
				p = DefaultSMonths[i];
			strcpy(SMonths[i], p);
		}
		DTM_FORMAT = DefaultMnyFlags | DefaultTimeFlags | DefaultDateFlags;
		strcpy(MnySign, DefaultMnySign);
		strcpy(DeciSep, DefaultDeciSep);
		strcpy(ThouSep, DefaultThouSep);
	}
}
/*
* Specify Use of Foreign Characters With Microsoft SQL Server
*/
int __cdecl GetUseIntlSettings()
{
	BYTE Data[4] = { 0 };
	LSTATUS sta = 0;
	HKEY phkResult = 0;
	DWORD cbData = 0;

	phkResult = 0;
	cbData = 4;
	if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\MSSQLServer\\Client\\DB-Lib", 0, 0x20019u, &phkResult))
		return 0;
	sta = RegQueryValueExA(phkResult, "UseIntlSettings", 0, 0, Data, &cbData);
	RegCloseKey(phkResult);
	if (sta)
		return 0;
	Data[cbData] = 0;
	if (!_stricmp("ON", (const char*)Data))
		return 2048;
	else
		return 0;
}
int __cdecl sub_7332C5A0(LCID Locale, char* mon)
{
	int i = 0; 

	for (i = 0; i < 12; ++i)
	{
		if (!sub_7332C5F0(Locale, i + 68, &mon[7 * i], 7))
			return 0;
	}
	return 1;
}
int __cdecl sub_7332C730(LCID Locale, WORD* a2)
{
	char pDst[4] = { 0 };

	if (!sub_7332C5F0(Locale, SQLTEXT, pDst, 2))
		return 0;
	if (pDst[0] == '0')
	{
		*a2 = 0;
	}
	else if (pDst[0] == '1')
	{
		*a2 = 4;
	}
	return 1;
}
int __cdecl sub_7332C790(LCID Locale, WORD* a2)
{
	char pDst[4] = { 0 };

	if (!sub_7332C5F0(Locale, 0x1Bu, pDst, 2))
		return 0;
	switch (pDst[0])
	{
	case '0':
	case '2':
		*a2 = 0;
		break;
	case '1':
	case '3':
		*a2 = 32;
		break;
	default:
		return 1;
	}
	return 1;
}
BOOL __cdecl sub_7332C800(LCID Locale, LPSTR pDst)
{
	return sub_7332C5F0(Locale, 0x14u, pDst, 10);
}
BOOL __cdecl sub_7332C830(LCID Locale, LPSTR pDst)
{
	return sub_7332C5F0(Locale, 0xEu, pDst, 5);
}
BOOL __cdecl sub_7332C860(LCID Locale, LPSTR pDst)
{
	return sub_7332C5F0(Locale, 0xFu, pDst, 5);
}
int __stdcall GetDtmFormat()
{
	__int16 form = 0; 
	int i = 0;
	int Locale = 0; 
	char pmon[12][7] = {0};

	int fmt = 0; 
	char Str[8] = {0};
	char pDst[12] = { 0 };


	SetDtmDefaults();
	Locale = GetUseIntlSettings();
	if (!Locale)
		return 1;
	if (sub_7332C5A0(Locale, &pmon[0][0]))
	{
		for (i = 0; i < 12; ++i)
			strcpy(SMonths[i], pmon[i]);
	}
	if (sub_7332C6C0(Locale, (WORD*) &fmt))
	{
		char h = HIBYTE(DTM_FORMAT);
		char l = DTM_FORMAT & 0xFC;
		form = l | h << 8;
		DTM_FORMAT = fmt | form;
	}
	if (sub_7332C730(Locale, (WORD*)&fmt))
		DTM_FORMAT = fmt | DTM_FORMAT & 0xFFFB;
	if (sub_7332C790(Locale, (WORD*)&fmt))
		DTM_FORMAT = fmt | DTM_FORMAT & 0xFFDF;
	if (sub_7332C800(Locale, pDst) && strlen(pDst))
		strcpy(MnySign, pDst);
	if (sub_7332C830(Locale, Str) && strlen(Str))
		strcpy(DeciSep, Str);
	if (sub_7332C860(Locale, Str))
	{
		if (strlen(Str))
			strcpy(ThouSep, Str);
	}

	return 1;
}

LSTATUS __stdcall CheckForClientCursors()
{
	LSTATUS result = 0; 
	BYTE Data[4] = { 0 };
	LSTATUS sta = 0;
	HKEY phkResult = 0; 
	DWORD cbData = 0;

	phkResult = 0;
	cbData = 4;
	UseClientCursors = 0;
	// 一般返回 ERROR_FILE_NOT_FOUND
	result = RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\MSSQLServer\\Client\\DB-Lib", 0, 0x20019u, &phkResult);
	if (result != ERROR_SUCCESS)
	{
		sta = RegQueryValueExA(phkResult, "UseClientCursors", 0, 0, Data, &cbData);
		result = RegCloseKey(phkResult);
		if (!sta)
		{
			Data[cbData] = 0;
			result = _stricmp("ON", (const char*)Data);
			if (!result)
				UseClientCursors = 1;
		}
	}
	return result;
}
LSTATUS __stdcall CheckForDataReadySleep()
{
	LSTATUS result = 0; 
	DWORD Type = 0; 
	BYTE Data[4] = { 0 };
	LSTATUS sta = 0; 
	HKEY phkResult = 0; 
	DWORD cbData = 0; 

	phkResult = 0;
	DataReadySleep = 250;
	result = RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\MSSQLServer\\Client\\DB-Lib", 0, 0x20019u, &phkResult);
	if (result != ERROR_SUCCESS)
	{
		sta = RegQueryValueExA(phkResult, "DataReadySleep", 0, &Type, Data, &cbData);
		result = RegCloseKey(phkResult);
		if (!sta && Type == 4 && (*(_DWORD*)Data <= 0x3E8u || *(_DWORD*)Data == -1))
		{
			result = *(_DWORD*)Data;
			DataReadySleep = *(_DWORD*)Data;
		}
	}
	return result;
}


BOOL __cdecl OpenUuidKeysIfNecessary()
{
	DWORD dwDisposition = 0;

	return hKey || !RegCreateKeyExA(HKEY_LOCAL_MACHINE, "Software\\Description\\Microsoft\\Rpc\\UuidTemporaryData", 0, null_string, 1u, 3u, 0, &hKey, &dwDisposition);
}
int __stdcall GetNodeIdFromRegistry(LPBYTE lpData)
{
	DWORD cbData = 0;
	BYTE Data[4] = { 0 };

	if (!OpenUuidKeysIfNecessary())
		return 1739;
	cbData = 6;
	if (RegQueryValueExA(hKey, "NetworkAddress", 0, 0, lpData, &cbData))
		return 1739;
	cbData = 4;
	if (RegQueryValueExA(hKey, "NetworkAddressLocal", 0, 0, Data, &cbData))
		return 1739;
	else
		return *(DWORD*)Data != 0 ? 1824 : 0;
}
void __cdecl CloseUuidKeys()
{
	if (hKey)
	{
		RegCloseKey(hKey);
		hKey = 0;
	}
}
int __stdcall GetNodeIdFromNetbios(BYTE* lpData)
{
	int i = 0; 

	struct _NCB ncb_; 
	char buf[636] = { 0 };

	for (i = 0; i < 8; ++i)
	{
		memset(&ncb_, 0, sizeof(ncb_));
		ncb_.ncb_lsn = 0;
		ncb_.ncb_command = NCBRESET;
		ncb_.ncb_lana_num = i;
		ncb_.ncb_callname[0] = 12;
		ncb_.ncb_length = sizeof(ncb_);
		Netbios(&ncb_);
		ncb_.ncb_command = NCBASTAT;
		ncb_.ncb_buffer = (PUCHAR)buf;
		ncb_.ncb_length = 636;
		ncb_.ncb_callname[0] = '*';
		ncb_.ncb_callname[1] = 0;
		Netbios(&ncb_);
		if (ncb_.ncb_retcode == NRC_GOODRET)
			break;
	}
	if (i == 8)
		return 1739;

	ADAPTER_STATUS* sta = (ADAPTER_STATUS*)buf;
	*(_DWORD*)lpData = *(_DWORD*)sta->adapter_address;
	*((WORD*)lpData + 2) = *(WORD*)&sta->adapter_address[4];
	return 0;
}

int __stdcall GetNodeIdFromIPX(BYTE* lpData)
{
	HANDLE hFile = 0; 

	int InBuffer = 0; 
	char OutBuffer[10] = { 0 };
	DWORD BytesReturned = 0; 
	_OSVERSIONINFOW VersionInformation; 

	VersionInformation.dwOSVersionInfoSize = sizeof(_OSVERSIONINFOW); // 276;
	GetVersionExW(&VersionInformation);
	if ((VersionInformation.dwPlatformId & VER_PLATFORM_WIN32_NT) != 0)
		return 1739;
	hFile = CreateFileA("\\\\.\\NWLINK", 0x40000000u, 2u, 0, 3u, 0x80u, 0);
	if (hFile == INVALID_HANDLE_VALUE)
		return 1739;
	InBuffer = 9;
	if (DeviceIoControl(hFile, 0x100u, &InBuffer, 4u, OutBuffer, 10u, &BytesReturned, 0))
	{
		*(_DWORD*)lpData = *(_DWORD*)&OutBuffer[4];
		*((WORD*)lpData + 2) = *(WORD*)&OutBuffer[8];
		CloseHandle(hFile);
		return 0;
	}
	else
	{
		CloseHandle(hFile);
		return 1739;
	}
}
void __stdcall SaveNodeIdInRegistry(BYTE* lpData, BYTE Data)
{
	if (hKey)
	{
		if (!RegSetValueExA(hKey, "NetworkAddress", 0, 3u, lpData, 6u))
			RegSetValueExA(hKey, "NetworkAddressLocal", 0, 4u, &Data, 4u);
	}
}
int __stdcall CookupNodeId(BYTE* lpData)
{
	DWORD i = 0; 
	char* p = 0; 
	char C = 0; 
	DWORD dwKey = 0; 
	DWORD nSize = 0; 
	DWORD SectorsPerCluster = 0; 
	DWORD BytesPerSector = 0;
	DWORD TotalNumberOfClusters = 0; 
	DWORD NumberOfFreeClusters = 0;
	BYTE adapter_address[6] = {0};
	LARGE_INTEGER PerformanceCount; 
	char Buffer[16] = { 0 };
	_MEMORYSTATUS memsta; 

	nSize = 16;
	if (GetComputerNameA(Buffer, &nSize))
	{
		i = 0;
		p = Buffer;
		nSize = 0;
		if (Buffer[0])
		{
			do
			{
				C = *p++ ^ adapter_address[i];
				adapter_address[i++] = C;
				if (i > 6)
					i = 0;
			} while (*p);
			nSize = i;
		}
	}
	if (QueryPerformanceCounter(&PerformanceCount))
	{
		*(_DWORD*)&adapter_address[2] ^= PerformanceCount.HighPart ^ PerformanceCount.LowPart;
		dwKey = PerformanceCount.HighPart ^ PerformanceCount.LowPart ^ *(_DWORD*)adapter_address;
	}
	else
	{
		dwKey = *(_DWORD*)adapter_address;
	}
	memsta.dwLength = 32;
	*(_DWORD*)adapter_address = (unsigned int)adapter_address ^ dwKey;
	*(_DWORD*)&adapter_address[2] ^= (unsigned int)adapter_address;
	GlobalMemoryStatus(&memsta);
	*(_DWORD*)adapter_address ^= memsta.dwMemoryLoad;
	*(_DWORD*)&adapter_address[2] ^= memsta.dwTotalPhys;
	*(_DWORD*)adapter_address ^= memsta.dwTotalPageFile ^ memsta.dwAvailPhys;
	*(_DWORD*)&adapter_address[2] ^= memsta.dwTotalVirtual ^ memsta.dwAvailPageFile;
	*(_DWORD*)adapter_address ^= memsta.dwAvailVirtual;
	if (AllocateLocallyUniqueId((PLUID)&PerformanceCount))
	{
		*(_DWORD*)adapter_address ^= PerformanceCount.LowPart;
		*(_DWORD*)&adapter_address[2] ^= PerformanceCount.HighPart;
	}
	if (GetDiskFreeSpaceA("c:\\", &SectorsPerCluster, &BytesPerSector, &NumberOfFreeClusters, &TotalNumberOfClusters))
	{
		*(_DWORD*)&adapter_address[2] ^= TotalNumberOfClusters * BytesPerSector * SectorsPerCluster;
		*(_DWORD*)adapter_address ^= NumberOfFreeClusters * BytesPerSector * SectorsPerCluster;
	}
	adapter_address[0] |= 0x80u;
	*(_DWORD*)lpData = *(_DWORD*)adapter_address;
	*((WORD*)lpData + 2) = *(WORD*)&adapter_address[4];
	return 1824;
}
int __stdcall GetNode(LPBYTE lpData)
{
	BOOL flag = 0; 
	int NodeIdFromRegistry = 0; 
	int result = 0;

	flag = 0;
	EnterCriticalSection(&CriticalSection);
	NodeIdFromRegistry = GetNodeIdFromRegistry(lpData);
	if (NodeIdFromRegistry == 1824)
	{
		flag = 1;
	}
	else if (!NodeIdFromRegistry)
	{
		CloseUuidKeys();
		LeaveCriticalSection(&CriticalSection);
		return 0;
	}
	if (!GetNodeIdFromNetbios(lpData)
		&& ((*(_DWORD*)lpData | *((unsigned __int16*)lpData + 2)) != 0 ? -1739 : 0) == -1739
		|| !GetNodeIdFromIPX(lpData)
		&& ((*(_DWORD*)lpData | *((unsigned __int16*)lpData + 2)) != 0 ? -1739 : 0) == -1739)
	{
		SaveNodeIdInRegistry(lpData, 0);
		CloseUuidKeys();
		LeaveCriticalSection(&CriticalSection);
		return 0;
	}
	if (flag == 1)
	{
		CloseUuidKeys();
		LeaveCriticalSection(&CriticalSection);
		return 1824;
	}
	else
	{
		result = CookupNodeId(lpData);
		SaveNodeIdInRegistry(lpData, 1u);
		CloseUuidKeys();
		LeaveCriticalSection(&CriticalSection);
		return result;
	}
}


column_data_t* __stdcall GetAltDataPointer(PDBPROCESS dbproc, int nrow, int column)
{
	if (dbproc->altrowdata
		&& dbproc->altrowdata[nrow]
		&& dbproc->altrowdata[nrow]->columnsdata
		&& dbproc->altrowdata[nrow]->columnsdata[column])
	{
		return dbproc->altrowdata[nrow]->columnsdata[column];
	}
	else
	{
		return 0;
	}
}
altcol_link_t* __stdcall GetCompute(PDBPROCESS dbproc, int computeid, int bErr)
{
	altcol_link_t* next = 0; 
	int i = 0; 

	i = 0;
	next = dbproc->altcolinfo;
	if (computeid >= 1 && computeid <= dbproc->n_compute_row)
	{
		while (1)
		{
			if (i >= computeid - 1)
				return next;
			if (!next)
				break;
			next = next->next;
			++i;
		}
		if (bErr)
			GeneralError(dbproc, SQLEICN);              // SQLEICN
		return 0;
	}
	else
	{
		if (bErr)
			GeneralError(dbproc, SQLEICN);
		return 0;
	}
}
/*
* computeid
* The ID that identifies the particular compute row of interest. 
* A SQL select statement may have multiple compute clauses, each of which returns a separate compute row. 
* The computeid corresponding to the first compute clause in a select is 1. 
* The computeid is returned by dbnextrow or dbgetrow.
*/
altcol_link_t* __stdcall CheckAltColumn(PDBPROCESS dbproc, int computeid, int column)
{
	altcol_link_t* pinfo = 0;

	if (dbproc)
	{
		if (CheckForValidDbproc(dbproc))
		{
			if (dbproc->bclosed)
			{
				GeneralError(dbproc, SQLEDDNE);
				return 0;
			}
			else
			{
				pinfo = GetCompute(dbproc, computeid, 1);
				if (pinfo)
				{
					if (column <= pinfo->n_alts && column >= 1)
					{
						return pinfo;
					}
					else
					{
						GeneralError(dbproc, SQLECNOR);
						return 0;
					}
				}
				else
				{
					return 0;
				}
			}
		}
		else
		{
			return 0;
		}
	}
	else
	{
		GeneralError(0, SQLENULL);
		return 0;
	}
}

int __stdcall GetColumnType(PDBPROCESS dbproc, int token, int datalength)
{
	int type = token;
	switch (token)
	{
	case SQLVARBINARY:
		type = SQLBINARY;
		break;
	case SQLINTN:
		switch (datalength)
		{
		case 1:
			type = SQLINT1;
			break;
		case 2:
			type = SQLINT2;
			break;
		case 4:
			type = SQLINT4;
			break;
		}
		break;
	case SQLVARCHAR:
		type = SQLCHAR;
		break;
	case SQLDECIMAL:
		type = SQLDECIMAL;
		break;
	case SQLNUMERIC:
		type = SQLNUMERIC;
		break;
	case SQLFLTN:
		type = SQLFLT8;
		if (datalength == 4)
			type = SQLFLT4;
		break;
	case SQLMONEYN:
		type = SQLMONEY;
		if (datalength == 4)
			type = SQLMONEY4;
		break;
	case SQLDATETIMN:
		type = SQLDATETIME;
		if (datalength == 4)
			type = SQLDATETIM4;
		break;
	default:
		return type;
	}
	return type;
}


int __stdcall TypeToConvert(int Type)
{
	int result = 0;

	switch (Type)
	{
	case SQLIMAGE:
		result = 3;
		break;
	case SQLTEXT:
		result = 1;
		break;
	case SQLVARBINARY:
	case SQLBINARY:
		result = 2;
		break;
	case SQLINTN:
	case SQLINT4:
		result = 6;
		break;
	case SQLVARCHAR:
	case SQLCHAR:
		result = 0;
		break;
	case SQLINT1:
		result = 4;
		break;
	case SQLBIT:
		result = 8;
		break;
	case SQLINT2:
		result = 5;
		break;
	case SQLDATETIM4:
		result = 13;
		break;
	case SQLFLT4:
		result = 11;
		break;
	case SQLMONEY:
	case SQLMONEYN:
		result = 9;
		break;
	case SQLDATETIME:
	case SQLDATETIMN:
		result = 10;
		break;
	case SQLFLT8:
	case SQLFLTN:
		result = 7;
		break;
	case SQLDECIMAL:
	case SQLNUMERIC:
		result = 15;
		break;
	case SQLMONEY4:
		result = 12;
		break;
	default:
		result = -1;
		break;
	}
	return result;
}


/*
* get printable length
*/
__int16 __stdcall GetColumnPrLength(__int16 ColumnType, __int16 length, int col_width)
{
	__int16 len = 0;
	__int16 datlen = 0; 


	switch (ColumnType)
	{
	case SQLIMAGE:
		return 256;
	case SQLTEXT:
		if (length <= col_width)
			len = col_width;
		else
			len = length;
		if (len >= 256)
			return 256;
		else
			return len;
	case SQLINTN:
		switch (col_width)
		{
		case 1:
			datlen = 4;
			break;
		case 2:
			datlen = 6;
			break;
		case 4:
			datlen = 11;
			break;
		}
		break;
	case SQLINT1:
		datlen = 3;
		break;
	case SQLBIT:
		datlen = 3;
		break;
	case SQLINT2:
		datlen = 6;
		break;
	case SQLINT4:
		datlen = 11;
		break;
	case SQLDATETIM4:
	case SQLDATETIME:
	case SQLDATETIMN:
		datlen = 27;
		break;
	case SQLFLT4:
	case SQLFLT8:
	case SQLFLTN:
		datlen = 20;
		break;
	case SQLMONEY:
	case SQLMONEYN:
	case SQLMONEY4:
		datlen = 26;
		break;
	case SQLDECIMAL:
		datlen = 40;
		break;
	case SQLNUMERIC:
		datlen = 40;
		break;
	default:
		datlen = 0;
	}

	int l = col_width;
	if (col_width < datlen)
		l = datlen;
	if (l < length)
		l = length;
	if (ColumnType == SQLIMAGE || ColumnType == SQLVARBINARY || ColumnType == SQLBINARY)
		return 2 * l + 2;
	return l;
	
}
double* __stdcall SmallMoneyToDouble(int* Src, double* lpValue)
{
	double* result = 0;

	*lpValue = (double)*Src;
	result = lpValue;
	*lpValue = *lpValue / 10000.0;
	return result;
}
DWORD __cdecl numeric_div(numeric_t* a, numeric_t* b, DWORD* pmod)
{
	unsigned int result; 
	int i = 0; 
	unsigned int mod, val;

	mod = 0;
	for (i = b->size - 1; i >= 0; --i)
	{
		val = b->values[i] + (mod << 8);
		a->values[i] = val / 10;
		mod = val % 10;
	}
	for (i = a->size - 1; i > 0 && !a->values[i]; --i)
		;
	a->size = i + 1;
	result = mod;
	*pmod = mod;
	return result;
}
char str0123456789[] = "0123456789";
/*
* Src - dbnumeric
*/
int __cdecl numerictostring(DBNUMERIC* Src, BYTE Size, BYTE* lpString, int max)
{
	int scale = 0;
	int l1 = 0;
	char buf[128] = { 0 };
	int i = 0;
	numeric_t numeric;
	char buf1[80] = { 0 };
	char* p = buf1;
	DWORD index = 0;
	int maxa = 0;
	i = 0;
	numeric.values = (BYTE*)buf;
	dbmove(Src->val, buf, Size);
	numeric.size = Size;
	numeric.sign = Src->sign;
	if (Size > 1u || Src->val[0])
	{
		while (numeric.size > 1 || *buf)
		{
			numeric_div(&numeric, &numeric, &index);
			*p++ = str0123456789[index];
			++i;
		}
	}
	else
	{
		numeric.sign = 0;
		*p++ = 48;
	}
	while (i <= Src->scale) // scale
	{
		*p++ = str0123456789[0];
		++i;
	}
	maxa = i;
	if (!numeric.sign)
	{
		*lpString++ = '-';
		++maxa;
	}
	while (i)
	{
		scale = Src->scale;
		l1 = i--;
		if (l1 == scale)
		{
			*lpString++ = '.';
			++maxa;
		}
		*lpString++ = *--p;
	}
	if (*lpString == '.')
		*lpString = 0;
	return 1;
}
int __cdecl ConvertNumericDecimalToChar(DBNUMERIC* Src, char* lpString)
{
	BYTE buf[80] = { 0 };
	int i = 0; 

	memset(buf, 0, sizeof(buf));
	for (i = 0; i < 80; ++i)
		buf[i] = 0;
	if (!numerictostring(Src, 0x10u, buf, 80))
		return 0;
	strcpy(lpString, (char*)buf);
	return 1;
}
int __stdcall IsValidNumber(char* lpSrc, int DataType)
{

	char* p = (char*)lpSrc;

	while (1)
	{
		if (!*p)
			return 1;
		if (*p < '0' || *p > '9')
		{
			if (*p != '+' && *p != '-')
			{
				if (*p == ' ')
					return 1;

				switch (DataType)
				{
				case SQLINT1:
				case SQLINT2:
				case SQLINT4:
					return 0;
				case SQLFLT4:
				case SQLFLT8:
					if (*p == '.' || *p == 'e' || *p == 'E')
						break;
					else {
						return 0;
					}
				case SQLDECIMAL:
				case SQLNUMERIC:
					if (*p == '.')
						break;
					else {
						return 0;
					}
				default:
					break;
				}
			}
	
		}

		++p;
	}
	return 0;
	

}
double __stdcall FloatToDouble(float value)
{
	char* DstBuf = 0; 
	double val = 0; 

	DstBuf = (char*)AllocateHeapMemory(4, 0, SQLMONEY, 1);
	if (!DstBuf)
		return 0.0;
	// Converts a floating-point value to a string
	_gcvt(value, 6, DstBuf);
	val = atof(DstBuf);
	FreeMemory(0, DstBuf);
	return val;
}
double* __stdcall MoneyToDouble(BYTE* Src, double* lpValue)
{
	double* result = 0;

	*lpValue = (double)*(int*)Src;
	*lpValue = *lpValue * 4294967296.0;
	*lpValue = (double)*((unsigned int*)Src + 1) + *lpValue;
	result = lpValue;
	*lpValue = *lpValue / 10000.0;
	return result;
}

int __cdecl ConvertToFloat(PDBPROCESS dbproc, int DataType, BYTE* Src, int Length, int dtOut, double* lpValue)
{
	int SiZ = 0;
	char Destination[104] = { 0 };
	int Count = 0;

	switch (DataType)
	{
	case SQLIMAGE:
	case SQLBINARY:
		if (Length >= 8)
		{
			dbmove(Src, lpValue, 8u);
		}
		else
		{
			dbzero(lpValue, 8u);
			dbmove(Src, lpValue, Length);
		}
		break;
	case SQLTEXT:
	case SQLCHAR:
		if (Length == -1)
		{
			strcpy(Destination, (char*)Src);
		}
		else
		{
			if (Length >= 100)
				SiZ = 100;
			else
				SiZ = Length;
			Count = SiZ;
			strncpy(Destination, (char*)Src, SiZ);
			Destination[Count] = 0;
		}
		if (IsValidNumber(Destination, 62))
			*lpValue = atof(Destination);
		else
			GeneralError(dbproc, 10109);
		break;
	case SQLINT1:
		*lpValue = (double)(BYTE)*Src;
		break;
	case SQLBIT:
		if (*Src)
		{
			*lpValue = 1.0;
		}
		else
		{
			*lpValue = 0.0;
		}
		break;
	case SQLINT2:
		*lpValue = (double)*(__int16*)Src;
		break;
	case SQLINT4:
		*lpValue = (double)*(int*)Src;
		break;
	case SQLFLT4:
		*lpValue = FloatToDouble(*(float*)Src);
		break;
	case SQLMONEY:
		MoneyToDouble(Src, lpValue);
		break;
	case SQLFLT8:
		*lpValue = *(double*)Src;
		break;
	case SQLDECIMAL:
	case SQLNUMERIC:
		ConvertNumericDecimalToDouble((DBNUMERIC*)Src, lpValue);
		break;
	case SQLMONEY4:
		SmallMoneyToDouble((int*)Src, lpValue);
		break;
	default:
		GeneralError(dbproc, 10016);
		break;
	}
	return 1;
}
BOOL __cdecl ConvertNumericDecimalToDouble(DBNUMERIC* Src, double* lpValue)
{
	char buf[80] = { 0 };

	*lpValue = 0.0;
	ConvertNumericDecimalToChar(Src, buf);
	return ConvertToFloat(0, SQLCHAR, (BYTE*)buf, strlen(buf), 0, lpValue) >= 0;
}
BOOL __cdecl ConvertNumericDecimalToLong(DBNUMERIC* Src, int* lpValue)
{
	double X,X1 = 0;
	double Y = 0; 

	if (!ConvertNumericDecimalToDouble(Src, &X))
		return 0;
	X1 = modf(X, &Y);
	*lpValue = (int)Y;
	return (double)*lpValue == Y;
}
int __stdcall CheckIntRange(PDBPROCESS dbproc, BYTE* lpSrc, int DataType, int dtOut)
{
	double val = 0; 
	bool flag = 0; 
	int lVal = 0;
	switch (DataType)
	{
	case SQLIMAGE:
	case SQLBINARY:
	case SQLINT1:
	case SQLBIT:
		return 1;
	case SQLINT2:
		if (dtOut != SQLINT1)
			return 1;
		if (*(__int16*)lpSrc > 255)
		{
			GeneralError(dbproc, SQLECOFL);
			return 0;
		}
		if (*(__int16*)lpSrc < 0)
		{
			GeneralError(dbproc, SQLECOFL);
			return 0;
		}
		return 1;
	case SQLINT4:
		if (dtOut == SQLINT1)
		{
			if (*(int*)lpSrc > 255)
			{
				GeneralError(dbproc, SQLECOFL);
				return 0;
			}
			if (*(int*)lpSrc >= 0)
				return 1;
		}
		else
		{
			if (*(int*)lpSrc > 0x7FFF)
			{
				GeneralError(dbproc, SQLECOFL);
				return 0;
			}
			if (*(int*)lpSrc >= -32768)
				return 1;
		}
		GeneralError(dbproc, SQLECOFL);
		return 0;
	case SQLFLT4:
		val = *(float*)lpSrc;
		if (dtOut == SQLINT1)
		{
			if (val > 255.5)
			{
				GeneralError(dbproc, SQLECOFL);
				return 0;
			}
			flag = *(float*)lpSrc < 0.0;
		}
		else
		{
			if (val > 32767.5)
			{
				GeneralError(dbproc, SQLECOFL);
				return 0;
			}
			flag = *(float*)lpSrc < -32768.5;
		}
		if (flag)
		{
			GeneralError(dbproc, SQLECOFL);
			return 0;
		}
		else
			return 1;
	case SQLMONEY:
		MoneyToDouble(lpSrc, &val);
		if (dtOut != SQLINT1)
		{
			if (val > 32767.5)
			{
				GeneralError(dbproc, SQLECOFL);
				return 0;
			}
			if (val < -32768.5)
			{
				GeneralError(dbproc, SQLECOFL);
				return 0;
			}
			else
				return 1;
		}
		if (val > 255.5 || val < 0.0)
		{
			GeneralError(dbproc, SQLECOFL);
			return 0;
		}
		return 1;
	case SQLFLT8:
		val = *(double*)lpSrc;
		if (dtOut == SQLINT1)
		{
			if (val > 255.0)
			{
				GeneralError(dbproc, SQLECOFL);
				return 0;
			}
			if (*(double*)lpSrc < -0.5)
			{
				GeneralError(dbproc, SQLECOFL);
				return 0;
			}else
				return 1;
		}
		else
		{
			if (val > 32767.0)
			{
				GeneralError(dbproc, SQLECOFL);
				return 0;
			}
			if (*(double*)lpSrc < -32769.0)
			{
				GeneralError(dbproc, SQLECOFL);
				return 0;
			}else
				return 1;
		}
		
	case SQLDECIMAL:
	case SQLNUMERIC:
		if (!ConvertNumericDecimalToLong((DBNUMERIC*)lpSrc, &lVal))
		{
			GeneralError(dbproc, SQLECOFL);
			return 0;
		}
		if (dtOut != SQLINT1)
			return 1;
		val = (double)(int)lVal;
		if (val > 255.0 || val < -0.5 || val > 32767.0)
		{
			GeneralError(dbproc, SQLECOFL);
			return 0;
		}
		if (val < -32769.0)
		{
			GeneralError(dbproc, SQLECOFL);
			return 0;
		}
		return 1;
	case SQLMONEY4:
		SmallMoneyToDouble((int*)lpSrc, &val);
		if (dtOut == SQLINT1)
		{
			if (val > 255.5)
			{
				GeneralError(dbproc, SQLECOFL);
				return 0;
			}
			flag = val < 0.0;
		}
		else
		{
			if (val > 32767.5)
			{
				GeneralError(dbproc, SQLECOFL);
				return 0;
			}
			flag = val < -32768.5;
		}
		if (flag)
		{
			GeneralError(dbproc, SQLECOFL);
			return 0;
		}else
			return 1;
	default:
		GeneralError(dbproc, 10016);
		return 0;
	}
}
BOOL __cdecl ConvertNumericDecimalToULong(DBNUMERIC*Src, DWORD* lpValue)
{
	double X,X1 = 0; 
	double Y = 0; 

	if (!ConvertNumericDecimalToDouble(Src, &X))
		return 0;
	X1 = modf(X, &Y);
	*lpValue = (DWORD)Y;
	return (double)(unsigned int)*lpValue == Y;
}
int __cdecl ConvertToInt(PDBPROCESS dbproc, int DataType, BYTE* Src, int Length, int dtOut, void* lpValue)
{
	int result = 0;
	int iVAl = 0;
	__int16 sVal = 0;
	int SiZ = 0;
	double dblVal = 0;
	int lval = 0;
	int Size = 0;
	DWORD uVal = 0;
	double dblVal1 = 0;
	char Destination[104] = { 0 };

	Size = (dtOut != SQLINT1) + 1;
	if (DataType != SQLCHAR
		&& DataType != SQLTEXT
		&& DataType != SQLMONEY
		&& DataType != SQLMONEY4
		&& !CheckIntRange(dbproc, (BYTE*)Src, DataType, dtOut))
	{
		return -1;
	}
	switch (DataType)
	{
	case SQLIMAGE:
	case SQLBINARY:
		dbzero(lpValue, Size);
		if (Length < Size && Length != -1)
			Size = Length;
		dbmove(Src, lpValue, Size);
		return Size;
	case SQLTEXT:
	case SQLCHAR:
		SiZ = Length;
		if (Length == -1)
		{
			strcpy(Destination, (char*)Src);
		}
		else
		{
			if (Length >= 100)
				SiZ = 100;
			strncpy(Destination, (char*)Src, SiZ);
			Destination[SiZ] = 0;
		}
		if (!IsValidNumber(Destination, dtOut))
		{
			GeneralError(dbproc, 10039);
			return -1;
		}
		lval = atol(Destination);
		if (!CheckIntRange(dbproc, (BYTE*)&lval, SQLINT4, dtOut))
			return -1;
		if (dtOut == SQLINT1)
		{
			*(BYTE*)lpValue = lval;
			return Size;
		}
		else
		{
			*(WORD*)lpValue = lval;
			return Size;
		}
	case SQLINT1:
		if (dtOut == SQLINT1)
		{
			*(BYTE*)lpValue = *Src;
		}else
			*(WORD*)lpValue = (BYTE)*Src;

		return Size;
		break;
	case SQLBIT:
		if (*Src)
		{
			result = Size;
			if (dtOut == 48)
				*(BYTE*)lpValue = 1;
			else
				*(WORD*)lpValue = 1;
		}
		else if (dtOut == 48)
		{
			*(BYTE*)lpValue = 0;
			return Size;
		}
		else
		{
			result = Size;
			*(WORD*)lpValue = 0;
		}
		return result;
	case SQLINT2:
		if (dtOut == 48)
		{
			*(BYTE*)lpValue = *Src;
			return Size;
		}
		else
		{
			result = Size;
			*(WORD*)lpValue = *(WORD*)Src;
		}
		return result;
	case SQLINT4:
		if (dtOut == SQLINT1)
			*(BYTE*)lpValue = *Src;
		else
			*(WORD*)lpValue = *(WORD*)Src;
		return Size;
	case SQLFLT4:
		dblVal = *(float*)Src;
		if (dtOut == SQLINT1)
		{
			iVAl = (int)dblVal;
			*(BYTE*)lpValue = iVAl;
			result = Size;
		}
		*(WORD*)lpValue = (int)dblVal;
		return Size;
	case SQLMONEY:
		MoneyToDouble((BYTE*)Src, &dblVal1);
		if (dblVal1 < 0.0)
			dblVal1 = dblVal1 - 0.5;
		else
			dblVal1 = dblVal1 + 0.5;

		lval = (int)dblVal1;
		if (!CheckIntRange(dbproc, (BYTE*)&lval, SQLINT4, dtOut))
			return -1;
		if (dtOut != SQLINT1)
		{
			*(WORD*)lpValue = lval;
		}else
			*(BYTE*)lpValue = lval;
		return Size;
	case SQLFLT8:
		dblVal = *(double*)Src;
		if (dtOut == SQLINT1)
			*(BYTE*)lpValue = (BYTE)dblVal;
		else
			*(WORD*)lpValue = (int)dblVal;
		return Size;
	case SQLDECIMAL:
	case SQLNUMERIC:
		if (dtOut == SQLINT1)
		{
			result = ConvertNumericDecimalToULong((DBNUMERIC*)Src, &uVal);
			if (!result)
				return result;
			iVAl = (BYTE)uVal;
			if ((BYTE)uVal != uVal)
			{
				GeneralError(dbproc, SQLECOFL);
				return -1;
			}
			*(BYTE*)lpValue = iVAl;
			result = Size;
		}
		else
		{
			result = ConvertNumericDecimalToLong((DBNUMERIC*)Src, (int*)& uVal);
			if (result)
			{
				sVal = (short)uVal;
				if ((short)uVal != uVal)
				{
					GeneralError(dbproc, SQLECOFL);
					return -1;
				}
				*(WORD*)lpValue = sVal;
				result = Size;
			}
		}
		break;
	case SQLMONEY4:
		SmallMoneyToDouble((int*)Src, &dblVal);
		if (dblVal < 0.0)
			dblVal = dblVal - 0.5;
		else
			dblVal = dblVal + 0.5;

		lval = (int)dblVal;
		if (!CheckIntRange(dbproc, (BYTE*)&lval, SQLINT4, dtOut))
			return -1;
		if (dtOut != SQLINT1)
		{
			*(WORD*)lpValue = lval;
		}else
			*(BYTE*)lpValue = (BYTE)lval;
		return Size;
	default:
		GeneralError(dbproc, 10016);
		return -1;
	}
	return result;
}
int __stdcall CheckLongRange(PDBPROCESS dbproc, double value)
{
	if (value <= 2147483647.5 && value >= -2147483648.5)
		return 1;
	GeneralError(dbproc, SQLECOFL);
	return 0;
}
int __cdecl ConvertToLong(PDBPROCESS dbproc, int DataType, BYTE* Src, int Length, int dtOut, void* lpValue)
{
	int L = 0; 
	char* pE = 0; 
	int iVal = 0; 
	BOOL flag = 0; 
	char* p1 = 0; 
	double Value = 0; 

	*(DWORD*)lpValue = 0;
	switch (DataType)
	{
	case SQLIMAGE:
	case SQLBINARY:
		if (Length >= 4)
		{
			dbmove(Src, lpValue, 4u);
		}
		else
		{
			dbzero(lpValue, 4u);
			dbmove(Src, lpValue, Length);
		}
		break;
	case SQLTEXT:
	case SQLCHAR:
		iVal = 0;
		p1 = (char*)Src;
		if (Length == -1)
			L = strlen((const char*)Src);
		else
			L = Length;
		pE = (char*)&Src[L];
		flag = 0;
		while (p1 < pE && (*p1 == ' ' || *p1 == 9))
			++p1;
		while (p1 < pE && (*(pE - 1) == ' ' || *(pE - 1) == 9))
			--pE;
		if (p1 < pE && (*p1 == '-' || *p1 == '+'))
			flag = *p1++ == '-';
		while (p1 < pE)
		{
			if ((char)*p1 < '0' || (char)*p1 > '9')
			{
				GeneralError(dbproc, 10039);
				return 0;
			}
			iVal = (char)*p1++ - '0' + 10 * iVal;
		}
		if (flag)
			iVal = -iVal;
		if ((double)iVal <= 2147483647.5 && (double)iVal >= -2147483648.5)
			*(DWORD*)lpValue = iVal;
		else
			GeneralError(dbproc, SQLECOFL);
		break;
	case SQLINT1:
		*(DWORD*)lpValue = *Src;
		break;
	case SQLBIT:
		if (*Src)
			*(DWORD*)lpValue = 1;
		else
			*(DWORD*)lpValue = 0;
		break;
	case SQLINT2:
		*(DWORD*)lpValue = *(__int16*)Src;
		break;
	case SQLINT4:
		*(DWORD*)lpValue = *(_DWORD*)Src;
		break;
	case SQLFLT4:
		if (CheckLongRange(dbproc, *(float*)Src))
			*(DWORD*)lpValue = (int)*(float*)Src;
		break;
	case SQLMONEY:
		MoneyToDouble(Src, &Value);
		if (Value > 0.0)
			Value = Value + 0.5;
		if (CheckLongRange(dbproc, Value))
			*(DWORD*)lpValue = (int)Value;
		break;
	case SQLFLT8:
		if (CheckLongRange(dbproc, *(double*)Src))
			*(DWORD*)lpValue = (int)*(double*)Src;
		break;
	case SQLDECIMAL:
	case SQLNUMERIC:
		ConvertNumericDecimalToLong((DBNUMERIC*)Src, (int*)lpValue);
		break;
	case SQLMONEY4:
		SmallMoneyToDouble((int*)Src, &Value);
		if (Value > 0.0)
			Value = Value + 0.5;
		if (CheckLongRange(dbproc, Value))
			*(DWORD*)lpValue = (int)Value;
		break;
	default:
		GeneralError(dbproc, 10016);
		break;
	}
	return 0;
}


char gHexstring[] = "0123456789abcdef";
void __stdcall cvttohex(char* Src, char C)
{

	Src[0] = gHexstring[(C & 0xF0) >> 4];
	Src[1] = gHexstring[ C & 0x0F];

}

int __stdcall BinaryToHex(BYTE* Src, char* lpString, int length, int prefix, int length1)
{
	char C = 0;
	int i = 0; 
	int pad = 0;
	int L = 0;

	pad = 0;
	if (length1 == -1)
		L = length;
	else
		L = length1 / 2;
	if (L > length)
		L = length;
	if (prefix)
	{
		strcpy(lpString, "0x");
		pad = 2;
	}
	for (i = 0; ; ++i)
	{
		if (i >= L)
			break;
		C = *Src++;
		cvttohex(&lpString[2 * i + pad], C);
	}
	if (length1 == -1)
		lpString[2 * i + pad] = 0;
	return 2 * i;
}
void __stdcall OverFlowFill(char* Src)
{
	Src[0] = '*';
	Src[1] = 0;

}

int __stdcall OverFlowError(PDBPROCESS dbproc, char* lpString)
{
	if (lpString)
		OverFlowFill(lpString);
	GeneralError(dbproc, SQLECOFL);
	return -1;
}
unsigned int __stdcall CharToChar(char* Src, void* Dst, int length, int endlength)
{
	unsigned int Size; 

	if (length == -1)
	{
		Size = strlen(Src);
		dbmove(Src, Dst, Size);
	}
	else
	{
		Size = length;
		dbmove(Src, Dst, length);
	}
	if (endlength == -1)
		*((BYTE*)Dst + Size) = 0;
	return Size;
}
int __stdcall BitToChar(char C, char* Dst, int endlength)
{
	if (C)
		*Dst = '1';
	else
		*Dst = '0';
	if (endlength == -1)
		Dst[1] = 0;
	return 1;
}
void __stdcall StripBlanks(char* Src)
{
	const char* p1 = 0;
	char* p2 = 0;

	if (Src && strlen(Src))
	{
		for (p1 = Src; *p1 == ' '; ++p1)
			;
		if (p1 != Src)
			strcpy(Src, p1);
		if (strlen(Src))
		{
			for (p2 = &Src[strlen(Src) - 1]; p2 >= Src && *p2 == ' '; --p2)
				*p2 = 0;
		}
	}
}
void __cdecl AddDecimalZeroToEnd(const char* Src)
{
	const char* p = 0; 
	int L = 0;
	char* p1 = 0; 

	if (Src)
	{
		if (*Src)
		{
			if (*Src != '-')
				goto LABEL_7;
			if (Src[1])
			{
				++Src;
				while (1)
				{
				LABEL_7:
					if (!*Src)
					{
						p = ".0";
						L = strlen(".0") + 1;
						p1 = (char*)&Src[strlen(Src) + 1];
						goto LABEL_16;
					}

					if (*Src < '0')
						break;

					if (*Src > '9')
						break;
					++Src;
				}
				if (*Src == '.')
				{
					if (!Src[1])
					{
						p = "0";
						L = strlen("0") + 1;

						p1 = (char*)&Src[strlen(Src) + 1];
					LABEL_16:
						qmemcpy(p1 - 1, p, L);
					}
				}
			}
		}
	}

}
int __cdecl sub_7332FDA0(char* Src, int pos, int Value)
{
	_ltoa(Value, &Src[pos], 10);
	if (Value >= 10)
		return pos + 2;
	if ((DTM_FORMAT & 0x40) != 0)
		return pos + 1;
	Src[pos + 1] = Src[pos];
	Src[pos] = '0';
	return pos + 2;
}
int __cdecl sub_7332FE10(char* Src, int pos, int Value)
{
	if ((DTM_FORMAT & 0x10) != 0)
	{
		_ltoa(Value, &Src[pos], 10);
		if (Value >= 10)
		{
			return pos + 2;
		}
		else if ((DTM_FORMAT & 0x40) != 0)
		{
			return pos + 1;
		}
		else
		{
			Src[pos + 1] = Src[pos];
			Src[pos] = '0';
			return pos + 2;
		}
	}
	else
	{
		strcpy(&Src[pos], SMonths[Value - 1]);
		return strlen(SMonths[Value - 1]) + pos;
	}
}
int __cdecl sub_7332FEF0(char* Src, int pos, int Value)
{
	_ltoa(Value, &Src[pos], 10);
	if ((DTM_FORMAT & 8) == 8)
		return pos + 4;
	Src[pos] = Src[pos + 2];
	Src[pos + 1] = Src[pos + 3];
	return pos + 2;
}
int __cdecl time2string(unsigned int ms, int pad, char* Dst)
{
	char Buffer[8] = { 0 };
	int i = 0; 
	char* p = 0; 
	if (ms >= 1000)
		return 0;
	*Dst = TimeSep[0];
	p = Dst + 1;
	_ltoa(ms, Buffer, 10);
	for (i = 0; i < (int)(pad - strlen(Buffer)); ++i)
		*p++ = '0';
	strcpy(p, Buffer);
	return pad + 1;
}
int __stdcall crack_date(int year, int ydays, char* Src, int a4, int* mon, int* monday)
{
	int pos = 0; 
	int dtmf = 0; 

	if (ydays > 365 || year < 1753 || year > 9999)
		return -1;
	YearDayToYrMoDay(year, ydays + 1, mon, monday);
	dtmf = DTM_FORMAT & 3;
	switch (dtmf)
	{
	case 1:
		pos = sub_7332FDA0(Src, 0, *monday);
		Src[pos] = DateSep[0];
		pos = sub_7332FE10(Src, pos + 1, *mon);
		Src[pos] = DateSep[0];
		return sub_7332FEF0(Src, pos + 1, year);
	case 2:
		pos = sub_7332FE10(Src, 0, *mon);
		Src[pos] = DateSep[0];
		pos = sub_7332FDA0(Src, pos + 1, *monday);
		Src[pos] = DateSep[0];
		return sub_7332FEF0(Src, pos + 1, year);
	case 3:
		pos = sub_7332FEF0(Src, 0, year);
		Src[pos] = DateSep[0];
		pos = sub_7332FE10(Src, pos + 1, *mon);
		Src[pos] = DateSep[0];
		return sub_7332FDA0(Src, pos + 1, *monday);
	default:
		return -1;
	}
}

int __stdcall crack_time(int format, int hour, int minute, int second, int ms, char* Src, int length)
{
	int L = 0; 
	int l1 = 0; 
	int l2 = 0;
	int pos = 0;
	int Value = 0;

	Value = hour;
	if ((DTM_FORMAT & 4) == 0)
	{
		if (hour > 12)
			Value = hour - 12;
		if (!hour && TimeStrAm[0])
			Value = 12;
	}
	L = strlen(Src) + 1;
	l1 = L - 1;
	if (Value >= 10)
	{
		_ltoa(Value, (char*)&Src[l1], 10);
		l2 = l1 + 2;
	}
	else
	{
		Src[l1] = ' ';
		l2 = L + 1;
		_ltoa(Value, (char*)&Src[L], 10);
	}
	pos = time2string(minute, 2, &Src[l2]) + l2;
	if (format == 2 || format == 3)
		pos += time2string(second, 2, &Src[pos]);
	if (format == 3)
		pos += time2string(ms, 3, &Src[pos]);
	if ((DTM_FORMAT & 4) == 0)
	{
		if (hour >= 12 && TimeStrPm[0])
		{
			strcpy((char*)&Src[pos], TimeStrPm);
			pos += strlen(TimeStrPm);
		}
		else if (hour < 12 && TimeStrAm[0])
		{
			strcpy((char*)&Src[pos], TimeStrAm);
			pos += strlen(TimeStrAm);
		}
	}
	if (length == -1)
		Src[pos] = 0;
	return pos;
}

int __stdcall DateTimeToChar(int npar, DBDATETIME* datatime, LPSTR lpTimeString, int length)
{
	int yrDays = 0;
	int minute = 0;
	char Source[32] = { 0 };
	int hour, leap, mon, year, second, pos, ydays, monday, ms, TiM; 

	pos = 0;
	if (datatime->dtdays < -53690)
		return -1;
	yrDays = datatime->dtdays + 53690;
	for (year = yrDays / 365; ; --year)
	{
		leap = LeapCount(year);
		ydays = yrDays - (leap + 365 * year);
		if (ydays >= 0)
			break;
	}
	year += 1753;
	pos = crack_date(year, ydays, Source, -1, &mon, &monday);
	if (pos == -1)
		return -1;
	Source[pos++] = ' ';
	Source[pos] = 0;
	TiM = datatime->dttime & 0x1FFFFFF;
	ydays = TiM / 300;
	hour = TiM / 300 / 3600;
	minute = TiM / 300 % 3600 / 60;
	second = TiM / 300 % 60;
	ms = 10 * (TiM % 300) / 3;
	if (npar == 4)
	{
		wsprintfA(lpTimeString, "{ts '%04i-%02i-%02i %02i:%02i:%02i.%03i'}", year, mon, monday, hour, minute, second, ms);
		return strlen(lpTimeString);
	}
	else if (npar == 5)
	{
		wsprintfA(lpTimeString, "{ts '%04i-%02i-%02i %02i:%02i:%02i'}", year, mon, monday, hour, minute, second);
		return strlen(lpTimeString);
	}
	else
	{
		pos += crack_time(npar, hour, minute, second, ms, &Source[pos], length);
		if (length == -1)
		{
			strcpy(lpTimeString, Source);
		}
		else if (length >= pos)
		{
			strncpy(lpTimeString, Source, pos);
		}
		else
		{
			strncpy(lpTimeString, Source, length);
		}
		return pos;
	}
}

int __stdcall SmallDateTimeToChar(PDBPROCESS dbproc, SmallDateTime* dateTim, LPSTR lpTimeString, int length)
{
	DBDATETIME datatime;

	datatime.dtdays = dateTim->dtdays;
	datatime.dttime = 18000 * dateTim->dttime;
	if (dbproc && (dbproc->ret_status & 0x400) != 0)
		return DateTimeToChar(5, &datatime, lpTimeString, length);
	else
		return DateTimeToChar(1, &datatime, lpTimeString, length);
}
char* __cdecl DBCS_STRSTR(char* Str1, const char* Str2)
{
	unsigned int i,l1, l2, d; 

	l1 = strlen(Str1);
	l2 = strlen(Str2);
	if (l1 < l2)
		return 0;
	if (l1 == l2)
		return strcmp(Str1, Str2) == 0 ? Str1 : 0;
	d = l1 - l2;
	for (i = 0; i < d; ++i)
	{
		while (*Str1 != *Str2 && i < d)
		{
			if (IsDBCSLeadByte(*Str1))
			{
				++Str1;
				++i;
			}
			++Str1;
			++i;
		}
		if (i > d)
			return 0;
		if (!strncmp(Str1, Str2, l2))
			return Str1;
		if (IsDBCSLeadByte(*Str1))
		{
			++Str1;
			++i;
		}
		++Str1;
	}
	return 0;
}
unsigned int __stdcall format_money(PDBPROCESS dbproc, char* lpOutString, int Count)
{
	const char* p0, * p1;
	unsigned int len, l0, l1;
	char* Source,* Sourcea; 
	int result = 0; 
	int l5, i, l4, L1, i1; 
	char* lpMem,* pStr,* p2,* p3; 

	i1 = 0;
	lpMem = (char*)AllocateHeapMemory(4, 0, 0x100u, 1);
	if (!lpMem)
		return -1;
	pStr = DBCS_STRSTR(lpOutString, DeciSep);
	if (pStr)
	{
		if (pStr[1])
		{
			if (pStr[2])
				goto LABEL_10;
			p0 = "0";
			len = strlen("0") + 1;
			p3 = &lpOutString[strlen(lpOutString) + 1];
		}
		else
		{
			p0 = "00";
			len = strlen("00") + 1;
			p3 = &lpOutString[strlen(lpOutString) + 1];
		}
		qmemcpy(p3 - 1, p0, len);
	LABEL_10:
		if (pStr[3])
			pStr[3] = 0;
		goto LABEL_12;
	}
	strcat(lpOutString, ".00");
LABEL_12:
	Source = lpMem + 251;
	p1 = DBCS_STRSTR(lpOutString, DeciSep);
	p2 = (char*)(p1 - 1);
	strncpy(lpMem + 252, p1, 3u);
	lpMem[255] = 0;
	l0 = strlen(lpOutString) + 1;
	l4 = l0 - 4;
	l5 = l0 - 4;
	if (*lpOutString == '-')
	{
		l4 = l0 - 5;
		l5 = l0 - 5;
		result = -1;
	}
	else
	{
		result = 1;
	}
	if (l4)
	{
		L1 = l4 / 3 + l4;
		if (!(l5 % 3))
			--L1;
		i = 0;
		while (i1 < L1)
		{
			if (i1 && i == 3)
			{
				if (p2 != lpOutString
					|| *lpOutString >= '0' && *lpOutString <= '9')
				{
					if (dbproc && (dbproc->ret_status & 0x400) == 0)
						*Source-- = ThouSep[0];
					i = 0;
				}
			}
			else
			{
				*Source-- = *p2--;
				++i;
			}
			++i1;
		}
	}
	else
	{
		*Source = '0';
		Source = lpMem + 250;
		if (result == -1 && lpMem[253] == '0' && lpMem[254] == '0')
			result = 1;
	}
	if (result == -1)
		*Source-- = '-';
	Sourcea = Source + 1;
	l1 = strlen(Sourcea) + 1;
	strncpy(lpOutString, Sourcea, l1 - 1);
	if (Count == -1)
		lpOutString[l1 - 1] = 0;
	FreeMemory(0, lpMem);
	return l1 - 1;
}

int __stdcall MoneyToChar(PDBPROCESS dbproc, DBMONEY* money, char* lpOutString, size_t Count)
{
	int L = 0; 
	int l0 = 0; 
	char buf[4] = {0};
	char C = 0; 
	int j = 0; 
	int i = 0; 
	int mnylow, mnyhigh; 
	int l1 = 0; 
	int mny1[10] = { 0 };
	int mnyl = 0; 
	int mny2[10] = { 0 };
	char* Source = 0; 

	C = '+';
	mnylow = money->mnylow;
	mnyhigh = money->mnyhigh;
	if (mnyhigh < 0)
	{
		C = '-';
		mnyhigh = ~mnyhigh;
		if (mnylow)
		{
			mnylow = -mnylow;
		}
		else
			++mnyhigh;
	}
	if ((unsigned int)mnyhigh < 0x8FFFFFFF || mnylow < -51)
	{
		if (mnylow >= -51)
			++mnyhigh;
		mnylow += 50;
	}
	mnyl = (unsigned __int16)mnylow;
	for (i = 0; i < 5; ++i)
	{
		mny1[i] = mnyl % 10;
		mnyl /= 10;
	}
	mnyl = HIWORD(mnylow);
	for (i = 0; i < 5; ++i)
	{
		mny1[i + 5] = mnyl % 10;
		mnyl /= 10;
	}
	mnyl = (unsigned __int16)mnyhigh;
	for (i = 0; i < 5; ++i)
	{
		mny2[i] = mnyl % 10;
		mnyl /= 10;
	}
	mnyl = HIWORD(mnyhigh);
	for (i = 0; i < 5; ++i)
	{
		mny2[i + 5] = mnyl % 10;
		mnyl /= 10;
	}
	buf[1] = 0;
	Source = buf;
	l1 = 0;
	for (j = 0; j < 19; ++j)
	{
		if (j >= 5)
			l0 = 0;
		else
			l0 = mny1[j];
		l1 += l0;
		for (i = 0; ; ++i)
		{
			L = j >= 4 ? 4 : j;
			if (i > L)
				break;
			l1 += ArB[j - i] * mny2[i] + ArA[j - i] * mny2[i + 5] + ArC[j - i] * mny1[i + 5];
		}
		if (j == 4)
			*Source-- = DeciSep[0];
		*Source-- = l1 % 10 + '0';
		l1 /= 10;
	}
	if (l1)
		return -1;
	++Source;
	while (*Source == '0')
		++Source;
	if (C != '+')
		*--Source = '-';
	if (Count == -1)
		strcpy(lpOutString, Source);
	else
		strncpy(lpOutString, Source, Count);
	return format_money(dbproc, lpOutString, Count);
}
int __stdcall SmallMoneyToChar(ULONG* mny, char* lpOutString, size_t Count)
{
	DBMONEY mny1; 

	mny1.mnylow = *mny;
	mny1.mnyhigh = 0;
	if ((*mny & 0x80000000) != 0)
		--mny1.mnyhigh;
	return MoneyToChar(0, &mny1, lpOutString, Count);
}

size_t __cdecl ConvertToChar_Local(
	PDBPROCESS dbproc,
	int dtIn,
	char* Src,
	int Length,
	int dtOut,
	char* lpOutString,
	int OutLength,
	int* lpSize,
	int format)
{
	int result = 0; 
	char Buffer[52] = { 0 };
	double val = 0; 
	int Size = 0; 

	Size = -1;
	if (OutLength >= 1 || OutLength == -1)
	{
		switch (dtIn)
		{
		case SQLIMAGE:
		case SQLBINARY:
			Size = BinaryToHex((BYTE*)Src, lpOutString, Length, 0, OutLength);
			if (OutLength < 2 * Length && OutLength != -1)
				OverFlowError(dbproc, 0);
			if (Size == -1)
				result = strlen(lpOutString);
			else
				result = Size;
			break;
		case SQLTEXT:
		case SQLCHAR:
			if (Length == -1)
				Length = strlen(Src);
			if (Length > OutLength && OutLength != -1)
			{
				GeneralError(dbproc, SQLECOFL);
				if (lpSize)
					*lpSize = Length;
				Length = OutLength;
			}
			Size = CharToChar(Src, lpOutString, Length, OutLength);
			if (Size == -1)
				result = strlen(lpOutString);
			else
				result = Size;
			break;
		case SQLINT1:
			_itoa((BYTE)*Src, Buffer, 10);
			Size = strlen(Buffer);
			if (OutLength != -1 && OutLength < (int)Size)
			{
				result = OverFlowError(dbproc, lpOutString);
				break;
			}
			if (OutLength == -1)
			{
				strcpy(lpOutString, Buffer);
			}else 
				dbmove(Buffer, lpOutString, Size);
			if (Size == -1)
				result = strlen(lpOutString);
			else
				result = Size;
			break;
		case SQLBIT:
			Size = BitToChar(*Src, Buffer, -1);
			if (OutLength < (int)Size && OutLength != -1)
			{
				*lpOutString = 42;
				return OverFlowError(dbproc, 0);
			}
			if (OutLength == -1)
			{
				strcpy(lpOutString, Buffer);
			}
			else
				dbmove(Buffer, lpOutString, Size);
			if (Size == -1)
				result = strlen(lpOutString);
			else
				result = Size;
			break;
		case SQLINT2:
			_itoa(*(__int16*)Src, Buffer, 10);
			Size = strlen(Buffer);
			if (OutLength != -1 && OutLength < (int)Size)
			{
				result = OverFlowError(dbproc, lpOutString);
				break;
			}
			if (OutLength == -1)
			{
				strcpy(lpOutString, Buffer);
			}
			else
				dbmove(Buffer, lpOutString, Size);
			if (Size == -1)
				result = strlen(lpOutString);
			else
				result = Size;
			break;
		case SQLINT4:
			_ltoa(*(_DWORD*)Src, Buffer, 10);
			Size = strlen(Buffer);
			if (OutLength != -1 && OutLength < (int)Size)
			{
				result = OverFlowError(dbproc, lpOutString);
				break;
			}
			if (OutLength == -1)
				strcpy(lpOutString, Buffer);
			else
				dbmove(Buffer, lpOutString, Size);
			if (!IsValidNumber(Buffer, SQLFLT4))
			{
				GeneralError(dbproc, 10109);
				return -1;
			}
			if (Size == -1)
				result = strlen(lpOutString);
			else
				result = Size;
			break;
		case SQLDATETIM4:
			Size = SmallDateTimeToChar(dbproc, (SmallDateTime*)Src, Buffer, -1);
			if (Size == -1)
			{
				GeneralError(dbproc, 10039);
				result = Size;
				break;
			}
			if (OutLength < (int)Size && OutLength != -1)
				OverFlowError(dbproc, 0);
			if (OutLength == -1)
			{
				strcpy(lpOutString, Buffer);
				if (Size == -1)
					result = strlen(lpOutString);
				else
					result = Size;
				break;
			}
			if (Size > OutLength)
			{
				Size = OutLength;
			}
			dbmove(Buffer, lpOutString, Size);
			if (Size == -1)
				result = strlen(lpOutString);
			else
				result = Size;
			break;
		case SQLFLT4:
			val = FloatToDouble(*(float*)Src);
			sprintf(Buffer, "%23.15g", val);
			StripBlanks(Buffer);
			AddDecimalZeroToEnd(Buffer);
			Size = strlen(Buffer);
			if (OutLength != -1 && OutLength < Size)
			{
				result = OverFlowError(dbproc, lpOutString);
				break;
			}
			if (OutLength != -1)
			{
				strcpy(lpOutString, Buffer);
			}
			else
				dbmove(Buffer, lpOutString, Size);
			if (Size == -1)
				result = strlen(lpOutString);
			else
				result = Size;
			break;
		case SQLMONEY:
			Size = MoneyToChar(dbproc, (DBMONEY*)Src, Buffer, 0xFFFFFFFF);
			if (Size == -1)
			{
				GeneralError(dbproc, 10039);
				result = Size;
				break;
			}
			if (OutLength < (int)Size && OutLength != -1)
			{
				result = OverFlowError(dbproc, lpOutString);
				break;
			}
			if (OutLength != -1)
			{
				strcpy(lpOutString, Buffer);
			}
			else
				dbmove(Buffer, lpOutString, Size);
			if (Size == -1)
				result = strlen(lpOutString);
			else
				result = Size;
			break;
		case SQLDATETIME:
			if (dbproc && (dbproc->ret_status & 0x400) != 0)
				format = 4;
			Size = DateTimeToChar(format, (dbdatetime*)Src, Buffer, -1);
			if (Size == -1)
			{
				GeneralError(dbproc, 10039);
				result = Size;
				break;
			}
			if (OutLength < Size && OutLength != -1)
			{
				OverFlowError(dbproc, 0);
				if (lpSize)
					*lpSize = Size;
			}
			if (OutLength == -1)
			{
				strcpy(lpOutString, Buffer);
				if (Size == -1)
					result = strlen(lpOutString);
				else
					result = Size;
				break;
			}
			if ((int)Size > OutLength)
				Size = OutLength;
			dbmove(Buffer, lpOutString, Size);
			if (Size == -1)
				result = strlen(lpOutString);
			else
				result = Size;
			break;
		case SQLFLT8:
			val = *(double*)Src;
			sprintf(Buffer, "%23.15g", val);
			StripBlanks(Buffer);
			AddDecimalZeroToEnd(Buffer);
			Size = strlen(Buffer);
			if (OutLength != -1 && OutLength < (int)Size)
			{
				result = OverFlowError(dbproc, lpOutString);
				break;
			}
			if (OutLength == -1)
				strcpy(lpOutString, Buffer);
			else
				dbmove(Buffer, lpOutString, Size);
			if (IsValidNumber(Buffer, SQLFLT8))
			{
				if (Size == -1)
					result = strlen(lpOutString);
				else
					result = Size;
			}
			else {
				GeneralError(dbproc, 10109);
				return -1;
			}
			break;
		case SQLDECIMAL:
		case SQLNUMERIC:
			ConvertNumericDecimalToChar((DBNUMERIC*)Src, Buffer);
			Size = strlen(Buffer);
			if (OutLength != -1 && OutLength < (int)Size)
			{
				result = OverFlowError(dbproc, lpOutString);
				break;
			}
			if (OutLength != -1)
			{
				dbmove(Buffer, lpOutString, Size);
			}else
				strcpy(lpOutString, Buffer);
			if (Size == -1)
				result = strlen(lpOutString);
			else
				result = Size;
			break;
		case SQLMONEY4:
			Size = SmallMoneyToChar((ULONG*)Src, Buffer, 0xFFFFFFFF);
			if (Size == -1)
			{
				GeneralError(dbproc, 10039);
				result = Size;
			}
			else if (OutLength >= Size || OutLength == -1)
			{
				if (OutLength == -1)
					strcpy(lpOutString, Buffer);
				else
					dbmove(Buffer, lpOutString, Size);

				if (Size == -1)
					result = strlen(lpOutString);
				else
					result = Size;
			}
			else
			{
				result = OverFlowError(dbproc, lpOutString);
			}
			break;
		default:
			GeneralError(dbproc, 10016);
			return -1;
		}
	}
	else
	{
		dbdoerror(dbproc, 7, SQLEPARM, 0, 0);
		return -1;
	}
	return result;
}

int __cdecl ConvertToChar2(PDBPROCESS dbproc, int DataType, BYTE* Src, int Length, int dtOut, char* lpOutString, int Outlength, int* lpSize)
{
	return ConvertToChar_Local(dbproc, DataType, (char*)Src, Length, dtOut, lpOutString, Outlength, lpSize, 1);
}

int __cdecl ConvertToChar(PDBPROCESS dbproc, int DataType, BYTE* Src, int Length, int dtOut, char* lpOutString, int Outlength)
{
	return ConvertToChar_Local(dbproc, DataType, (char*)Src, Length, dtOut, lpOutString, Outlength, 0, 1);
}

int __stdcall TypeLength(int Type)
{
	int result = 0;

	switch (Type)
	{
	case SQLINT1:
		result = 1;
		break;
	case SQLBIT:
		result = 1;
		break;
	case SQLINT2:
		result = 2;
		break;
	case SQLINT4:
		result = 4;
		break;
	case SQLDATETIM4:
		result = 4;
		break;
	case SQLFLT4:
		result = 4;
		break;
	case SQLMONEY:
		result = 8;
		break;
	case SQLDATETIME:
		result = 8;
		break;
	case SQLFLT8:
		result = 8;
		break;
	case SQLDECIMAL:
	case SQLNUMERIC:
		result = 19;
		break;
	case SQLMONEY4:
		result = 4;
		break;
	default:
		result = 0;
		break;
	}
	return result;
}
int __stdcall CharToBinary(char* Src, BYTE* lpBuffer, int Length, int OutLength)
{
	int L, i, lmax, l; 
	BYTE C = 0; 
	char C1 = 0; 
	char C2 = 0; 
	char* p = 0; 

	p = Src;
	if (Length == -1)
		l = strlen(Src);
	else
		l = Length;
	if ((Length > 2 || Length == -1) && !_strnicmp(Src, "0x", 2u))
	{
		l -= 2;
		p = Src + 2;
	}
	if (OutLength == -1)
		lmax = 2 * l;
	else
		lmax = OutLength;
	if (OutLength != -1 && 2 * OutLength < l)
		l = 2 * OutLength;
	L = l / 2;
	do
	{
		if (l <= 0)
			break;
		*lpBuffer = 0;
		for (i = 0; i < 2; ++i)
		{
			C = *p++;
			if (C == ' ' || !C)
				C = '0';
			if ((C < '0' || C >'9') && ((C & 0xDFu) < 'A' || (C & 0xDFu) > 'F'))
				return NO_MORE_ROWS;
			if (C > '9')
				C = (C & 0xDF) - 7;
			C1 = C - '0';
			if (i)
				C2 = C1 & 0xF;
			else
				C2 = 16 * C1;
			*lpBuffer += C2;
			if (!i && l == 1)
				return NO_MORE_ROWS;
		}
		++lpBuffer;
		l -= 2;
		--lmax;
	} while (lmax);
	return L;
}

int __cdecl ConvertToBinary(PDBPROCESS dbproc, int DataType, BYTE* Src, int Length, int dtOut, void* lpOutBuffer, int Outlength)
{
	int result, result1, Size, Sizea;

	switch (DataType)
	{
	case SQLIMAGE:
	case SQLBINARY:
		if (Outlength == -1)
		{
			if (Length < 1)
				return -1;
			Sizea = Length;
		}
		else
		{
			Sizea = Outlength;
		}
		if (Length > 0 && Sizea > Length)
			Sizea = Length;
		if (Sizea < Length)
			GeneralError(dbproc, SQLECOFL);
		if (Outlength > 0)
			dbzero(lpOutBuffer, Outlength);
		dbmove(Src, lpOutBuffer, Sizea);
		result = Sizea;
		break;
	case SQLTEXT:
	case SQLCHAR:
		if (Outlength != -1 && Outlength < (Length + 1) / 2)
			GeneralError(dbproc, SQLECOFL);
		result1 = CharToBinary((char*)Src, (BYTE*)lpOutBuffer, Length, Outlength);
		if (result1 == NO_MORE_ROWS)
		{
			GeneralError(dbproc, 10039);
			result = -1;
		}
		else
		{
			result = result1;
		}
		break;
	case SQLINT1:
	case SQLBIT:
	case SQLINT2:
	case SQLINT4:
	case SQLDATETIM4:
	case SQLFLT4:
	case SQLMONEY:
	case SQLDATETIME:
	case SQLFLT8:
	case SQLDECIMAL:
	case SQLNUMERIC:
	case SQLMONEY4:
		if (Outlength == -1)
		{
			Size = TypeLength(DataType);
			dbmove(Src, lpOutBuffer, Size);
		}
		else
		{
			if (Outlength > Length && Length >= 0)
				Size = Length;
			else
				Size = Outlength;
			if (Size > TypeLength(DataType))
				Size = TypeLength(DataType);
			if (Size < TypeLength(DataType))
				GeneralError(dbproc, SQLECOFL);
			dbmove(Src, lpOutBuffer, Size);
		}
		result = Size;
		break;
	default:
		GeneralError(dbproc, 10016);
		result = -1;
		break;
	}
	return result;
}
char* __stdcall StrICStr(char* String1, char* String2)
{
	const char* p1 = 0; 
	char* result = 0; 
	unsigned int L;

	p1 = String1;
	if (!*String1 || !*String2)
		return 0;
	result = DBCS_STRSTR(String1, String2);
	if (result)
		return result;
	L = strlen(String2) + 1;
	if (!*String1)
		return 0;
	while (_strnicmp(p1, String2, L - 1))
	{
		if (!*++p1)
			return 0;
	}
	return (char*)p1;
}
int __stdcall FindMonth(char* Src, char* space)
{
	char* p1 = 0;
	int i = 0;
	char C = 0; 
	int typ = 0; 
	int m1 = 0; 
	int i1 = 0; 
	int result = 0; 
	char String1[8] = { 0 };
	char m = 0; 

	p1 = Src;
	i = 0;
	C = *Src;
	m = 1;
	if (C)
	{
		do
		{
			if (__mb_cur_max <= 1)
				typ = _pctype[*p1] & 0x103;
			else
				typ = _isctype(*p1, 259);
			if (typ)
				break;
			if (*p1 == ' ' && p1[1] != ' ')
				++m;
		} while (*++p1);
	}
	if (*p1)
	{
		while (1)
		{
			m1 = __mb_cur_max <= 1 ? _pctype[*p1] & 259 : _isctype(*p1, 259);
			if (!m1 || i >= 5)
				break;
			String1[i++] = *p1++;
		}
	}
	String1[i] = 0;
	if (i)
	{
		i1 = 0;
		while ((char*)StrICStr(String1, SMonths[i1]) != String1)
		{
			++i1;
			if (i1 >=  12)
			{
				*space = 0;
				return 0;
			}
		}
		*space = m;
		return i1 + 1;
	}
	else
	{
		result = 0;
		*space = 0;
	}
	return result;
}
BOOL __stdcall FindNextDigit(char* Src)
{
	char C = 0; 
	char* p1 = 0; 

	p1 = Src;
	if (Src)
	{
		do
		{
			C = *p1++;
			if (C >= '0' && C <= '9')
			{
				return TRUE;
				break;
			}
		} while (C);
	}
	return 0;
}

int __stdcall GetNextDigitBlock(char* Src, char* lpStr)
{
	char* p1, *p2; 
	int result = 0;
	char C = 0; 

	p2 = lpStr;
	p1 = Src;
	result = 0;
	*lpStr = 0;
	if (p1)
	{
		do
		{
			C = *p1++;
			if (C < '0')
				break;
			if (C > '9')
				break;
			*p2++ = C;
			++result;
		} while (C);
	}
	*p2 = 0;
	return result;
}
char __stdcall FindDateToken(char* Src)
{
	char* p1,* p2;
	char C = 0; 
	char C3 = 0; 
	char C2 = 0; 
	char C1[2] = { 0 };
	p1 = Src;

	C = *p1;
	if (*p1)
	{
		while (2)
		{
			if (C != DateSep[0])
			{
				switch (C)
				{
				case ' ':
				case ',':
					C3 = *p1;
					C1[0] = ' ';
					if (C3 == ' ')
					{
						do
							C2 = *++p1;
						while (C2 == ' ');
					}
					--p1;
					goto LABEL_13;
				case '-':
					C1[0] = '-';
					goto LABEL_13;
				case '.':
					C1[0] = '.';
					goto LABEL_13;
				case '/':
					C1[0] = '/';
					goto LABEL_13;
				default:
					C = *++p1;
					if (C)
						continue;
					return 0;
				}
			}
			break;
		}
		C1[0] = DateSep[0];
	LABEL_13:
		p2 = p1 + 1;
		if (DBCS_STRSTR(p1 + 1, C1) || C1[0] != ' ' || DBCS_STRSTR(p2, (char*)","))
			return C1[0];
	}
	return 0;
}
int __stdcall CountDigits(char* Src)
{
	char* p1 = 0;
	int result = 0;
	BYTE i = 0; 

	p1 = Src;
	result = 0;
	for (i = *Src; i; ++result)
	{
		if (i < '0')
			break;
		if (i > '9')
			break;
		i = *++p1;
	}
	return result;
}

int __stdcall FixedDate(char* Source, int* mon, int* day, int* year)
{
	int count = 0; 
	int l = 0;
	int y = 0; 
	char* p1 = 0;
	char Destination[3] = { 0 };

	count = CountDigits(Source);
	if (count == 6)
	{
		l = 2;
		goto LABEL_5;
	}
	if (count == 8)
	{
		l = 4;
	LABEL_5:
		strncpy(Destination, Source, l);
		Destination[l] = 0;
		y = atol(Destination);
		if (l == 2)
		{
			if (y >= 50)
			{
				*year = y + 1900;
				goto LABEL_9;
			}else
				y += 2000;
		}
		*year = y;
	LABEL_9:
		p1 = &Source[l];
		strncpy(Destination, p1, 2u);
		Destination[2] = 0;
		*mon = atol(Destination);
		strncpy(Destination, p1 + 2, 2u);
		Destination[2] = 0;
		*day = atol(Destination);
		return 1;
	}
	return 0;
}

int __stdcall DateFormatCrack(char* Source, int* mon, int* day, int* year)
{
	char* Src = 0; 
	int monfinded = 0; 
	char c1 = 0; 
	int y1, y2, y3, y4;
	int d1, d2; 
	int* dm = 0; 
	char space = 0; 
	char String[12] = { 0 };
	int ymd[3] = { 0 };

	Src = Source;
	*year = 1753;
	*mon = 1;
	*day = 1;

	space = 1;

	if (*Src == 0)
		return 1;
	monfinded = FindMonth(Src, &space);

	if (monfinded)
		*mon = monfinded;
	Source = Src;

	int L = 3;
	int i = 0;
	do
	{
		if (FindNextDigit(Source))
		{
			GetNextDigitBlock(Source, String);
			ymd[i] = atol(String);
		}
		else
		{
			ymd[i] = 0;
		}
		++i;
		--L;
	} while (L);

	c1 = 1;
	if (!DBCS_STRSTR(Src, (char*)","))
		c1 = 0;
	if (!FindDateToken(Src))
	{
		if (monfinded)
			return FixedDate(Src, mon, day, year);
		y1 = ymd[0];
		if (ymd[0])
		{
			if (ymd[0] < 50)
			{
				*year = ymd[0] + 2000;
				return 1;
			}
			if (ymd[0] >= 100)
				goto LABEL_19;
			goto LABEL_18;
		}
		return 0;
	}
	if ((DTM_FORMAT & 3) == 1)
	{
		*day = ymd[0];
		if (monfinded)
		{
			y4 = ymd[1];
			goto LABEL_49;
		}
		d2 = ymd[1];
		dm = mon;
		goto LABEL_48;
	}
	if ((DTM_FORMAT & 3) == 2)
	{
		if (year)
		{
			y3 = ymd[0];
			if (c1)
			{
				if (space != 3)
				{
				LABEL_40:
					if (ymd[0] < 1753)
					{
						*day = ymd[0];
						*year = ymd[1];
						goto LABEL_50;
					}
					*year = ymd[0];
					goto LABEL_42;
				}
			}
			else if (space != 3)
			{
				if (ymd[0] >= 1753)
				{
					*year = ymd[0];
					*day = ymd[1];
					goto LABEL_50;
				}
				y4 = ymd[1];
				*day = ymd[0];
			LABEL_49:
				*year = y4;
				goto LABEL_50;
			}
			if (ymd[0] > 31)
			{
				*day = ymd[1];
				*year = y3;
				goto LABEL_50;
			}
			goto LABEL_40;
		}
		d2 = ymd[1];
		*mon = ymd[0];
		dm = day;
	LABEL_48:
		y4 = ymd[2];
		*dm = d2;
		goto LABEL_49;
	}
	if ((DTM_FORMAT & 3) != 3)
		return 0;
	y2 = ymd[0];
	if (ymd[0] <= 100)
	{
		if (ymd[0] >= 50)
			y2 = ymd[0] + 1900;
		else
			y2 = ymd[0] + 2000;
	}
	*year = y2;
	if (monfinded)
	{
	LABEL_42:
		*day = ymd[1];
		goto LABEL_50;
	}
	d1 = ymd[2];
	*mon = ymd[1];
	*day = d1;
LABEL_50:
	y1 = *year;
	if (*year >= 100)
		return 1;
	if (y1 >= 50)
	{
	LABEL_18:
		y1 += 1900;
	LABEL_19:
		*year = y1;
		return 1;
	}
	*year = y1 + 2000;
	return 1;
}

BOOL __stdcall ExtractDateTimePiece(char* Src, char* lpOutString, int fmt, int length)
{
	unsigned int L; 
	int B = 0; 
	char* pr,* pl,* p1, * p2, * p3, * p4, * p5, * p6, * po1, * pi;
	char* pi1, * pi2;
	char* result = 0; 
	char C = 0; 
	char Source[256] = { 0 };

	L = length;
	B = 1;
	if (length == -1)
		L = strlen(Src);


	dbmove(Src, Source, L);
	pr = &Source[L + 1];
	pl = &Source[L - 1];
	*(pr - 1) = 0;
	if (pr - 2 > Source)
	{
		do
		{
			if (*pl != ' ')
				break;
			--pl;
		} while (pl > Source);
	}
	if (pl - 2 > Source)
	{
		p1 = pl - 1;
		if (StrICStr(pl - 1, TimeStrAm) || StrICStr(pl - 1, TimeStrPm))
		{
			for (pi1 = pl - 2; pi1 > Source; --pi1)
			{
				if (*pi1 != ' ')
					break;
			}
			if (pi1[1] == ' ')
				strcpy(pi1 + 1, p1);
		}
	}
	result = DBCS_STRSTR(Source, TimeSep);
	p2 = result;
	if (TimeStrAm[0] && !result)
	{
		result = StrICStr(Source, TimeStrAm);
		p2 = result;
	}
	if (TimeStrPm[0])
	{
		if (result)
			goto LABEL_22;
		result = StrICStr(Source, TimeStrPm);
		p2 = result;
	}
	if (!result)
	{
		B = 0;
		goto LABEL_28;
	}
LABEL_22:
	if (*result != ' ')
	{
		do
		{
			if (result == Source)
				break;
			C = *--result;
		} while (C != ' ');
	}
	for (C = *p2; C != ' '; C = *++p2)
	{
		if (!C)
			break;
	}
LABEL_28:
	if (fmt != 1)
	{
		if (fmt != 2 || !B)
			return (BOOL)result;
		for (pi2 = lpOutString; result != p2; ++result)
			*pi2++ = *result;
		*pi2 = 0;
		return 1;
	}
	if (B != 1)
	{
		int l1 = L;
		char *ps1 = Source;
		if (Source[0] == ' ')
		{
			do
			{
				C = *++ps1;
				--l1;
			} while (C == ' ');
		}
		strncpy(lpOutString, ps1, l1);
		if (length == -1)
		{
			lpOutString[l1] = 0;
			return 1;
		}
		return 1;
	}
	if (result == Source)
	{
		C = *p2;
		p4 = 0;
		for (p3 = p2; C; C = *++p3)
		{
			if (C != ' ')
				break;
		}
		if (!*p3)
			return -1;
	}
	else
	{
		p3 = Source;
		p4 = result;
	}
	C = *p3;
	for (po1 = lpOutString; C; ++p3)
	{
		if (p3 == p4)
			break;
		*po1 = C;
		C = p3[1];
		++po1;
	}
	*po1 = ' ';
	C = *p2;
	p5 = po1 + 1;
	for (pi = p2; C; C = *++pi)
	{
		if (C != ' ')
			break;
	}
	for (C = *pi; C; ++pi)
	{
		*p5 = C;
		C = pi[1];
		++p5;
	}
	*p5 = 0;
	p6 = &lpOutString[strlen(lpOutString) - 1];
	if (*p6 == ' ')
	{
		do
			C = *--p6;
		while (C == ' ');
	}
	p6[1] = 0;
	return 1;
}

int __stdcall CharToDate(char* Src, DBDATETIME* datetime, int length)
{
	int result, L, B1; 
	BOOL Bl = 0; 
	bool flag = 0; 
	int lC, i, d; 
	int day, year, mon; 
	char Destination[256] = { 0 };

	L = length;
	if (length == -1)
		L = strlen(Src);
	if (!ExtractDateTimePiece(Src, Destination, 1, L))
		return 0;
	Destination[L] = 0;
	if (!DateFormatCrack(Destination, &mon, &day, &year))
		return 0;
	if (year < 1753)
		return 0;
	if (day > 31)
		return 0;
	if (day < 1)
		return 0;
	result = mon;
	if (mon > 12 || mon < 1 || year > 9999)
		return 0;
	if (mon == 1 && day == 1 && year == 1900)
	{
		datetime->dtdays = 0;
		return result;
	}
	B1 = (1 << (16 - mon)) & 0xAB50;
	Bl = isleapyear(year);
	if (mon == 2)
	{
		if (!Bl)
		{
			if (day > 28)
				return 0;
			goto LABEL_25;
		}
		flag = day <= 29;
	}
	else
	{
		if (!B1 && day > 30)
			return 0;
		if (!B1)
			goto LABEL_25;
		flag = day <= 31;
	}
	if (!flag)
		return 0;
LABEL_25:
	year -= 1753;
	lC = LeapCount(year);
	i = 0;
	for (d = 365 * year + lC; i < mon - 1; ++i)
	{
		if (i == 1)
		{
			if (Bl)
				d += 29;
			else
				d += 28;
		}
		else if (((1 << (15 - i)) & 0xAB50) != 0)
		{
			d += 31;
		}
		else
		{
			d += 30;
		}
	}
	datetime->dtdays = day + d - 53691;
	return 1;
}

int __stdcall CharToTime(char* Src, DBDATETIME* datetime, int length)
{
	int flag, flag1;
	int s1, L; 
	int l1 = 0; 
	ULONG sec1 = 0; 
	int val1 = 0; 
	char String[8] = { 0 };
	char Str1[36] = { 0 };
	char* p1 = 0;
	flag = 0;
	flag1 = 0;
	s1 = 0;
	if (!ExtractDateTimePiece(Src, Str1, 2, length))
		return -1;
	if ((DTM_FORMAT & 4) != 0)
		goto LABEL_10;
	if (TimeStrAm[0] && StrICStr(Str1, TimeStrAm))
	{
		flag = 1;
		L = 1;
		goto LABEL_11;
	}
	if (TimeStrPm[0] && StrICStr(Str1, TimeStrPm))
	{
		flag = 1;
		L = 0;
	}
	else
	{
	LABEL_10:
		L = length;
	}
LABEL_11:
	if (DBCS_STRSTR(Str1, TimeSep))
	{
		flag1 = 1;
	}
	else if (!flag)
	{
		return -1;
	}
	p1 = Str1;
	if (flag1 != 1)
	{
		if (!L)
			s1 = 12960000; // 60^4
		GetNextDigitBlock(p1, String);
		val1 = atol(String);
		if (val1 == 12 && !L)
			val1 = 0;
		sec1 = 1080000 * val1 + s1;
		goto LABEL_49;
	}
	if (!FindNextDigit(p1))
		return -1;
	GetNextDigitBlock(p1, String);
	l1 = atol(String);
	if (!flag)
	{
		if (l1 < 12)
			goto LABEL_31;
	LABEL_23:
		L = 0;
		l1 -= 12;
		goto LABEL_27;
	}
	if (L)
	{
		if (l1 == 12)
			l1 = 0;
		goto LABEL_27;
	}
	if (l1 == 12)
		goto LABEL_23;
LABEL_27:
	if (l1 > 12)
		return -1;
	if (!L)
		s1 = 12960000;
LABEL_31:
	sec1 = 1080000 * l1 + s1;
	if (FindNextDigit(p1))
	{
		GetNextDigitBlock(p1, String);
		val1 = atol(String);
		if (val1 > 60)
			return -1;
		sec1 += 18000 * val1;
	}
	if (FindNextDigit(p1))
	{
		GetNextDigitBlock(p1, String);
		val1 = atol(String);
		if (val1 > 60)
			return -1;
		sec1 += 300 * val1;
	}
	if (FindNextDigit(p1))
	{
		GetNextDigitBlock(p1, String);
		val1 = atol(String);
		if (val1 > 999)
			return -1;
		sec1 += (30 * val1 + 5) / 100;
	}
LABEL_49:
	datetime->dttime = sec1;
	return 1;
}

int __cdecl ConvertToDateTime(PDBPROCESS dbproc, int DataType, SmallDateTime* Src, int Length, int dtOut, DBDATETIME* datetime)
{
	int result = 0; 

	switch (DataType)
	{
	case SQLTEXT:
	case SQLCHAR:
		datetime->dtdays = 0;
		datetime->dttime = 0;
		if (CharToDate((char*)Src, datetime, Length) && CharToTime((char*)Src, datetime, Length))
			result = 8;
		else
			GeneralError(dbproc, 10039);
		result = -1;
		break;
	case SQLDATETIM4:
		datetime->dtdays = Src->dtdays;
		datetime->dttime = 18000 * Src->dttime;

		result = 8;
		break;
	case 61:
		*datetime = *(DBDATETIME*)Src;
		result = 8;
		break;
	default:
		GeneralError(dbproc, 10016);
		result = -1;
		break;
	}
	return result;
}
int __cdecl ConvertToBit(PDBPROCESS dbproc, int DataType, BYTE* Src, int Length, int dtOut, char* lpBuffer)
{
	DWORD ulVal = 0; 
	double Value = 0;

	switch (DataType)
	{
	case SQLIMAGE:
	case SQLBINARY:
		if (*Src)
			*lpBuffer = 1;
		else
			*lpBuffer = 0;
		return 1;
	case SQLTEXT:
	case SQLCHAR:
		if (*Src == '1')
		{
			*lpBuffer = 1;
		}
		else
		{
			if (*Src != '0')
			{
				GeneralError(dbproc, 10039);
				return -1;
			}
			*lpBuffer = 0;
		}
		if (Length == -1)
			Length = strlen((const char*)Src);
		if (Length > 1)
			GeneralError(dbproc, SQLECOFL);
		return 1;
	case SQLINT1:
		if (*Src)
			*lpBuffer = 1;
		else
			*lpBuffer = 0;
		return 1;
	case SQLBIT:
		*lpBuffer = *Src;
		return 1;
	case SQLINT2:
		if (*(WORD*)Src)
			*lpBuffer = 1;
		else
			*lpBuffer = 0;
		return 1;
	case SQLINT4:
		if (*(_DWORD*)Src)
			*lpBuffer = 1;
		else
			*lpBuffer = 0;
		return 1;
	case SQLFLT4:
		*lpBuffer = *(float*)Src != 0.0;
		return 1;
	case SQLMONEY:
		MoneyToDouble(Src, &Value);
		*lpBuffer = Value != 0.0;
		return 1;
	case SQLFLT8:
		*lpBuffer = *(double*)Src != 0.0;
		return 1;
	case SQLDECIMAL:
	case SQLNUMERIC:
		if (!ConvertNumericDecimalToULong((DBNUMERIC*)Src, &ulVal))
			return 0;
		if ((BYTE)ulVal == ulVal && (!(BYTE)ulVal || (BYTE)ulVal == 1))
		{
			*lpBuffer = (char)ulVal;
			return 1;
		}
		else
		{
			GeneralError(dbproc, SQLECOFL);
			return -1;
		}
	case SQLMONEY4:
		SmallMoneyToDouble((int*)Src, &Value);
		*lpBuffer = Value != 0.0;
		return 1;
	default:
		GeneralError(dbproc, 10016);
		return -1;
	}
}
BOOL __stdcall negatemny(DBMONEY* lpMoney)
{
	BOOL B = 0; 
	int val = 0;
	B = lpMoney->mnyhigh < 0;
	lpMoney->mnyhigh = ~lpMoney->mnyhigh;
	if (lpMoney->mnylow)
	{
		val = lpMoney->mnylow;
		lpMoney->mnylow = -val;
	}
	else
		++lpMoney->mnyhigh;
	return !B || lpMoney->mnyhigh || lpMoney->mnylow;
}
BOOL __stdcall convertmny(DBMONEY* lpMoney, int radix, BYTE C)
{
	int h = 0; 
	int i = 0; 

	h = C + radix * *((unsigned __int16*)&lpMoney->mnyhigh + moneys[0]);
	*((WORD*)&lpMoney->mnyhigh + moneys[0]) = h;
	for (i = 1; i < 4; ++i)
	{
		h = HIWORD(h) + radix * *((unsigned __int16*)&lpMoney->mnyhigh + moneys[i]);
		*((WORD*)&lpMoney->mnyhigh + moneys[i]) = h;
	}
	return !HIWORD(h) && (h & 0x8000u) == 0;
}

int __stdcall CharToMoney(char* Src, DBMONEY* lpMoney, unsigned int Length)
{
	char C,C1 = 0;
	int result = 0; 
	int B1, B2, B3, B4, B5;
	int Count, i, SiZ; 
	char* p1 = 0; 
	int Siz1 = 0; 

	result = 0;
	B2 = 0;
	B4 = 0;
	B3 = 0;
	B1 = 0;
	SiZ = 0;
	Count = 0;
	Siz1 = 0;
	B5 = 0;
	p1 = Src;
	lpMoney->mnyhigh = 0;
	lpMoney->mnylow = 0;
	if (Length == -1)
		Length = strlen(Src);
	while (Count != Length && *p1)
	{
		C1 = *p1++;
		++Count;
		if (C1 == DeciSep[0])
		{
			if (B4)
				return NO_MORE_ROWS;
			B4 = 1;
			if (B1 && Siz1 != 3)
				return NO_MORE_ROWS;
		}
		else if (C1 == ThouSep[0])
		{
			if (!B3)
				return NO_MORE_ROWS;
			if (B1)
			{
				if (Siz1 != 3)
					return NO_MORE_ROWS;
			}
			else
			{
				B1 = 1;
				if (Siz1 > 3)
					return NO_MORE_ROWS;
			}
			Siz1 = 0;
		}
		else if (C1 == MnySign[0])
		{
			if (strlen(MnySign) > 1)
			{
				for (i = 1; i < (int)strlen(MnySign); ++i)
				{
					C = *p1++;
					if (C != MnySign[i])
						return NO_MORE_ROWS;
				}
			}
			if (B2 || B3 != ((DTM_FORMAT & 0x20) != 0))
				return NO_MORE_ROWS;
			B2 = 1;
		}
		else
		{
			switch (C1)
			{
			case ' ':
				if (B3)
					B5 = 1;
				break;
			case '+':
				if (result || B3 || B5)
					return NO_MORE_ROWS;
				result = 1;
				break;
			case '-':
				if (result || B3 || B5)
					return NO_MORE_ROWS;
				result = -1;
				break;
			default:
				if (C1 < '0' || C1 > '9')
					return NO_MORE_ROWS;
				if (B5)
					return NO_MORE_ROWS;
				B3 = 1;
				if (B4)
					++SiZ;
				else
					++Siz1;
				if (B1 && Siz1 > 3)
					return NO_MORE_ROWS;
				if (SiZ <= 4 && !convertmny(lpMoney, 10, C1 - '0'))
					return -1;
				break;
			}
		}
	}
	if (B1 && Siz1 != 3)
		return NO_MORE_ROWS;
	if (SiZ < 4 && !convertmny(lpMoney, mnyradix[SiZ], 0))
		return -1;
	if (result >= 0 || negatemny(lpMoney))
		return 0;
	return -1;
}


char* __stdcall GetConversionMemory(PDBPROCESS dbproc, BYTE* Src, int DataType)
{
	char* result = 0;
	int L = 0; 
	char* Buffer = 0;

	switch (DataType)
	{
	case SQLINT1:
		L = 3;
		break;
	case SQLBIT:
		L = 3;
		break;
	case SQLINT2:
		L = 6;
		break;
	case SQLINT4:
		L = 11;
		break;
	case SQLFLT4:
	case SQLFLT8:
		L = 20;
		break;
	default:
		return 0;

	}

	Buffer = (char*)AllocateHeapMemory(4, dbproc, L + 20, 1);
	if (Buffer)
	{
		switch (DataType)
		{
		case SQLINT1:
		case SQLBIT:
			_itoa(*Src, Buffer, 10);
			break;
		case SQLINT2:
			_itoa(*(__int16*)Src, Buffer, 10);
			break;
		case SQLINT4:
			_ltoa(*(_DWORD*)Src, Buffer, 10);
			break;
		case SQLFLT4:
			_gcvt(*(float*)Src, 20, Buffer);
			break;
		case SQLFLT8:
			_gcvt(*(double*)Src, 20, Buffer);
			break;
		default:
			result = 0;
			break;
		}
		result = Buffer;
	}
	else
	{
		FreeOnError(0, dbproc);
		result = 0;
	}
	return result;
}
BOOL __cdecl ConvertNumericDecimalToMoney(DBNUMERIC*Src, DBMONEY* monry)
{
	char Buffer[80] = { 0 };

	ConvertNumericDecimalToChar(Src, Buffer);
	return ConvertToMoney(0, SQLCHAR, (BYTE*)Buffer, strlen(Buffer), 0, monry, 0) >= 0;
}
int __cdecl ConvertToMoney(PDBPROCESS dbproc, int DataType, BYTE* Src, int Length, int dtOut, DBMONEY* lpBuffer, int OutLength)
{
	int result = 0; 
	int SiZ = 0; 
	int Size = 0; 
	double dblVal = 0; 
	double dblVal1 = 0;
	void* lpMem = 0; 

	switch (DataType)
	{
	case SQLIMAGE:
	case SQLBINARY:
		if (OutLength == -1)
		{
			if (Length < 1)
			{
				GeneralError(dbproc, SQLECOFL);
				result = -1;
				break;
			}
			Size = Length;
		}
		else
		{
			Size = OutLength;
		}
		if (Length > 0 && Size > Length)
			Size = Length;
		dbzero(lpBuffer, 8u);
		if (Length >= 8)
			SiZ = 8;
		else
			SiZ = Length;
		if (Size < SiZ)
			GeneralError(dbproc, SQLECOFL);
		dbmove(Src, lpBuffer, Size);
		return Size;
	case SQLTEXT:
	case SQLCHAR:
		result = CharToMoney((char*)Src, lpBuffer, Length);
		goto LABEL_48;
	case SQLINT1:
	case SQLINT2:
	case SQLINT4:
		lpMem = (void*)GetConversionMemory(dbproc, Src, DataType);
		if (!lpMem)
			return -1;
		result = CharToMoney((char*)lpMem, lpBuffer, -1);
		FreeMemory(dbproc, lpMem);
	LABEL_48:
		switch (result)
		{
		case NO_MORE_ROWS:
			GeneralError(dbproc, 10039);
			return -1;
		case -1:
			GeneralError(dbproc, SQLECOFL);
			result = -1;
		case 0:
			return 8;
		}
		return result;
	case SQLFLT4:
		lpBuffer->mnylow = 0;
		lpBuffer->mnyhigh = 0;
		if (!Src || !Length)
			return 8;
		dblVal = *(float*)Src;
		if (dblVal < 0.0)
			dblVal = -dblVal;
		if (dblVal > 9.223372036854776e14)
		{
			GeneralError(dbproc, SQLECOFL);
			result = -1;
			break;
		}
		dblVal1 = dblVal + 0.00005;
		lpBuffer->mnyhigh = (int)(dblVal1 / 429496.7296);
		lpBuffer->mnylow = (int)((dblVal1 - (double)lpBuffer->mnyhigh * 429496.7296) * 10000.0);
		if (*(float*)Src < 0.0 && !negatemny(lpBuffer))
		{
			GeneralError(dbproc, SQLECOFL);
			result = -1;
		}else
			result = 8;
		break;
	case SQLMONEY:
		*lpBuffer = *(DBMONEY*)Src;
		return 8;
	case SQLFLT8:
		lpBuffer->mnylow = 0;
		lpBuffer->mnyhigh = 0;
		if (Src && Length)
		{
			dblVal = *(double*)Src;
			if (dblVal < 0.0)
				dblVal = -dblVal;
			if (dblVal <= 9.223372036854776e14
				&& ((dblVal1 = dblVal + 0.00005,
					lpBuffer->mnyhigh = (int)(dblVal1 / 429496.7296),
					lpBuffer->mnylow = (int)((dblVal1 - (double)lpBuffer->mnyhigh * 429496.7296) * 10000.0),
					*(double*)Src >= 0.0)
					|| negatemny(lpBuffer)))
			{
				result = 8;
			}
			else
			{
				GeneralError(dbproc, SQLECOFL);
				result = -1;
			}
		}
		else
		{
			result = 8;
		}
		break;
	case SQLDECIMAL:
	case SQLNUMERIC:
		if (ConvertNumericDecimalToMoney((DBNUMERIC*)Src, lpBuffer))
			return 8;
		else
			return -1;
	case SQLMONEY4:
		lpBuffer->mnylow = *(_DWORD*)Src;
		lpBuffer->mnyhigh = 0;
		if (*(int*)Src < 0)
			--lpBuffer->mnyhigh;
		return 8;
	default:
		GeneralError(dbproc, 10016);
		return -1;
	}
	return result;
}
void __stdcall MoneyToReal(BYTE* Src, float* lpValue)
{
	double Value = 0; 

	MoneyToDouble(Src, &Value);
	*lpValue = (float)Value;

}
void __stdcall SmallMoneyToReal(float* money, float* lpValue)
{

	*lpValue = *money;
	*lpValue = *lpValue / 10000.f;

}

int __cdecl ConvertToReal(PDBPROCESS dbproc, int DataType, BYTE* Src, int Length, int dtOut, float* lpValue)
{
	int SiZ = 0; 
	double dblVal = 0; 
	char Destination[104] = { 0 };
	int Count = 0;

	switch (DataType)
	{
	case SQLIMAGE:
	case SQLBINARY:
		if (Length >= 4)
		{
			dbmove(Src, lpValue, 4u);
			return 4;
		}
		dbzero(lpValue, 4u);
		dbmove(Src, lpValue, Length);
		return Length;
	case SQLTEXT:
	case SQLCHAR:
		if (Length == -1)
		{
			strcpy(Destination, (char*)Src);
		}
		else
		{
			if ((int)Length >= 100)
				SiZ = 100;
			else
				SiZ = Length;
			Count = SiZ;
			strncpy(Destination, (char*)Src, SiZ);
			Destination[Count] = 0;
		}
		if (IsValidNumber(Destination, 59))
		{
			*lpValue = (float)atof(Destination);
			return 4;
		}
		GeneralError(dbproc, 10109);
		return -1;
	case SQLINT1:
		*lpValue = (float)(BYTE)*Src;
		return 4;
	case SQLBIT:
		if (*Src)
			*lpValue = 1.0;
		else
			*lpValue = 0.0;
		return 4;
	case SQLINT2:
		*lpValue = (float)*(__int16*)Src;
		return 4;
	case SQLINT4:
		*lpValue = (float)*(int*)Src;
		return 4;
	case SQLFLT4:
		*lpValue = *(float*)Src;
		return 4;
	case SQLMONEY:
		MoneyToReal((BYTE*)Src, lpValue);
		return 4;
	case SQLFLT8:
		dblVal = *(double*)Src;
		if (dblVal < -3.3999e38 || dblVal > 3.4e38)
		{
			GeneralError(dbproc, SQLECOFL);
			return -1;
		}
		*lpValue = (float)dblVal;
		return 4;
	case SQLDECIMAL:
	case SQLNUMERIC:
		if (!ConvertNumericDecimalToDouble((DBNUMERIC*)Src, &dblVal))
			return -1;

		if (dblVal >= -3.3999e38 && dblVal <= 3.4e38)
		{
			*lpValue = (float)dblVal;
			return 4;
		}
		else
		{
			GeneralError(dbproc, SQLECOFL);
			return -1;
		}
	case SQLMONEY4:
		SmallMoneyToReal((float*)Src, lpValue);
		return 4;
	default:
		GeneralError(dbproc, 10016);
		return -1;
	}
}
int __cdecl ConvertToSmallMoney(PDBPROCESS dbproc, int DataType, BYTE* Src, int Length, int dtOut, DWORD* lpMoney, int OutLength)
{
	int result = 0; 
	int B = 0; 

	DBMONEY Money;
	DBMONEY4 smallmoney;
	int temp = 0;

	B = 0;

	*(DWORD*)lpMoney = 0;
	if (OutLength >= 4)
		result = ConvertToMoney(dbproc, DataType, Src, Length, SQLMONEY, (DBMONEY*)&Money, 8);
	else
		result = ConvertToMoney(dbproc, DataType, Src, Length, SQLMONEY, (DBMONEY*)&Money, OutLength);

	if (result == -1)
		return -1;
	if (DataType == SQLIMAGE || DataType == SQLBINARY)
	{
		temp = Money.mnyhigh;
		Money.mnyhigh = Money.mnylow;
		Money.mnylow = temp;
		smallmoney = temp;
	}
	if (Money.mnyhigh < 0)
	{
		// 为负
		B = 1;
		negatemny(&Money);
	}
	if (Money.mnyhigh == 0 
		|| (B && Money.mnylow > 0x80000000) 
		|| !B && Money.mnylow > 0x7FFFFFFFu)
	{
		// "Data-conversion resulted in overflow."
		GeneralError(dbproc, SQLECOFL);
		return -1;
	}
	else
	{
		if (B)
			smallmoney = -smallmoney;
		*lpMoney = smallmoney;
		if (result <= 4)
			return result;
		else
			return 4;
	}
}
int __cdecl ConvertToSmallDate(PDBPROCESS dbproc, int DataType, SmallDateTime* Src, int Length, int dtOut, SmallDateTime* date)
{
	ULONG ul = 0; 
	DBDATETIME dt; 

	if (ConvertToDateTime(dbproc, DataType, Src, Length, SQLDATETIME, &dt) != -1)
	{
		ul = dt.dttime / 18000;
		dt.dttime /= 18000u;
		if (dt.dtdays < 0x10000 && ul < 1440)
		{
			date->dtdays = dt.dtdays;
			date->dttime = (ushort)ul;
			return 4;
		}
		GeneralError(dbproc, 10039);
	}
	return -1;
}

void __cdecl LocalCharSetConvert(PDBPROCESS dbproc, char* Source, int Count, char mode)
{
	char* result = 0;

	char C[255] = { 0 };

	if ((dbproc->ret_status & 0x400) == 0 || dbproc->bcpinfo->direction != DB_OUT)
	{
		if (Count <= 255)
		{
			result = C;
		}
		else
		{
			result = (char*)AllocateHeapMemory(4, dbproc, Count + 1, 1);
			if (!result)
				return;
		}
		strncpy(result, Source, Count);
		result[Count] = 0;
		if ((dbproc->ret_status & 0x400) != 0 && dbproc->bcpinfo->direction == DB_IN)
		{
			dbWinConvToServer(dbproc, result, Count);
		}
		else if (mode == 1)
		{
			OemToCharA(result, result);
		}
		else
		{
			CharToOemA(result, result);
		}
		strncpy(Source, result, Count);
		if (Count > 255)
			FreeMemory(dbproc, result);
	}

}

BOOL __cdecl IsNumericValid(BYTE* Src)
{
	return *Src <= 38u && Src[1] <= 38u && Src[1] <= *Src && (!Src[2] || Src[2] == 1);
}
char __cdecl GetMaxNumericBytes(char C)
{
	char result = 0; 

	switch (C)
	{
	case 0:
	case 1:
	case 2:
		result = 2;
		break;
	case 3:
	case 4:
		result = 3;
		break;
	case 5:
	case 6:
	case 7:
		result = 4;
		break;
	case 8:
	case 9:
		result = 5;
		break;
	case 0xA:
	case 0xB:
	case 0xC:
		result = 6;
		break;
	case 0xD:
	case 0xE:
		result = 7;
		break;
	case 0xF:
	case 0x10:
		result = 8;
		break;
	case 0x11:
	case 0x12:
	case 0x13:
		result = 9;
		break;
	case 0x14:
	case 0x15:
		result = 10;
		break;
	case 0x16:
	case 0x17:
	case 0x18:
		result = 11;
		break;
	case 0x19:
	case 0x1A:
		result = 12;
		break;
	case 0x1B:
	case 0x1C:
		result = 13;
		break;
	case 0x1D:
	case 0x1E:
	case 0x1F:
		result = 14;
		break;
	case 0x20:
	case 0x21:
		result = 15;
		break;
	case SQLIMAGE:
	case SQLTEXT:
	case 0x24:
		result = 16;
		break;
	case SQLVARBINARY:
	case SQLINTN:
		result = 17;
		break;
	default:
		result = -1;
		break;
	}
	return result;
}
void __cdecl numeric_shift(DWORD* Src, int shift)
{

	BYTE* p1 = 0; 
	BYTE* p2 = 0; 
	BYTE* p3 = 0; 
	int val1 = 0; 
	int val2 = 0;

	val1 = 0;
	p1 = (BYTE*)Src[2];
	p2 = p1;
	p3 = &p1[*Src];
	while (p2 < p3)
	{
		val2 = *p1++ * shift + val1;
		*p2++ = val2 % 0x100;
		val1 = val2 >> 8;
	}
	if (val1)
		*p2++ = val1;

	*Src = (DWORD)p2 - Src[2];

}

void __cdecl numeric_add(DWORD* Src, unsigned int add)
{

	int val = 0;
	int i = 0;
	int byVal = 0; 

	val = *Src;
	for (i = 0; i < val; ++i)
	{
		byVal = *(BYTE*)(Src[2] + i) + add;
		*(BYTE*)(Src[2] + i) = byVal % 0x100;
		add = byVal >> 8;

	}
	if (add)
	{
		*(BYTE*)(Src[2] + i) = add;
	}
	*Src = i;

}
int __cdecl stringtonumeric(char* Src, int typ, BYTE* numeric, DBNUMERIC* lpBuffer)
{
	char C = 0; 
	int pos = 0; 
	char i = 0; 
	int ival[3] = { 0 };

	pos = -1;
	ival[2] = (int)lpBuffer->val;
	ival[0] = 0;

	if (*Src == '-')
	{
		*(BYTE*)& ival[1] = 0;
		++Src;
	}
	else if (*Src == '+')
	{
		*(BYTE*)&ival[1] = 1;
		++Src;
	}
	else
	{
		*(BYTE*)&ival[1] = 1;
	}
	i = 0;
	while (1)
	{
		C = (char)*Src++;
		if (!C || C == ' ')
			break;
		if (C < '0' || C > '9')
		{
			if (C != '.')
				return 0;
			pos = i;
		}
		else
		{
			numeric_shift((DWORD*)ival, 10);
			numeric_add((DWORD*)ival, C - '0');
			++i;
		}
	}
	lpBuffer->precision = i;
	if (pos == -1)
		lpBuffer->scale = 0;
	else
		lpBuffer->scale = i - pos;
	lpBuffer->sign = ival[1];
	*numeric = (BYTE)ival[0];
	return 1;
}
int __cdecl ConvertCharToNumericDecimal(char* Src, int Count, DBNUMERIC* lpBuffer)
{
	char Destination[80] = { 0 };
	BYTE numeric[4] = { 0 };
	char* p = 0; 

	memset(Destination, 0, sizeof(Destination));
	if (Count > 79)
		return 0;
	dbzero(lpBuffer, 19u);
	strncpy(Destination, Src, Count);
	Destination[Count] = 0;
	for (p = Destination; *p == ' '; ++p)
		;
	if (p != Destination)
	{
		if (!*p)
			return 0;
		strcpy(Destination, p);
	}
	return stringtonumeric(Destination, 0, numeric, lpBuffer);
}
int __cdecl ConvertULongToNumericDecimal(unsigned int value, DBNUMERIC* lpBuffer)
{
	char C = 0;

	dbzero(lpBuffer, 19u);
	lpBuffer->sign = 1;
	*(_DWORD*)lpBuffer->val = value;
	C = 1;
	while (value >= 10)
	{
		++C;
		value /= 10;
	}
	lpBuffer->precision = C;
	return 1;
}
int __cdecl ConvertLongToNumericDecimal(int value, DBNUMERIC* lpBuffer)
{
	char sign = 0; 

	sign = 1;
	if (value < 0)
	{
		value = -value;
		sign = 0;
	}
	ConvertULongToNumericDecimal(value, lpBuffer);
	lpBuffer->sign = sign;
	return 1;
}
int __cdecl ConvertDoubleToNumericDecimal(double value, int , DBNUMERIC* lpBuffer)
{
	int L; 
	const char* Format = 0; 
	char Buffer[380] = { 0 };

	char* p = 0; 

	Format = "%23.15f";
	memset(Buffer, 0, sizeof(Buffer));
	sprintf(Buffer, Format, value);
	StripBlanks(Buffer);
	AddDecimalZeroToEnd(Buffer);
	L = strlen(Buffer) + 1;

	if (L != 1 && DBCS_STRSTR(Buffer, (char*)"."))
	{
		for (p = &Buffer[L - 2]; *p == '0'; --p)
		{
			if (!(__mb_cur_max <= 1 ? _pctype[*(p - 1)] & 4 : _isctype(*(p - 1), 4)))
				break;
			*p = 0;
		}
	}
	return ConvertCharToNumericDecimal(Buffer, strlen(Buffer), lpBuffer);
}
int __cdecl ConvertMoneyToNumericDecimal(BYTE* Src, DBNUMERIC* lpBuffer)
{
	double Value = 0; 

	MoneyToDouble(Src, &Value);
	return ConvertDoubleToNumericDecimal(Value, 0, lpBuffer);
}
int __cdecl NumericToNumeric(int a1, DBNUMERIC* Src, DBNUMERIC* lpBuffer)
{
	char* Src1 = 0; 
	char C = 0; 
	char Str1[78] = { 0 }, Source[78] = { 0 };

	int i1,i2 = 0;
	char* p1 = 0; 



	C = 0;
	memset(Source, 0, sizeof(Source));
	memset(Str1, 0, sizeof(Str1));

	if (!lpBuffer->precision && !lpBuffer->scale)
	{
		lpBuffer->precision = Src->precision;
		lpBuffer->scale = Src->scale;
	}
	if (!ConvertNumericDecimalToChar(Src, Str1))
		return 0;
	p1 = DBCS_STRSTR(Str1, (char*)".");
	if (Str1[0] == '+' || Str1[0] == '-')
	{
		C = Str1[0];
		Src1 = &Str1[1];
	}
	else
	{
		Src1 = Str1;
	}
	if (p1)
	{
		while (*Src1 == '0')
			++Src1;
	}
	if (p1)
		i2 = (int)(&Str1[strlen(Str1)] - (int)p1 - 1);
	else
		i2 = 0;
	if (lpBuffer->scale < (i2))
	{

		if (lpBuffer->scale)
		{
			p1[lpBuffer->scale + 1] = 0;
		}
		else
		{
			*p1 = 0;
			p1 = 0;
		}
	}
	if (p1)
		i1 = i2 + (int)(p1 - Src1);
	else
		i1 = strlen(Src1);
	if (lpBuffer->precision < i1)
		return 0;
	if (a1 && i1 - i2 > (lpBuffer->precision - lpBuffer->scale))
		return 0;
	if (C == '-')
		Source[0] = '-';
	else
		Source[0] = '+';
	BYTE btVal2 = 0;
	while (btVal2 < lpBuffer->precision + 1)
	{
		Source[btVal2 + 1] = '0';
		btVal2++;
	}
	Source[lpBuffer->precision + 2] = 0;
	if (!p1)
		strcat(Str1, ".");
	dbmove(
		Src1,
		&Source[lpBuffer->precision - (char)lpBuffer->scale + 1 - (i1 - i2)],
		strlen(Src1));
	return ConvertCharToNumericDecimal(Source, strlen(Source), lpBuffer);
}
int __cdecl ConvertMoney4ToNumericDecimal(int* Src, DBNUMERIC* lpDecimal)
{
	double value = 0; 

	SmallMoneyToDouble(Src, &value);
	return ConvertDoubleToNumericDecimal(value, 0, lpDecimal);
}

int __cdecl ConvertToNumericDecimal(PDBPROCESS dbproc, int DataType, BYTE* Src, int Length, int dtOut, DBNUMERIC* lpDecimal, int OutLength)
{
	int result, result1;
	double val = 0; 
	DBNUMERIC Deci; 
	int Sizea = 0; 

	Deci = *lpDecimal;
	Deci.sign = 0;
	if (!IsNumericValid(&Deci.precision))
		return -1;
	switch (DataType)
	{
	case SQLIMAGE:
	case SQLBINARY:
		if (OutLength >= 19)
			Sizea = 19;
		else
			Sizea = OutLength;
		dbzero(lpDecimal, OutLength);
		dbmove(Src, lpDecimal, Sizea);
		result1 = 1;
		break;
	case SQLTEXT:
	case SQLCHAR:
		if (Length == -1)
			Sizea = strlen((const char*)Src);
		else
			Sizea = Length;
		result1 = ConvertCharToNumericDecimal((char*)Src, Sizea, lpDecimal);
		break;
	case SQLINT1:
	case SQLBIT:
		result1 = ConvertULongToNumericDecimal(*Src, lpDecimal);
		break;
	case SQLINT2:
		result1 = ConvertLongToNumericDecimal(*(__int16*)Src, lpDecimal);
		break;
	case SQLINT4:
		result1 = ConvertLongToNumericDecimal(*(_DWORD*)Src, lpDecimal);
		break;
	case SQLFLT4:
		val = FloatToDouble(*(float*)Src);
		result1 = ConvertDoubleToNumericDecimal(val, 1, lpDecimal);
		break;
	case SQLMONEY:
		result1 = ConvertMoneyToNumericDecimal(Src, lpDecimal);
		break;
	case SQLFLT8:
		result1 = ConvertDoubleToNumericDecimal(*(double*)Src, 0, lpDecimal);
		break;
	case SQLDECIMAL:
	case SQLNUMERIC:
		if (IsNumericValid(Src))
		{
			result1 = NumericToNumeric(0, (DBNUMERIC*)Src, lpDecimal);
		}
		else
		{
			return -1;
		}
		break;
	case SQLMONEY4:
		result1 = ConvertMoney4ToNumericDecimal((int*)Src, lpDecimal);
		break;
	default:
		GeneralError(dbproc, 10016);
		return -1;
	}

	if (!result1 || !Deci.precision || DataType == SQLNUMERIC || DataType == SQLDECIMAL)
	{
		result = result1 != 0 ? 19 : -1;
	}
	else if (NumericToNumeric(1, lpDecimal, &Deci))
	{
		dbmove(&Deci, lpDecimal, 19u);
		result = 19;
	}
	else
	{
		result = -1;
	}
	return result;
}

int __cdecl canquery(PDBPROCESS dbproc)
{
	int result = 0; 
	char buffer[100] = { 0 };

	if ((dbproc->ret_status & 1) != 0)
	{
		dbproc->ret_status &= ~1u;
		do
			result = dbreadtext(dbproc, buffer, 100);
		while (result > 0);
		if (result == -1)
			return 0;
	}

	while (1)
	{
		result = dbnextrow(dbproc);
		if (result == NO_MORE_ROWS)
			break;
		if (!result)
			return 0;
		if (result == -3)
			dbclrbuf(dbproc, 1);
	}
	return 1;
}

void __stdcall DropDbproc(PDBPROCESS dbproc)
{

	for (int i = 0; i < DbMaxProcs; ++i)
	{
		if (dbproc == DbProcArray[i])
		{
			DbProcArray[i] = 0;
			return ;
		}
	}

}
void __stdcall DropProcArray()
{

	EnterCriticalSection(&DbProcSem);
	if (DbProcArray)
	{
		for (int i = 0; i < DbMaxProcs; ++i)
		{
			if (DbProcArray[i])
			{
				LeaveCriticalSection(&DbProcSem);
				return;
			}
		}
		FreeMemory(0, DbProcArray);
		DbProcArray = 0;
		LeaveCriticalSection(&DbProcSem);
	}
	else
	{

		LeaveCriticalSection(&DbProcSem);
	}
}

int __stdcall MoveRows(PDBPROCESS dbproc, int nrow)
{
	alt_column_data_t** altrowdata = 0;
	int row_ = 0;
	rowbuffer_t* pbuffer = 0;
	int i = 0;
	column_data_t** column_data = 0;

	i = 0;
	column_data = dbproc->columns_data;
	altrowdata = dbproc->altrowdata;
	row_ = dbproc->rowidx;
	if (nrow + row_ <= dbproc->nbufrow)
		dbproc->rowidx += nrow;
	else
		dbproc->rowidx += nrow - dbproc->nbufrow;

	if (nrow == dbproc->nbufrow - 1)
		dbproc->nextrowidx = dbproc->rowidx;

	while (i < nrow)
	{
		if (row_ > dbproc->nbufrow)
			row_ = 1;
		pbuffer = &dbproc->rowbuffer[row_ - 1];
		dbproc->columns_data = pbuffer->columnsdata;
		if (column_data == dbproc->columns_data)
			column_data = 0;
		free_rowdata(dbproc, 0);
		dbproc->altrowdata = pbuffer->altcoldata;
		if (altrowdata == dbproc->altrowdata)
			altrowdata = 0;
		if (dbproc->altrowdata)
		{
			free_altrowdata(dbproc);
			pbuffer->altcoldata = 0;
		}
		pbuffer->nrow = 0;
		++i;
		++row_;
		++dbproc->firstrow;
	}
	dbproc->columns_data = column_data;
	dbproc->altrowdata = altrowdata;
	return 1;
}

int __stdcall CheckColumn(PDBPROCESS dbproc, int col)
{
	if (dbproc)
	{
		if (CheckForValidDbproc(dbproc))
		{
			if (dbproc->bclosed)
			{
				GeneralError(dbproc, SQLEDDNE);
				return 0;
			}
			else if (col <= dbproc->numcols && col >= 1)
			{
				return 1;
			}
			else
			{
				GeneralError(dbproc, SQLECNOR);
				return 0;
			}
		}
		else
		{
			return 0;
		}
	}
	else
	{
		GeneralError(0, SQLENULL);
		return 0;
	}
}

int __stdcall numtabkeys(PDBPROCESS dbproc, int ntab)
{
	int i = 0;
	column_info_t** coldata = 0;
	int Count = 0;

	Count = 0;
	coldata = dbproc->columns_info;
	for (i = 0; i < dbproc->ncols; ++i)
	{
		if (coldata[i]->ntab == ntab && (coldata[i]->type & 8) != 0)
			++Count;
	}
	return Count;
}
/*
* timestamp column name
*/
char* __stdcall dbtsname(PDBPROCESS dbproc, int ntab)
{
	int i = 0;
	column_info_t** coldata = 0; 

	coldata = dbproc->columns_info;
	for (i = 0; ; ++i)
	{
		if (i >= dbproc->ncols)
			return 0;
		if (coldata[i]->ntab == ntab && coldata[i]->usertype == SQLTIMESTAMP)
			break;
	}
	if ((coldata[i]->type & 0x20) != 0)
		return coldata[i]->actualname;
	else
		return coldata[i]->name;
}
char* __stdcall dbkeyname(PDBPROCESS dbproc, int ntab, int index, int* lpSize)
{
	int i = 0;
	int C = 0; 
	column_info_t** coldata = 0; 

	C = 0;
	coldata = dbproc->columns_info;
	for (i = 0; i < dbproc->ncols; ++i)
	{
		if (coldata[i]->ntab == ntab && (coldata[i]->type & 8) != 0)
			++C;
		if (index == C)
			break;
	}
	if (index == C)
	{
		if ((coldata[i]->type & 0x20) != 0)
		{
			if (lpSize)
				*lpSize = strlen((const char*)coldata[i]->actualname);
			return coldata[i]->actualname;
		}
		else
		{
			if (lpSize)
				*lpSize = strlen(coldata[i]->name);
			return coldata[i]->name;
		}
	}
	else
	{
		if (lpSize)
			*lpSize = -1;
		return 0;
	}
}
BYTE* __stdcall dbkeydata(PDBPROCESS dbproc, int ntab, int index, int* lpSize)
{
	int i = 0; 
	int C = 0;
	column_info_t** coldata = 0; 
	column_data_t** column_data = 0; 

	C = 0;
	coldata = dbproc->columns_info;
	for (i = 0; i < dbproc->ncols; ++i)
	{
		if (coldata[i]->ntab == ntab && (coldata[i]->type & 8) != 0)
			++C;
		if (index == C)
			break;
	}
	if (index == C)
	{
		column_data = dbproc->columns_data;
		if (column_data)
		{
			if (lpSize)
				*lpSize = column_data[i]->len;
			return column_data[i]->data;
		}
		else
		{
			if (lpSize)
				*lpSize = 0;
			return 0;
		}
	}
	else
	{
		if (lpSize)
			*lpSize = 0;
		return 0;
	}
}
int __cdecl getcommontype(int DataType, int DataLength)
{
	int result = 0; 

	switch (DataType)
	{
	case SQLINTN:
		switch (DataLength)
		{
		case 1:
			result = SQLINT1;
			break;
		case 2:
			result = SQLINT2;
			break;
		case 4:
			result = SQLINT4;
			break;
		default:
			result = 0;
			break;
		}
		break;
	case SQLFLTN:
		if (DataLength == 4)
		{
			result = SQLFLT4;
		}
		else if (DataLength == 8)
		{
			result = SQLFLT8;
		}
		else
		{
			result = 0;
		}
		break;
	case SQLMONEYN:
		if (DataLength == 4)
		{
			result = SQLMONEY4;
		}
		else if (DataLength == 8)
		{
			result = SQLMONEY;
		}
		else
		{
			result = 0;
		}
		break;
	case SQLDATETIMN:
		if (DataLength == 4)
		{
			result = SQLDATETIM4;
		}
		else if (DataLength == 8)
		{
			result = SQLDATETIME;
		}
		else
		{
			result = 0;
		}
		break;
	default:
		result = DataType;
		break;
	}
	return result;
}
int __cdecl dbconvert_getcommontype(int DataType, int DataLength)
{
	int result = 0; 

	switch (DataType)
	{
	case SQLVARBINARY:
		result = SQLBINARY;
		break;
	case SQLINTN:
	case SQLFLTN:
	case SQLMONEYN:
	case SQLDATETIMN:
		result = getcommontype(DataType, DataLength);
		break;
	case SQLVARCHAR:
		result = SQLCHAR;
		break;
	default:
		result = DataType;
		break;
	}
	return result;
}
int __stdcall PadString(char* Src, int length, int BindType, int DataOutLength, char cPad)
{
	int I = 0; 
	int i = 0;
	int L = 0; 
	char* p = 0; 

	if (BindType == NTBSTRINGBIND)
	{
		p = &Src[length - 1];
		if (DataOutLength != -1 && length >= DataOutLength)
			p = &Src[length - 2];
		while (p > Src && *p == ' ')
			--p;
		if (p == Src && *p == ' ')
			*p = 0;
		else
			p[1] = 0;
		return 1;
	}
	else
	{
		if (BindType == STRINGBIND)
			L = DataOutLength - 1;
		else
			L = DataOutLength;
		for (i = length; i < L; ++i)
			Src[i] = cPad;
		if (BindType == STRINGBIND)
		{
			if (i <= L)
				I = i;
			else
				I = L;
			Src[I] = 0;
		}
		return 1;
	}
}
size_t __stdcall DoNullBind(PDBPROCESS dbproc, int BindType, int DataOutLength, char* Src)
{
	int lo,l1,lp = 0;
	null_value_t* nullbind = dbproc->nulls;
	if (DataOutLength >= 1)
		lo = DataOutLength;
	else
		lo = 0;
	dbproc->isavail = 0;
	switch (BindType)
	{
	case TINYBIND:
		*Src = nullbind->ntiny;
		return 1;
	case SMALLBIND:
		*(WORD*)Src = nullbind->nsmall;
		return 2;
	case INTBIND:
		*(_DWORD*)Src = nullbind->nint;
		return 4;
	case CHARBIND:

		if (DataOutLength != -1 && DataOutLength < nullbind->nchar_length)
		{
			GeneralError(dbproc, SQLECOFL);
			return -1;
		}
		if (lo <= 0)
		{
			l1 = nullbind->nchar_length;
		}
		else
		{
			if (lo >= nullbind->nchar_length)
				lp = nullbind->nchar_length;
			else
				lp = lo;
			l1 = lp;
		}

		dbmove(nullbind->p_nchar, Src, l1);
		PadString(Src, l1, BindType, lo < 0 ? 0 : lo, ' ');
		return l1;
	case BINARYBIND:

		if (DataOutLength != -1 && DataOutLength < nullbind->nbinary_length)
		{
			GeneralError(dbproc, SQLECOFL);
			return -1;
		}
		if (lo <= 0)
		{
			l1 = nullbind->nbinary_length;
		}
		else
		{
			if (lo >= nullbind->nbinary_length)
				lp = nullbind->nbinary_length;
			else
				lp = lo;
			l1 = lp;
		}

		dbmove(nullbind->p_nbinary, Src, l1);
		if ((int)(lo - l1) >= 0)
			dbzero(&Src[l1], lo - l1);
		else
			dbzero(&Src[l1], 0);
		return l1;
	case BITBIND:
		*Src = (char)nullbind->nbit;
		return 1;
	case DATETIMEBIND:
		dbmove(&nullbind->ndatetime, Src, 8u);
		return 8;
	case MONEYBIND:
		dbmove(&nullbind->nmoney, Src, 8u);
		return 8;
	case FLT8BIND:
		*(double*)Src = nullbind->nfloat8;
		return 8;
	case STRINGBIND:
		l1 = strlen(nullbind->p_nstring);

		if (DataOutLength != -1 && DataOutLength < l1)
		{
			GeneralError(dbproc, SQLECOFL);
			return -1;
		}
		if (lo <= 0)
		{
			lp = l1;
		}
		else
		{
			if (lo >= l1)
				lp = l1;
			else
				lp = lo;

		}

		strncpy(Src, nullbind->p_nstring, lp);
		PadString(Src, lp, BindType, lo < 0 ? 0 : lo, 32);
		if (lo <= 0)
			l1 = lp;
		else
			l1 = lo - 1;
		Src[l1] = 0;
		return lp;
	case NTBSTRINGBIND:
		l1 = strlen(nullbind->p_ntbstring) ;

		if (DataOutLength != -1 && DataOutLength < l1)
		{
			GeneralError(dbproc, SQLECOFL);
			return -1;
		}
		if (lo <= 0)
		{
			lp = l1;
		}
		else
		{
			if (lo >= l1)
				lp = l1;
			else
				lp = lo;

		}

		if (!lp && DataOutLength)
			*Src = 0;
		strncpy(Src, nullbind->p_ntbstring, lp);
		Src[lp] = 0;
		return lp;
	case VARYCHARBIND:
		if (DataOutLength != -1 && DataOutLength < nullbind->p_nvarychar->len)
		{
			GeneralError(dbproc, SQLECOFL);
			return -1;
		}
		if (lo <= 0)
		{
			l1 = nullbind->p_nvarychar->len;
		}
		else
		{
			if (lo >= nullbind->p_nvarychar->len)
				lp = nullbind->p_nvarychar->len;
			else
				lp = lo;
			l1 = lp;
		}

		*(WORD*)Src = l1;
		dbmove(nullbind->p_nvarychar->str, Src + 2, l1);
		return l1;
	case VARYBINBIND:

		if (DataOutLength == -1 || DataOutLength >= nullbind->p_nvarybin->len)
		{
			if (lo <= 0)
			{
				l1 = nullbind->p_nvarybin->len;
			}
			else
			{
				if (lo >= nullbind->p_nvarybin->len)
					l1 = nullbind->p_nvarybin->len;
				else
					l1 = lo;

			}

			*(WORD*)Src = l1;
			dbmove(nullbind->p_nvarybin->array, Src + 2, l1);
			return l1;
		}
		else
		{
			GeneralError(dbproc, SQLECOFL);
			return -1;
		}
	case FLT4BIND:
		*(float*)Src = nullbind->nfloat4;
		return 4;
	case SMALLMONEYBIND:
		dbmove(&nullbind->nsmallmoney, Src, 4u);
		return 4;
	case SMALLDATETIBIND:
		dbmove(&nullbind->nsmalldate, Src, 4u);
		return 4;
	case DECIMALBIND:
	case SRCDECIMALBIND:
		*(DBDECIMAL*)Src = nullbind->ndecimal;
		return 19;
	case NUMERICBIND:
	case SRCNUMERICBIND:
		*(DBNUMERIC*)Src = nullbind->nnumeric;
		return 19;
	default:
		return 0;
	}
}
int __stdcall SetTypeNull(PDBPROCESS dbproc, BYTE* Src, int DataType, int DataOutLength)
{
	int result = 0;
	int l0 = 0; 
	int bdType = 0;

	switch (DataType)
	{
	case SQLIMAGE:
	case SQLBINARY:
		bdType = BINARYBIND;
		break;
	case SQLTEXT:
	case SQLCHAR:
		if (DataOutLength == -1)
			bdType = NTBSTRINGBIND;
		else
			bdType = CHARBIND;
		break;
	case SQLINT1:
		bdType = TINYBIND;
		break;
	case SQLBIT:
		bdType = BITBIND;
		break;
	case SQLINT2:
		bdType = SMALLBIND;
		break;
	case SQLINT4:
		bdType = INTBIND;
		break;
	case SQLDATETIM4:
		bdType = SMALLDATETIBIND;
		break;
	case SQLFLT4:
		bdType = FLT4BIND;
		break;
	case SQLMONEY:
		bdType = MONEYBIND;
		break;
	case SQLDATETIME:
		bdType = DATETIMEBIND;
		break;
	case SQLFLT8:
		bdType = FLT8BIND;
		break;
	case SQLDECIMAL:
		bdType = SRCDECIMALBIND;
		break;
	case SQLNUMERIC:
		bdType = SRCNUMERICBIND;
		break;
	case SQLMONEY4:
		bdType = SMALLMONEYBIND;
		break;
	default:
		break;
	}
	if (dbproc)
		return DoNullBind(dbproc, bdType, DataOutLength, (char*)Src);
	switch (DataType)
	{
	case SQLIMAGE:
	case SQLTEXT:
	case SQLBINARY:
	case SQLCHAR:
		if (DataOutLength)
		{
			*Src = 0;
			result = 1;
		}
		else
		{
			GeneralError(0, SQLECOFL);
			result = 0;
		}
		break;
	default:
		l0 = TypeLength(DataType);
		dbzero(Src, l0);
		result = l0;
		break;
	}
	return result;
}
int __cdecl getcmdbuffer(PDBPROCESS dbproc, int Length, buf_node_t** pbuf, int* lpReturn)
{
	int Count = 0; 
	buf_node_t* cmd = 0; 

	if (!CheckEntry(dbproc))
		return 0;
	if (Length >= 0)
	{
		Count = 0;
		for (cmd = dbproc->cmdbuffer; cmd && Length >= (cmd->size + Count); cmd = cmd->next)
			Count += cmd->size;
		if (cmd)
		{
			*pbuf = cmd;
			*lpReturn = Length - Count;
		}
		else
		{
			*pbuf = 0;
			*lpReturn = 0;
		}
		return 1;
	}
	else
	{
		GeneralError(dbproc, 10035);
		return 0;
	}
}
int __stdcall VarBindLength(BYTE* Src, int Length, BYTE cpad, int DataType)
{
	BYTE* p = 0;

	if (DataType != SQLTEXT && DataType != SQLVARCHAR && DataType != SQLCHAR)
		return Length;
	for (p = &Src[Length - 1]; p >= Src && *p == cpad; --p)
		;
	return p - Src + 1;
}
BOOL __stdcall BindVar(PDBPROCESS dbproc, int row)
{
	BOOL result = 0;
	int l1 = 0; 
	BYTE* p = 0;
	BYTE cPad = 0; 

	BYTE* data = 0; 
	int L, len, length, ColumnType, lengthOut; 
	column_data_t** column_data = 0; 

	if (row >= dbproc->numcols || !dbproc->binds || !dbproc->binds[row])
		return 1;
	column_data = dbproc->columns_data;
	ColumnType = GetColumnType(dbproc, dbproc->columns_info[row]->coltype, dbproc->columns_info[row]->collen);
	if (ColumnType == SQLIMAGE || ColumnType == SQLTEXT)
	{
		data = ((blob_t * )column_data[row]->data)->data;
		len = column_data[row]->len;
	}
	else
	{
		data = column_data[row]->data;
		len = column_data[row]->len;
	}

	if (!dbproc->binds[row]->conv_func)
		return 0;
	if (len && data)
	{
		lengthOut = dbproc->binds[row]->length;
		if (dbproc->binds[row]->indicator)
			*(_DWORD*)dbproc->binds[row]->indicator = 0;
		switch (dbproc->binds[row]->bind_type)
		{
		case TINYBIND:
			length = VarBindLength(data, len, ' ', ColumnType);
			if (((CONVERTFUNC)dbproc->binds[row]->conv_func)(
				dbproc,
				ColumnType,
				data,
				length,
				SQLINT1,
				dbproc->binds[row]->buffer,
				lengthOut) != -1)
				return 1;
			return 0;
		case SMALLBIND:
			length = VarBindLength(data, len, 32, ColumnType);
			if (((CONVERTFUNC)dbproc->binds[row]->conv_func)(
				dbproc,
				ColumnType,
				data,
				length,
				SQLINT2,
				dbproc->binds[row]->buffer,
				lengthOut) != -1)
				return 1;
			return 0;
		case INTBIND:
			length = VarBindLength(data, len, 32, ColumnType);
			if (((CONVERTFUNC)dbproc->binds[row]->conv_func)(
				dbproc,
				ColumnType,
				data,
				length,
				SQLINT4,
				dbproc->binds[row]->buffer,
				lengthOut) != -1)
				return 1;
			return 0;
		case CHARBIND:
			goto LABEL_23;
		case BINARYBIND:
			length = ((CONVERTFUNC)dbproc->binds[row]->conv_func)(
				dbproc,
				ColumnType,
				data,
				len,
				SQLBINARY,
				dbproc->binds[row]->buffer,
				lengthOut);
			if (length == -1)
				return 0;
			PadString((char*)dbproc->binds[row]->buffer, length, dbproc->binds[row]->bind_type, lengthOut, 0);
			return 1;
		case BITBIND:
			if (((CONVERTFUNC)dbproc->binds[row]->conv_func)(
				dbproc,
				ColumnType,
				data,
				len,
				SQLBIT,
				dbproc->binds[row]->buffer,
				lengthOut) != -1)
				return 1;
			return 0;
		case DATETIMEBIND:
			if (ColumnType == SQLCHAR || ColumnType == SQLTEXT || ColumnType == SQLVARCHAR)
			{
				if (ColumnType == SQLVARCHAR)
					cPad = 0;
				else
					cPad = ' ';
				L = len;
				for (p = &data[len - 1]; L > 0 && *p == cPad && p != data; --p)
					--L;
				len = L;
			}
			if (((CONVERTFUNC)dbproc->binds[row]->conv_func)(
				dbproc,
				ColumnType,
				data,
				len,
				SQLDATETIME,
				dbproc->binds[row]->buffer,
				lengthOut) != -1)
				return 1;
			return 0;
		case MONEYBIND:
			length = VarBindLength(data, len, 32, ColumnType);
			if (((CONVERTFUNC)dbproc->binds[row]->conv_func)(
				dbproc,
				ColumnType,
				data,
				length,
				SQLMONEY,
				dbproc->binds[row]->buffer,
				lengthOut) != -1)
				return 1;
			return 0;
		case FLT8BIND:
			// int __cdecl ConvertToFloat(db_dbprocess* dbproc, int DataType, BYTE* Src, unsigned int Size, int dtOut, double* lpValue)
			length = VarBindLength(data, len, 32, ColumnType);
			if (((CONVERTFUNC)dbproc->binds[row]->conv_func)(
				dbproc,
				ColumnType,
				data,
				length,
				SQLFLT8,
				dbproc->binds[row]->buffer,
				lengthOut) != -1)
				return 1;
			return 0;
		case STRINGBIND:
		case NTBSTRINGBIND:
			if (lengthOut == 1)
			{
				*(BYTE*)dbproc->binds[row]->buffer = 0;
				return 1;
			}
			if (lengthOut > 0)
				--lengthOut;
		LABEL_23:
			length = ((CONVERTFUNC0)dbproc->binds[row]->conv_func)(
				dbproc,
				ColumnType,
				data,
				len,
				SQLCHAR,
				dbproc->binds[row]->buffer,
				lengthOut,
				dbproc->binds[row]->indicator);
			if (length == -1)
				return 0;
			PadString((char*)dbproc->binds[row]->buffer, length, dbproc->binds[row]->bind_type, dbproc->binds[row]->length, 32);
			return 1;
			break;
		case VARYCHARBIND:
			length = VarBindLength(data, len, 0, ColumnType);
			if ((unsigned int)lengthOut > 2)
			{
				if (lengthOut > 0)
					lengthOut -= 2;
				l1 = ((CONVERTFUNC0)dbproc->binds[row]->conv_func)(
					dbproc,
					ColumnType,
					data,
					length,
					SQLCHAR,
					(char*)dbproc->binds[row]->buffer + 2,
					lengthOut,
					dbproc->binds[row]->indicator);
			}
			else
			{
				l1 = ((CONVERTFUNC0)dbproc->binds[row]->conv_func)(
					dbproc,
					ColumnType,
					data,
					length,
					SQLCHAR,
					(char*)dbproc->binds[row]->buffer + 2,
					0,
					dbproc->binds[row]->indicator);
			}
			if (l1 == -1)
				return 0;
			*(WORD*)dbproc->binds[row]->buffer = l1;
			return 1;
		case VARYBINBIND:
			length = VarBindLength(data, len, 32, ColumnType);
			if (lengthOut > 2)
			{
				if (lengthOut > 0)
					lengthOut -= 2;
				l1 = ((CONVERTFUNC)dbproc->binds[row]->conv_func)(
					dbproc,
					ColumnType,
					data,
					length,
					SQLBINARY,
					(char*)dbproc->binds[row]->buffer + 2,
					lengthOut);
			}
			else
			{
				l1 = ((CONVERTFUNC)dbproc->binds[row]->conv_func)(
					dbproc,
					ColumnType,
					data,
					length,
					SQLBINARY,
					(char*)dbproc->binds[row]->buffer + 2,
					0);
			}
			if (l1 == -1)
			{
				result = 0;
			}
			else
			{
				*(WORD*)dbproc->binds[row]->buffer = l1;
				return 1;
			}
			break;
		case FLT4BIND:
			length = VarBindLength(data, len, 32, ColumnType);
			if (((CONVERTFUNC)dbproc->binds[row]->conv_func)(
				dbproc,
				ColumnType,
				data,
				length,
				SQLFLT4,
				dbproc->binds[row]->buffer,
				lengthOut) != -1)
				return 1;
			return 0;
		case SMALLMONEYBIND:
			length = VarBindLength(data, len, 32, ColumnType);
			if (((CONVERTFUNC)dbproc->binds[row]->conv_func)(
				dbproc,
				ColumnType,
				data,
				length,
				SQLMONEY4,
				dbproc->binds[row]->buffer,
				lengthOut) != -1)
				return 1;
			return 0;
		case SMALLDATETIBIND:
			if (ColumnType == SQLCHAR || ColumnType == SQLTEXT || ColumnType == SQLVARCHAR)
			{
				if (ColumnType == SQLVARCHAR)
					cPad = 0;
				else
					cPad = ' ';
				L = len;
				for (p = &data[len - 1]; L > 0 && *p == cPad && p != data; --p)
					--L;
				len = L;
			}
			if (((CONVERTFUNC)dbproc->binds[row]->conv_func)(
				dbproc,
				ColumnType,
				data,
				len,
				SQLDATETIM4,
				dbproc->binds[row]->buffer,
				lengthOut) != -1)
				return 1;
			return 0;
		case DECIMALBIND:
		case NUMERICBIND:
			goto LABEL_79;
		case SRCDECIMALBIND:
		case SRCNUMERICBIND:
			*(BYTE*)dbproc->binds[row]->buffer = 0;
			*((BYTE*)dbproc->binds[row]->buffer + 1) = 0;
		LABEL_79:
			length = VarBindLength(data, len, 32, ColumnType);
			if (((CONVERTFUNC)dbproc->binds[row]->conv_func)(
				dbproc,
				ColumnType,
				data,
				length,
				SQLNUMERIC,
				dbproc->binds[row]->buffer,
				lengthOut) != -1)
				return 1;
			return 0;
		default:
			return 0;
		}
	}
	else
	{
		if (dbproc->binds[row]->indicator)
			*(_DWORD*)dbproc->binds[row]->indicator = -1;
		return DoNullBind(dbproc, dbproc->binds[row]->bind_type, dbproc->binds[row]->length, (char*)dbproc->binds[row]->buffer) != -1;
	}
	return result;
}
BOOL __stdcall BindAVar(PDBPROCESS dbproc, int nrow, int column)
{
	BOOL result = 0; 
	BYTE* buffer = 0; 
	altcol_link_t* Compute = 0;
	BYTE* data,cPad = 0; 
	int ColumnType = 0; 
	BYTE* p = 0;
	int L,len,length,l1 = 0; 
	column_data_t** pvdata = 0;
	col_bind_t* bindcol = 0;
	Compute = GetCompute(dbproc, nrow, 1);
	if (!Compute)
		return 0;
	if (!Compute->altbinds || !Compute->altbinds[column])
		return 1;
	ColumnType = GetColumnType(dbproc, Compute->altcols[column]->token, Compute->altcols[column]->length);
	if (!dbproc->altrowdata)
		return 0;
	pvdata = dbproc->altrowdata[nrow - 1]->columnsdata;
	if (!pvdata)
		return 0;
	data = (BYTE*)pvdata[column]->data;
	len = pvdata[column]->len;
	bindcol = Compute->altbinds[column];
	if (!bindcol->conv_func)
		return 0;
	if (len && data)
	{
		length = bindcol->length;
		if (bindcol->indicator)
			*bindcol->indicator = 0;
		switch (bindcol->bind_type)
		{
		case 1:
			l1 = VarBindLength(data, len, 0x20u, ColumnType);
			if (((int(__cdecl*)(PDBPROCESS, int, BYTE*, int, int, void*, int))bindcol->conv_func)(
				dbproc,
				ColumnType,
				data,
				l1,
				SQLINT1,
				bindcol->buffer,
				length) != -1)
				goto LABEL_104;
			return 0;
		case 2:
			l1 = VarBindLength(data, len, 0x20u, ColumnType);
			if (((int(__cdecl*)(PDBPROCESS, int, BYTE*, int, int, void*, int))bindcol->conv_func)(
				dbproc,
				ColumnType,
				data,
				l1,
				SQLINT2,
				bindcol->buffer,
				length) != -1)
				goto LABEL_104;
			return 0;
		case 3:
			l1 = VarBindLength(data, len, 0x20u, ColumnType);
			if (((int(__cdecl*)(PDBPROCESS, int, BYTE*, int, int, void*, int))bindcol->conv_func)(
				dbproc,
				ColumnType,
				data,
				l1,
				SQLINT4,
				bindcol->buffer,
				length) != -1)
				goto LABEL_104;
			return 0;
		case 4:
			goto LABEL_23;
		case 5:
			l1 = ((int(__cdecl*)(PDBPROCESS, int, BYTE*, int, int, void*, int))bindcol->conv_func)(
				dbproc,
				ColumnType,
				data,
				len,
				SQLBINARY,
				bindcol->buffer,
				length);
			if (l1 == -1)
				return 0;
			PadString((char*)bindcol->buffer, l1, bindcol->bind_type, length, 0);
			goto LABEL_104;
		case 6:
			if (((int(__cdecl*)(PDBPROCESS, int, BYTE*, int, int, void*, int))bindcol->conv_func)(
				dbproc,
				ColumnType,
				data,
				len,
				SQLBIT,
				bindcol->buffer,
				length) != -1)
				goto LABEL_104;
			return 0;
		case 7:
			if (ColumnType == SQLCHAR || ColumnType == SQLTEXT || ColumnType == SQLVARCHAR)
			{
				if (ColumnType == SQLVARCHAR)
					cPad = 0;
				else
					cPad = ' ';
				L = len;
				for (p = &data[len - 1]; L > 0 && *p == cPad && p != data; --p)
					--L;
				len = L;
			}
			if (((int(__cdecl*)(PDBPROCESS, int, BYTE*, int, int, void*, int))bindcol->conv_func)(
				dbproc,
				ColumnType,
				data,
				len,
				SQLDATETIME,
				bindcol->buffer,
				length) != -1)
				goto LABEL_104;
			return 0;
		case 8:
			l1 = VarBindLength(data, len, 0x20u, ColumnType);
			if (((int(__cdecl*)(PDBPROCESS, int, BYTE*, int, int, void*, int))bindcol->conv_func)(
				dbproc,
				ColumnType,
				data,
				l1,
				SQLMONEY,
				bindcol->buffer,
				length) != -1)
				goto LABEL_104;
			return 0;
		case 9:
			l1 = VarBindLength(data, len, 0x20u, ColumnType);
			if (((int(__cdecl*)(PDBPROCESS, int, BYTE*, int, int, void*, int))bindcol->conv_func)(
				dbproc,
				ColumnType,
				data,
				l1,
				SQLFLT8,
				bindcol->buffer,
				length) != -1)
				goto LABEL_104;
			return 0;
		case 10:
		case 11:
			if (length == 1)
			{
				*(BYTE*)bindcol->buffer = 0;
				goto LABEL_104;
			}
			if (length > 0)
				--length;
		LABEL_23:
			l1 = ((int(__cdecl*)(PDBPROCESS, int, BYTE*, int, int, void*, int, int*))bindcol->conv_func)(
				dbproc,
				ColumnType,
				data,
				len,
				SQLCHAR,
				bindcol->buffer,
				length,
				bindcol->indicator);
			if (l1 == -1)
				return 0;
			PadString((char*)bindcol->buffer, l1, bindcol->bind_type, bindcol->length, 32);
			goto LABEL_104;
		case 12:
			length = VarBindLength(data, len, 0, ColumnType);
			if (length > 2)
			{
				if (length > 0)
					length -= 2;
				l1 = ((int(__cdecl*)(PDBPROCESS, int, BYTE*, int, int, void*, int, int*))bindcol->conv_func)(
					dbproc,
					ColumnType,
					data,
					length,
					SQLCHAR,
					(char*)bindcol->buffer + 2,
					length,
					bindcol->indicator);
			}
			else
			{
				l1 = ((int(__cdecl*)(PDBPROCESS, int, BYTE*, int, int, void*, int, int*))bindcol->conv_func)(
					dbproc,
					ColumnType,
					data,
					length,
					SQLCHAR,
					(char*)bindcol->buffer + 2,
					0,
					bindcol->indicator);
			}
			if (l1 == -1)
				return 0;
			*(WORD*)bindcol->buffer = l1;
			goto LABEL_104;
		case 13:
			length = VarBindLength(data, len, 0x20u, ColumnType);
			if ((unsigned int)length > 2)
			{
				if (length > 0)
					length -= 2;
				l1 = ((int(__cdecl*)(PDBPROCESS, int, BYTE*, int, int, void*, int))bindcol->conv_func)(
					dbproc,
					ColumnType,
					data,
					length,
					SQLBINARY,
					(char*)bindcol->buffer + 2,
					length);
			}
			else
			{
				l1 = ((int(__cdecl*)(PDBPROCESS, int, BYTE*, int, int, void*, int))bindcol->conv_func)(
					dbproc,
					ColumnType,
					data,
					length,
					SQLBINARY,
					(char*)bindcol->buffer + 2,
					0);
			}
			if (l1 == -1)
			{
				result = 0;
			}
			else
			{
				*(WORD*)bindcol->buffer = l1;
			LABEL_104:
				result = 1;
			}
			break;
		case 14:
			length = VarBindLength(data, len, 0x20u, ColumnType);
			if (((int(__cdecl*)(PDBPROCESS, int, BYTE*, int, int, void*, int))bindcol->conv_func)(
				dbproc,
				ColumnType,
				data,
				length,
				SQLFLT4,
				bindcol->buffer,
				length) != -1)
				goto LABEL_104;
			return 0;
		case 15:
			length = VarBindLength(data, len, 0x20u, ColumnType);
			if (((int(__cdecl*)(PDBPROCESS, int, BYTE*, int, int, void*, int))bindcol->conv_func)(
				dbproc,
				ColumnType,
				data,
				length,
				SQLMONEY4,
				bindcol->buffer,
				length) != -1)
				goto LABEL_104;
			return 0;
		case 16:
			if (ColumnType == SQLCHAR || ColumnType == SQLTEXT || ColumnType == SQLVARCHAR)
			{
				if (ColumnType == SQLVARCHAR)
					cPad = 0;
				else
					cPad = ' ';
				L = len;
				for (p = &data[len - 1]; L > 0 && *p == cPad && p != data; --p)
					--L;
				len = L;
			}
			if (((int(__cdecl*)(PDBPROCESS, int, BYTE*, int, int, void*, int))bindcol->conv_func)(
				dbproc,
				ColumnType,
				data,
				len,
				SQLDATETIM4,
				bindcol->buffer,
				length) != -1)
				goto LABEL_104;
			return 0;
		case 17:
		case 18:
			goto LABEL_79;
		case 19:
		case 20:
			buffer = (BYTE*)bindcol->buffer;
			buffer[0] = 0;
			buffer[1] = 0;
		LABEL_79:
			length = VarBindLength(data, len, 0x20u, ColumnType);
			if (((int(__cdecl*)(PDBPROCESS, int, BYTE*, int, int, void*, int))bindcol->conv_func)(
				dbproc,
				ColumnType,
				data,
				length,
				SQLNUMERIC,
				bindcol->buffer,
				length) != -1)
				goto LABEL_104;
			return 0;
		default:
			return 0;
		}
	}
	else
	{
		if (bindcol->indicator)
			*bindcol->indicator = -1;
		return DoNullBind(dbproc, bindcol->bind_type, bindcol->length, (char*)bindcol->buffer) != -1;
	}
	return result;
}

int __cdecl CheckTimeoutAndReturn(PDBPROCESS dbproc, int t)
{
	if (!t)
		return 0;
	if ((dbproc->opmask & 8) == 0)
		return t;
	dbproc->opmask &= ~8u;
	return 0;
}
int __stdcall NextRowIndex(PDBPROCESS dbproc)
{
	if ((dbproc->nextrowidx + 1) <= dbproc->nbufrow)
		return dbproc->nextrowidx + 1;
	else
		return 1;
}
int __stdcall RowDataInBuffer(PDBPROCESS dbproc)
{
	rowbuffer_t* r = 0; 
	int i = 0; 
	int row_ = 0; 

	if (dbproc->nbufrow <= 1u || !dbproc->columns_data)
		return 0;
	i = 0;
	row_ = dbproc->rowidx;
	while (i < dbproc->nbufrow)
	{
		if (row_ > dbproc->nbufrow)
			row_ -= dbproc->nbufrow;
		r = &dbproc->rowbuffer[row_ - 1];
		if ((r->nrow == -1 || r->nrow == 0) && r->columnsdata == dbproc->columns_data)
			return 1;
		++i;
		++row_;
	}
	return 0;
}
int __stdcall GetRowColumnData(PDBPROCESS dbproc, int row)
{
	int result = 0; 
	DBNUMERIC* numeric; 
	int Size, SiZ; 
	column_info_t** coldata = 0; 
	int len = 0; 
	blob_t* ptxtimg = 0; 
	int Err = 0; 
	int Buffer = 0;
	column_data_t** column_data = 0; 

	coldata = dbproc->columns_info;
	column_data = dbproc->columns_data;
	if (coldata[row]->coltype == SQLTEXT || coldata[row]->coltype == SQLIMAGE)
	{
		len = getbyte(dbproc, (BYTE*)&Err);
		if (!Err)
			return 0;
		ptxtimg = (blob_t*)AllocateHeapMemory(4, dbproc, 0x16u, 1);
		if (!ptxtimg)
			return FreeOnError(0, dbproc);
		column_data[row]->data = (BYTE*)ptxtimg;
		if (!len)
		{
			column_data[row]->len = 0;
			if (BindVar(dbproc, row))
				return 1;
			else
				return -1;
		}
		ptxtimg->size = len;
		ptxtimg->txptr = (BYTE*)AllocateHeapMemory(4, dbproc, len, 0);
		if (!ptxtimg->txptr)
			return FreeOnError(0, dbproc);
		if (dbproc->CommLayer->rbytes
			&& len <= dbproc->CommLayer->wbytes
			&& len <= dbproc->CommLayer->length - dbproc->CommLayer->rbytes)
		{
			memmove(ptxtimg->txptr, &dbproc->CommLayer->buffer0[dbproc->CommLayer->rbytes], len);
			dbproc->CommLayer->rbytes += len;
			dbproc->CommLayer->wbytes -= len;
			result = 1;
		}
		else
		{
			result = getbytes_internal(dbproc, (BYTE*)ptxtimg->txptr, len);
		}
		if (!result)
			return 0;
		if (dbproc->CommLayer->rbytes
			&& dbproc->CommLayer->wbytes >= 8u
			&& dbproc->CommLayer->length - dbproc->CommLayer->rbytes >= 8)
		{
			memmove(&ptxtimg->timestamp, &dbproc->CommLayer->buffer0[dbproc->CommLayer->rbytes], 8u);
			dbproc->CommLayer->rbytes += 8;
			dbproc->CommLayer->wbytes -= 8;
			result = 1;
		}
		else
		{
			result = getbytes_internal(dbproc, (BYTE*)&ptxtimg->timestamp, 8);
		}
		if (!result)
			return 0;
		if (!gettokenlen(dbproc, coldata[row]->coltype, (BYTE*)&Size))
			return 0;
		if (dbproc->textlimit_size && dbproc->textlimit_size < Size)
		{
			SiZ = Size;
			Size = dbproc->textlimit_size;
		}
		else
		{
			SiZ = Size;
		}
		column_data[row]->len = Size;
		ptxtimg->len = Size;
		if (!Size)
		{
			if (BindVar(dbproc, row))
				return 1;
			else
				return -1;
		}
		ptxtimg->data = (BYTE*)AllocateHeapMemory(4, dbproc, Size, 0);

		if (!ptxtimg->data)
			return FreeOnError(0, dbproc);
		if (column_data[row]->len == -1)
			return 1;
		if (dbproc->CommLayer->rbytes
			&& Size <= dbproc->CommLayer->wbytes
			&& Size <= dbproc->CommLayer->length - dbproc->CommLayer->rbytes)
		{
			memmove(ptxtimg->data, &dbproc->CommLayer->buffer0[dbproc->CommLayer->rbytes], Size);
			dbproc->CommLayer->rbytes += Size;
			dbproc->CommLayer->wbytes -= Size;
			result = 1;
		}
		else
		{
			result = getbytes_internal(dbproc, ptxtimg->data, Size);
		}
		if (!result)
			return 0;
		if (coldata[row]->coltype == SQLTEXT)
			dbWinConvFromServer(dbproc, (char*)ptxtimg->data, Size);
		if (Size < SiZ)
		{
			SiZ -= Size;
			while (1)
			{
				if (SiZ-- <= 0)
					break;
				if (dbproc->CommLayer->rbytes
					&& dbproc->CommLayer->wbytes
					&& dbproc->CommLayer->length - dbproc->CommLayer->rbytes >= 1)
				{
					memmove(&Buffer, &dbproc->CommLayer->buffer0[dbproc->CommLayer->rbytes], 1u);
					++dbproc->CommLayer->rbytes;
					--dbproc->CommLayer->wbytes;
					result = 1;
				}
				else
				{
					result = getbytes_internal(dbproc, (BYTE*)&Buffer, 1);
				}
				if (!result)
					return 0;
			}
		}
		if (BindVar(dbproc, row))
			return 1;
		else
			return -1;
	}
	else
	{
		if (!gettokenlen(dbproc, coldata[row]->coltype, (BYTE*)&Size))
			return 0;
		column_data[row]->len = Size;
		if (Size)
		{
			if (column_data[row]->len != -1)
			{
				if (coldata[row]->coltype == SQLNUMERIC || coldata[row]->coltype == SQLDECIMAL)
				{
					numeric = (DBNUMERIC*)AllocateHeapMemory(4, dbproc, 19u, 0);
					if (!numeric)
						return FreeOnError(0, dbproc);
					dbzero(numeric, 19u);
					numeric->precision = coldata[row]->precision;
					numeric->scale = coldata[row]->scale;
					if (dbproc->CommLayer->rbytes
						&& dbproc->CommLayer->wbytes
						&& dbproc->CommLayer->length - dbproc->CommLayer->rbytes >= 1)
					{
						memmove(&numeric->sign, &dbproc->CommLayer->buffer0[dbproc->CommLayer->rbytes], 1u);
						++dbproc->CommLayer->rbytes;
						--dbproc->CommLayer->wbytes;
						result = 1;
					}
					else
					{
						result = getbytes_internal(dbproc, &numeric->sign, 1);
					}
					if (!result)
						return 0;
					if (dbproc->CommLayer->rbytes
						&& column_data[row]->len - 1 <= dbproc->CommLayer->wbytes
						&& column_data[row]->len - 1 <= dbproc->CommLayer->length - dbproc->CommLayer->rbytes)
					{
						memmove(numeric->val, &dbproc->CommLayer->buffer0[dbproc->CommLayer->rbytes], column_data[row]->len - 1);
						dbproc->CommLayer->rbytes += column_data[row]->len - 1;
						dbproc->CommLayer->wbytes -= column_data[row]->len - 1;
						result = 1;
					}
					else
					{
						result = getbytes_internal(dbproc, numeric->val, column_data[row]->len - 1);
					}
					if (!result)
						return 0;
					column_data[row]->data = (BYTE*)numeric;
				}
				else
				{
					column_data[row]->data = (BYTE*)AllocateHeapMemory(4, dbproc, column_data[row]->len, 0);

					if (!column_data[row]->data)
						return FreeOnError(0, dbproc);
					if (dbproc->CommLayer->rbytes
						&& column_data[row]->len <= dbproc->CommLayer->wbytes
						&& column_data[row]->len <= dbproc->CommLayer->length - dbproc->CommLayer->rbytes)
					{
						memmove(column_data[row]->data, &dbproc->CommLayer->buffer0[dbproc->CommLayer->rbytes], column_data[row]->len);
						dbproc->CommLayer->rbytes += LOWORD(column_data[row]->len);
						dbproc->CommLayer->wbytes -= LOWORD(column_data[row]->len);
						result = 1;
					}
					else
					{
						result = getbytes_internal(dbproc, (BYTE*)column_data[row]->data, column_data[row]->len);
					}
					if (!result)
						return 0;
				}
				if (coldata[row]->coltype == SQLCHAR || coldata[row]->coltype == SQLVARCHAR)
					dbWinConvFromServer(dbproc, (char*)column_data[row]->data, LOWORD(column_data[row]->len));
				switch (coldata[row]->coltype)
				{
				case SQLINTN:
				case SQLDECIMAL:
				case SQLNUMERIC:
				case SQLFLTN:
				case SQLMONEYN:
				case SQLDATETIMN:
					column_data[row]->len = coldata[row]->collen;
					break;
				default:
					break;
				}
				if (dbproc->binds && dbproc->binds[row] && row < dbproc->numcols && !BindVar(dbproc, row))
					return -1;
			}
			return 1;
		}
		if (BindVar(dbproc, row))
			return 1;
		else
			return -1;
	}
}
int __stdcall AltDataInBuffer(PDBPROCESS dbproc)
{
	rowbuffer_t* rBuf = 0; 
	int i = 0;
	int row_ = 0; 

	if (dbproc->nbufrow <= 1u || !dbproc->altrowdata)
		return 0;
	i = 0;
	row_ = dbproc->rowidx;
	while (i < dbproc->nbufrow)
	{
		if (row_ > dbproc->nbufrow)
			row_ -= dbproc->nbufrow;
		rBuf = &dbproc->rowbuffer[row_ - 1];
		if (rBuf->nrow != -1 && rBuf->nrow && rBuf->altcoldata == dbproc->altrowdata)
			return 1;
		++i;
		++row_;
	}
	return 0;
}
int __stdcall AllocateAltData(PDBPROCESS dbproc)
{
	int naltrow = 0; 
	alt_column_data_t** altr = 0; 
	altcol_link_t* altcolinfo = 0; 
	__int16 i = 0; 

	naltrow = dbproc->n_compute_row;
	altr = (alt_column_data_t**)AllocateHeapMemory(4, dbproc, 4 * naltrow, 1);
	if (!altr)
		return FreeOnError(0, dbproc);
	altcolinfo = dbproc->altcolinfo;
	for (i = 0; i < naltrow; ++i)
	{
		altr[i] = (alt_column_data_t*)AllocateHeapMemory(4, dbproc, 8u, 1);
		if (!altr[i])
			return FreeOnError(0, dbproc);
		altr[i]->columnsdata = (column_data_t**)AllocateHeapMemory(4, dbproc, 4 * altcolinfo->n_alts, 1);
		if (!altr[i]->columnsdata)
			return FreeOnError(0, dbproc);
		altr[i]->nrow = i + 1;
		altr[i]->ncol = altcolinfo->n_alts;
		altcolinfo = altcolinfo->next;
	}
	dbproc->altrowdata = altr;
	return 1;
}

int __stdcall GetAltRowColumnData(PDBPROCESS dbproc, int column, altcol_link_t* acol, alt_column_data_t* arow)
{

	int result = 0; 
	DBNUMERIC Src;
	column_data_t** column_data = 0;
	altcol_t** altcols = 0; 

	altcols = acol->altcols;
	arow->columnsdata[column] = (column_data_t*)AllocateHeapMemory(4, dbproc, 8u, 1);
	if (!arow->columnsdata[column])
		return FreeOnError(0, dbproc);
	column_data = arow->columnsdata;
	arow->ncol = acol->n_alts;
	arow->nrow = acol->nrow;
	if (!gettokenlen(dbproc, altcols[column]->token, (BYTE*)column_data[column]))
		return 0;
	if (column_data[column]->len)
	{
		if (altcols[column]->token == SQLNUMERIC || altcols[column]->token == SQLDECIMAL)
		{
			dbzero(&Src, 0x13u);
			column_data[column]->data = (BYTE*)AllocateHeapMemory(4, dbproc, 19u, 0);

			if (!column_data[column]->data)
				return FreeOnError(0, dbproc);
			if (dbproc->CommLayer->rbytes
				&& (signed int)column_data[column]->len <= dbproc->CommLayer->wbytes
				&& (signed int)column_data[column]->len <= dbproc->CommLayer->length - dbproc->CommLayer->rbytes)
			{
				memmove(&Src.sign, &dbproc->CommLayer->buffer0[dbproc->CommLayer->rbytes], column_data[column]->len);
				dbproc->CommLayer->rbytes += LOWORD(column_data[column]->len);
				dbproc->CommLayer->wbytes -= LOWORD(column_data[column]->len);
				result = 1;
			}
			else
			{
				result = getbytes_internal(dbproc, (BYTE*)&Src.sign, column_data[column]->len);
			}
			if (!result)
				return 0;
				Src.precision = altcols[column]->precision;
				Src.scale = altcols[column]->scale;
			dbmove(&Src, column_data[column]->data, 19u);
		}
		else
		{
			column_data[column]->data = (BYTE*)AllocateHeapMemory(4, dbproc, column_data[column]->len, 0);
			if (!column_data[column]->data)
				return FreeOnError(0, dbproc);
			if (dbproc->CommLayer->rbytes
				&& column_data[column]->len <= dbproc->CommLayer->wbytes
				&& column_data[column]->len <= dbproc->CommLayer->length - dbproc->CommLayer->rbytes)
			{
				memmove(column_data[column]->data, &dbproc->CommLayer->buffer0[dbproc->CommLayer->rbytes], column_data[column]->len);
				dbproc->CommLayer->rbytes += LOWORD(column_data[column]->len);
				dbproc->CommLayer->wbytes -= LOWORD(column_data[column]->len);
				result = 1;
			}
			else
			{
				result = getbytes_internal(dbproc, (BYTE*)column_data[column]->data, column_data[column]->len);
			}
			if (!result)
				return 0;
		}
	}
	if (BindAVar(dbproc, arow->nrow, column))
		return 1;
	else
		return -1;
}

int __cdecl GetSQLServerVersion(PDBPROCESS dbproc)
{
	int row = 0; 
	int result = 0; 
	int bSucc = 0; 
	int Count = 0; 
	char* Source = 0; 
	char Destination[256] = { 0 };
	int bSucc1 = 0;

	if (dbproc->ServerMajor >= 6u)
		return 1;
	bSucc1 = 0;
	dbprocmsghandle_super(dbproc, 0, 2);
	dbprocerrhandle_super(dbproc, 0, 2);
	bSucc = 0;
	if (dbcmd(dbproc, "select @@microsoftversion"))
	{
		if (dbsqlexec(dbproc))
		{
			while (1)
			{
				result = dbresults(dbproc);
				if (result == SUCCEED_ABORT || result == FAIL)
					break;
				do
					row = dbnextrow(dbproc);
				while (row != NO_MORE_ROWS && row);
			}
			dbproc->ServerMajor = 4;
			dbproc->ServerMinor = 21;
			dbproc->ServerRevision = 0;
			dbproc->bServerType = 1;
			bSucc1 = 1;
		}
		else if (dbcmd(dbproc, VersionString)) // "select @@version"
		{
			if (dbsqlexec(dbproc))
			{
				if (dbresults(dbproc) == SUCCEED)
				{
					bSucc = 1;
					if (dbnextrow(dbproc) == MORE_ROWS)
					{
						Source = (char*)dbdata(dbproc, 1);
						if (Source)
						{
							Count = dbdatlen(dbproc, 1);
							if (Count >= 1 && Count <= 255)
							{
								strncpy(Destination, Source, Count);
								Destination[Count] = 0;
								if (DBCS_STRSTR(Destination, "SQL Server for Windows NT 4.20"))
								{
									dbproc->ServerMajor = 4;
									dbproc->ServerMinor = 2;
									dbproc->ServerRevision = 0;
									dbproc->bServerType = 1;
									bSucc1 = 1;
								}
							}
						}
					}
				}
			}
		}
	}
	dbprocmsghandle_super(dbproc, 0, 4);
	dbprocerrhandle_super(dbproc, 0, 4);
	if (bSucc)
		dbcanquery(dbproc);
	return bSucc1;
}
int __stdcall OpenAnotherProc()
{
	int i = 0; 

	EnterCriticalSection(&DbProcSem);
	if (DbProcArray)
	{
		for (i = 0; i < DbMaxProcs; ++i)
		{
			if (!DbProcArray[i])
			{
				LeaveCriticalSection(&DbProcSem);
				return 1;
			}
		}
		LeaveCriticalSection(&DbProcSem);
		return 0;
	}
	else
	{
		LeaveCriticalSection(&DbProcSem);
		return 1;
	}
}

int __stdcall AddDBProc(PDBPROCESS dbproc)
{
	int i = 0;

	EnterCriticalSection(&DbProcSem);
	if (DbProcArray || (DbProcArray = (PDBPROCESS*)AllocateHeapMemory(4, 0, 4 * DbMaxProcs, 1)) != 0)
	{
		for (i = 0; i < DbMaxProcs; ++i)
		{
			if (!DbProcArray[i])
			{
				DbProcArray[i] = dbproc;
				LeaveCriticalSection(&DbProcSem);
				return 1;
			}
		}
		LeaveCriticalSection(&DbProcSem);
		GeneralError(dbproc, 10029);
		return 0;
	}
	else
	{
		LeaveCriticalSection(&DbProcSem);
		return FreeOnError(0, dbproc);
	}
}
int __stdcall DumpDbProc(PDBPROCESS dbproc, LPVOID lpBuffer)
{

	tidyproc(dbproc);
	if (dbproc->b_security)
	{
		TermSession(dbproc);
		dbproc->b_security = 0;
	}

	if (dbproc->conn_object)
		DbCloseConnection(dbproc);
	if (dbproc->CommLayer)
	{
		if (dbproc->CommLayer->buffer_0)
			FreeMemory(0, dbproc->CommLayer->buffer_0);
		if (dbproc->CommLayer->buffer_1)
			FreeMemory(0, dbproc->CommLayer->buffer_1);
		FreeMemory(0, dbproc->CommLayer);
	}
	if (dbproc->conn_object)
		FreeMemory(0, (LPVOID)dbproc->conn_object);
	if (dbproc->hHeap)
		HeapDestroy(dbproc->hHeap);
	FreeMemory(0, dbproc);
	if (lpBuffer)
		FreeMemory(0, lpBuffer);
	return 0;
}
int __stdcall InitNulls(PDBPROCESS dbproc)
{
	null_value_t* pnull = 0;

	pnull = (null_value_t*)AllocateHeapMemory(4, dbproc, 0x70u, 1);
	if (!pnull)
		return 0;
	pnull->p_nstring = (char*)AllocateHeapMemory(4, dbproc, 1u, 1);
	if (!pnull->p_nstring)
		return 0;
	pnull->p_ntbstring = (char*)AllocateHeapMemory(4, dbproc, 1u, 1);
	if (!pnull->p_ntbstring)
		return 0;
	pnull->p_nvarybin = (DBVARYBIN*)AllocateHeapMemory(4, dbproc, 3u, 1);
	if (!pnull->p_nvarybin)
		return 0;
	pnull->p_nvarychar = (DBVARYCHAR*)AllocateHeapMemory(4, dbproc, 3u, 1);
	if (!pnull->p_nvarychar)
		return 0;
	dbproc->nulls = pnull;
	return 1;
}
const char* sdidebug_opt[3] = { "off" ,"on" ,"context" };
int __cdecl sp_sdidebug(
	PDBPROCESS dbproc,
	int opt,
	char* dbgOn,
	int ProcessId,
	int ThreadId,
	char* dbgCtx,
	size_t Count,
	void* pdata)
{
	int result = 0; 

	result = 0;
	if (dbrpcinit(dbproc, "sp_sdidebug", 0)
		&& dbrpcparam(dbproc, 0, 0, SQLVARCHAR, -1, strlen(sdidebug_opt[opt]), (LPCBYTE)sdidebug_opt[opt])
		&& (opt != 1
			|| dbrpcparam(dbproc, 0, 0, SQLVARCHAR, -1, strlen(dbgCtx), (LPCBYTE)dbgCtx)
		&& dbrpcparam(dbproc, 0, 0, SQLVARCHAR, -1, strlen(dbgOn), (LPCBYTE)dbgOn))
		&& (opt == 0 || dbrpcparam(dbproc, 0, 0, SQLINT4, -1, 0xFFFFFFFF, (LPCBYTE)&ProcessId)
			&& dbrpcparam(dbproc, 0, 0, SQLINT4, -1, 0xFFFFFFFF, (LPCBYTE)&ThreadId))
		&& (opt != 1 || dbrpcparam(dbproc, 0, 0, SQLVARBINARY, -1, Count, (LPCBYTE)pdata))) // SQLVARBINARY
	{
		if (dbrpcexec(dbproc))
		{
			result = 1;
			if (dbsqlok(dbproc))
			{
				if (dbresults(dbproc) || dbnextrow(dbproc))
					return 1;
			}
		}
	}
	if (result)
		dbcancel(dbproc);
	return 0;
}
int __cdecl CheckSQLDebug(PDBPROCESS dbproc)
{
	int CurrentThreadId = 0; 
	int CurrentProcessId = 0; 
	int result = 0; 

	result = 1;
	if (debug_no_entry
		|| (dbproc->bServerType != 1 || dbproc->ServerMajor < 6u || dbproc->ServerMinor < 5u)
		&& dbproc->ServerMajor <= 6u)
	{
		return 1;
	}
	debug_no_entry = 1;
	CurrentProcessId = GetCurrentProcessId();
	if ((dbproc->ret_status & 0x200) == 0 && *((_DWORD*)pMemMap + 1) == 1)
	{
		result = sp_sdidebug(
			dbproc,
			1, // On
			(char*)pMemMap + 8, // dbgOn
			CurrentProcessId,
			*(_DWORD*)pMemMap, // ThreadId
			(char*)pMemMap + 40, // dbgCtx
			*((_DWORD*)pMemMap + 14), // Count
			(char*)pMemMap + 60); // pdata
		if (result == 1)
		{
			dbproc->ret_status |= 0x200;
			dbproc->ThreadId = 0;
		}
	}
	if ((dbproc->ret_status & 0x200) != 0)
	{
		if (*((_DWORD*)pMemMap + 1))
		{
			if (dbproc->ThreadId != GetCurrentThreadId())
			{
				CurrentThreadId = GetCurrentThreadId();
				result = sp_sdidebug(dbproc, 2, 0, CurrentProcessId, CurrentThreadId, 0, 0, 0); // context
				if (result == 1)
					dbproc->ThreadId = GetCurrentThreadId();
			}
		}
		else
		{
			result = sp_sdidebug(dbproc, 0, 0, 0, 0, 0, 0, 0); // off
			dbproc->ret_status &= ~0x200u;
		}
	}
	debug_no_entry = 0;
	return result;
}
int __cdecl CheckSQLDebugOnConnect(PDBPROCESS dbproc)
{
	DWORD Value = 0; 
	char Buffer[12] = { 0 };
	char Name[32] = { 0 };
	int result = 0; 
	HANDLE hFileMappingObject = 0;

	result = 1;
	Value = GetCurrentProcessId();
	_ultoa(Value, Buffer, 16);
	strcpy(Name, "DBSSDebug");
	strcat(Name, Buffer);
	hFileMappingObject = OpenFileMappingA(FILE_MAP_READ| FILE_MAP_WRITE, 0, Name);
	if (hFileMappingObject)
	{
		pMemMap = MapViewOfFile(hFileMappingObject, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, 0);
		return CheckSQLDebug(dbproc);
	}
	return result;
}

int __cdecl UpdateFallback(PDBPROCESS dbproc)
{
	HKEY hKey = 0; 
	DWORD dwDisposition = 0; 
	HKEY phkResult = 0; 
	//char Buffer[52];
	char* p = 0; 
	int result = 0; 
	char szBackupServer[32] = { 0 };
	int result1 = 0;
	char* Source = 0; 
	size_t Count = 0; 

	if (dbproc->ServerMajor < 6u)
		return 1;
	result1 = 0;
	szBackupServer[0] = 0;
	dbprocmsghandle_super(dbproc, 0, 2);
	dbprocerrhandle_super(dbproc, 0, 2);
	result = 0;
	if (dbrpcinit(dbproc, "sp_fallback_MS_sel_fb_svr", 0))
	{
		if (dbrpcparam(dbproc, (char*)"@pFallbackSvrName", 1, SQLCHAR, 31, 0, 0))
		{
			result = 1;
			if (dbrpcsend(dbproc))
			{
				if (!dbretstatus(dbproc))
				{
					if (dbresults(dbproc))
					{
						Count = dbretlen(dbproc, 1);
						if ((int)Count >= 1)
						{
							Source = (char*)dbretdata(dbproc, 1);
							if (Source)
							{
								strncpy((char*)szBackupServer, Source, Count);
								szBackupServer[Count] = 0;
								for (p = (char*)&szBackupServer[Count - 1]; p >= (char*)szBackupServer && *p == ' '; --p)
									*p = 0;
								result = 0;
								if (dbproc->backupserver )
								{
									phkResult = 0;
									hKey = 0;
									//strcpy(Buffer, "SOFTWARE\\Microsoft\\MSSQLServer\\Client\\BackupServer");
									if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\MSSQLServer\\Client\\BackupServer", 0, 0x20006u, &phkResult)
										&& RegCreateKeyExA(
											HKEY_LOCAL_MACHINE,
											"SOFTWARE\\Microsoft\\MSSQLServer\\Client\\BackupServer",
											0,
											0,
											0,
											0xF003Fu,
											0,
											&phkResult,
											&dwDisposition))
									{
										goto LABEL_25;
									}
									if (RegOpenKeyExA(phkResult, dbproc->backupserver, 0, 0x20006u, &hKey)
										&& RegCreateKeyExA(phkResult, dbproc->backupserver, 0, 0, 0, 0xF003Fu, 0, &hKey, &dwDisposition))
									{
										RegCloseKey(phkResult);
										goto LABEL_25;
									}
									if (RegSetValueExA(hKey, "BackupServer", 0, 1u, (const BYTE*)szBackupServer, strlen((const char*)szBackupServer) + 1))
									{
										RegCloseKey(hKey);
										RegCloseKey(phkResult);
										goto LABEL_25;
									}
									RegCloseKey(hKey);
									RegCloseKey(phkResult);
								}
								result1 = 1;
							}
						}
					}
				}
			}
		}
	}
LABEL_25:
	dbprocmsghandle_super(dbproc, 0, 4);
	dbprocerrhandle_super(dbproc, 0, 4);
	if (result)
		dbcanquery(dbproc);
	return result1;
}

int __stdcall GetAnsiOem()
{
	char Data[40] = { 0 };
	DWORD cbData = 0;
	HKEY phkResult = 0; 

	phkResult = 0;
	cbData = 40;
	if (!RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\MSSQLServer\\Client\\DB-Lib", 0, 0x20019u, &phkResult))
	{
		if (RegQueryValueExA(phkResult, szAutoAnsiToOem, 0, 0, (LPBYTE)Data, &cbData))
			Data[0] = 0;
		else
			Data[cbData] = 0;
		RegCloseKey(phkResult);
	}
	if (!_strnicmp(Data, dbon + 1, 2u)) // " on "
		return 1;
	else
		return 2;
}
int __cdecl GetStringEqualToken(char* Str1, const char* Str2, char* pToken, unsigned __int16 length)
{
	int result = 0; 
	int typ = 0; 
	int k = 0; 
	char* pStr = 0; 
	char* p = 0; 
	char* p1 = 0;

	if (!Str1 || !Str2 || !pToken)
		return 0;
	pStr = DBCS_STRSTR(Str1, Str2);
	if (!pStr)
		return 0;
	for (p = &pStr[strlen(Str2)]; *p; ++p)
	{
		if (!(__mb_cur_max <= 1 ? _pctype[*p] & 8 : _isctype(*p, 8)))
			break;
	}
	if (!*p)
		return 0;
	if (*p != '=')
		return 0;
	if (!*p)
		return 0;
	for (p1 = p + 1; *p1; ++p1)
	{
		if (!(__mb_cur_max <= 1 ? _pctype[(char)*p1] & 8 : _isctype((char)*p1, 8)))
			break;
	}
	if (!*p1)
		return 0;
	for (k = 0; ; ++k)
	{
		if (!*p1)
			break;
		if (__mb_cur_max <= 1)
		{
			typ = _pctype[*p1] & 8;
		}
		else
		{
			typ = _isctype((char)*p1, 8);

		}
		if (typ)
			break;
		result = length;
		if (k >= length)
			break;
		*pToken++ = *p1++;
	}
	*pToken = 0;
	return result;
}
int __cdecl IsServerAnsi(PDBPROCESS dbproc)
{
	int exe_succ = 0; 
	int Count = 0; 
	char* Source = 0; 
	char Str1[52] = { 0 };
	char Destination[256] = { 0 };
	int result = 0; 

	result = 0;
	dbprocmsghandle_super(dbproc, 0, 2);
	dbprocerrhandle_super(dbproc, 0, 2);
	exe_succ = 0;
	if (dbcmd(dbproc, getansiid))
	{
		if (dbsqlexec(dbproc))
		{
			exe_succ = 1;
			if (dbresults(dbproc) == SUCCEED && dbnextrow(dbproc) == MORE_ROWS)
			{
				Source = (char*)dbdata(dbproc, 3);
				if (Source)
				{
					Count = dbdatlen(dbproc, 3);
					if (Count >= 1 && Count <= 255)
					{
						strncpy(Destination, Source, Count);
						Destination[Count] = 0;
						if (GetStringEqualToken(Destination, "charset", Str1, 50))
						{
							if (!strcmp("iso_1", Str1) || DBCS_STRSTR(Str1, "cp125"))
								result = 1;
						}
					}
				}
			}
		}
	}
	dbprocmsghandle_super(dbproc, 0, 4);
	dbprocerrhandle_super(dbproc, 0, 4);
	if (exe_succ)
		dbcanquery(dbproc);
	return result;
}

retval_t* __stdcall ReturnRequestedRetval(PDBPROCESS dbproc, int length)
{
	int C = 0; 
	int i = 0;

	C = 0;
	for (i = 0; i < dbproc->nretval; ++i)
	{
		if (dbproc->retvals[i]->Status)
			++C;
		if (C == length)
			return dbproc->retvals[i];
	}
	return 0;
}
int __stdcall OptionInit(PDBPROCESS dbproc)
{
	int index = 0; 
	int i,j = 0;
	int bSucc = 0;
	const char* Source; 
	int result = 0; 

	index = 0;
	Source = 0;
	bSucc = 0;
	for (i = 0; i < 19; ++i)
	{
		if ((OptionDict[i].optmask & 4) != 0)
		{
			if ((OptionDict[i].optmask & 2) != 0)
			{
				index = OptionDict[i].index;
				Source = 0;
			}
			else if (i == 3)
			{
				if ((OptionDict[3].option & 1) != 0)
				{
					index = OptionDict[3].index;
					Source = "time";
				}
				if ((OptionDict[3].option & 2) != 0)
				{
					index = OptionDict[3].index;
					Source = "io";
				}
			}
			else if (i == 1)
			{
				for (j = 0; j < 9; ++j)
				{
					if (((1 << j) & OptionDict[1].option) != 0)
					{
						index = OptionDict[1].index;
						Source = Offsets[j];
						break;
					}
				}
			}
			else
			{
				index = i;
				Source = (char*)OptionDict[OptionDict[i].index].optname;
			}
			dbsetopt(dbproc, index, Source);
			switch (index)
			{
			case 1:
			case 2:
			case 3:
			case 5:
			case 6:
			case 7:
			case 9:
			case 10:
			case 11:
			case 12:
			case 13:
			case 18:
				bSucc = 1;
				break;
			default:
				continue;
			}
		}
	}
	if (bSucc)
	{
		if (!dbsqlexec(dbproc))
			return 0;
		while (1)
		{
			result = dbresults(dbproc);
			if (result == NO_MORE_RESULTS)
				break;
			if (result == FAIL)
				return 0;
			while (dbnextrow(dbproc) != NO_MORE_ROWS)
				;
		}
		dbfreebuf(dbproc);
	}
	return 1;
}
int __stdcall pagedone(PDBPROCESS dbproc)
{
	int result = 0;
	int bSucc = 0;
	int bytbuf[2] = { 0 };
	char buffer[4] = { 0 };

	bSucc = 1;
	if (!gettokenlen(dbproc, dbproc->token, (BYTE*)buffer))
		return 0;
	if (dbproc->CommLayer->rbytes
		&& dbproc->CommLayer->wbytes >= 8u
		&& dbproc->CommLayer->length - dbproc->CommLayer->rbytes >= 8)
	{
		memmove(bytbuf, &dbproc->CommLayer->buffer0[dbproc->CommLayer->rbytes], 8u);
		dbproc->CommLayer->rbytes += 8;
		dbproc->CommLayer->wbytes -= 8;
		result = 1;
	}
	else
	{
		result = getbytes_internal(dbproc, (BYTE*)bytbuf, 8);
	}
	if (!result)
		return 0;
	if ((bytbuf[0] & 8) != 0 || (bytbuf[0] & 0x10) != 0)
	{
		dbproc->DoneRowCount = bytbuf[1];
		dbproc->opmask |= 1u;
	}
	else
	{
		dbproc->opmask &= ~1u;
	}
	if ((bytbuf[0] & 2) != 0)
	{
		// "General SQL Server error: Check messages from the SQL Server."
		GeneralError(dbproc, SQLESMSG);
		bSucc = 0;
	}
	if ((bytbuf[0] & 1) == 0)
	{
		if ((dbproc->cmd_flag & 2) != 0)
		{
			dbproc->cmd_flag |= 8u;
			dbproc->severity_level = 0;
		}
		else
		{
			if (dbproc->severity_level != 3)
			{
				dbproc->severity_level = 2;
				dbproc->cmd_flag |= 0x40u;
			}
			dbproc->cmd_flag ^= 8u;
			dbproc->cmd_flag |= 4u;
		}
	}
	if ((bytbuf[0] & 0x20) != 0 && (bytbuf[0] & 1) == 0)
	{
		dbproc->cmd_flag ^= 2u;
		if ((dbproc->cmd_flag & 8) != 0)
		{
			dbproc->cmd_flag ^= 8u;
			if (dbproc->severity_level != 3)
			{
				dbproc->severity_level = 2;
				dbproc->cmd_flag |= 0x40u;
			}
			dbproc->cmd_flag |= 4u;
		}
		return 1;
	}
	if (dbproc->token != SQLDONE)
		return 1;
	if (!bSucc)
		return 0;
	dbproc->token = 0;
	return 1;
}
int __stdcall pageerror(PDBPROCESS dbproc)
{
	int result = 0;
	BYTE token = 0;
	int bSucc = 0;
	LPVOID lpMem = 0;
	int Size = 0;
	int rBuf = 0;

	bSucc = 1;
	rBuf = 1;
	lpMem = AllocateHeapMemory(4, dbproc, 0x201u, 1);
	if (!lpMem)
		return FreeOnError(0, dbproc);
	while (dbproc->token == SQLINFO || dbproc->token == SQLERROR)
	{
		if (!gettokenlen(dbproc, dbproc->token, (BYTE*)&Size))
			return 0;
		token = dbproc->token;
		if (token == SQLERROR)
		{
			dbproc->severity_level = EXNONFATAL;
			bSucc = 0;
		}
		else if (token == SQLINFO)
		{
			if (dbproc->CommLayer->rbytes
				&& Size <= dbproc->CommLayer->wbytes
				&& Size <= dbproc->CommLayer->length - dbproc->CommLayer->rbytes)
			{
				memmove(lpMem, &dbproc->CommLayer->buffer0[dbproc->CommLayer->rbytes], Size);
				dbproc->CommLayer->rbytes += Size;
				dbproc->CommLayer->wbytes -= Size;
				result = 1;
			}
			else
			{
				result = getbytes_internal(dbproc, (BYTE*)lpMem, Size);
			}
			if (!result)
			{
				FreeOnError(lpMem, dbproc);
				return 0;
			}
			PrintMessage(dbproc, (char*)lpMem, Size);
		}
		dbproc->token = getbyte(dbproc, (BYTE*)&rBuf);
	}
	FreeMemory(dbproc, lpMem);
	return bSucc && rBuf;
}

int __stdcall dbtabnum(PDBPROCESS dbproc, const char* tab_name)
{
	int i = 0;
	char** tabnames = 0;

	tabnames = dbproc->tabnames;
	if (tab_name)
	{
		for (i = 0; i < dbproc->ntab; ++i)
		{
			if (tabnames[i] && !strcmp(tabnames[i], tab_name))
				return i + 1;
		}
	}
	return -1;
}
int __stdcall dbkeytype(PDBPROCESS dbproc, int ntab, int column)
{
	int i = 0;
	int c = 0;
	column_info_t** coldata = 0;

	c = 0;
	coldata = dbproc->columns_info;
	for (i = 0; i < dbproc->ncols; ++i)
	{
		if (coldata[i]->ntab == ntab && (coldata[i]->type & 8) != 0)
			++c;
		if (column == c)
			break;
	}
	if (column == c)
		return GetColumnType(dbproc, coldata[i]->coltype, coldata[i]->collen);
	else
		return -1;
}
int __stdcall FindTimeStampIndex(PDBPROCESS dbproc)
{
	retval_t** retvals = 0;
	int i = 0;

	retvals = dbproc->retvals;
	if (retvals)
	{
		for (i = 0; i < dbproc->nretval; ++i)
		{
			if (retvals[i] && retvals[i]->name && !strcmp((const char*)retvals[i]->name, "ts"))
				return i;
		}
	}
	return -1;
}
int __stdcall IsTimeStamp(BYTE* lpBuf)
{
	int i = 0;

	for (i = 0; i < 8; ++i)
	{
		if (*lpBuf++)
			return 1;
	}
	return 0;
}
int __cdecl GetFullName(PDBPROCESS dbproc, char* Destination, char* Src, int Size)
{
	int result = 0; 
	size_t Count = 0; 
	char* p0, * p1;


	if (dbisopt(dbproc, 18, 0)) // quoted_identifier
	{
		Count = 31 * Size - 1;
		if (strlen(Src) <= Count)
		{
			p0 = Src;
			*Destination = 0;
			do
			{
				p1 = DBCS_STRSTR(p0, ".");
				if (p1)
				{
					if (p1 != p0)
					{
						strcat(Destination, "\"");
						strncat(Destination, p0, p1 - p0);
						strcat(Destination, "\"");
					}
					strcat(Destination, ".");
					result = (int)(p1 + 1);
					p0 = p1 + 1;
				}
				else
				{
					strcat(Destination, "\"");
					strcat(Destination, p0);
					result = 0;
					strcat(Destination, "\"");
				}
			} while (p1);
		}
		else
		{
			strncpy(Destination, Src, Count);
			Destination[Count] = 0;
		}
	}
	else
	{
		result = strlen(Src) + 1;
		qmemcpy(Destination, Src, (unsigned int)result);
	}
	return result;
}

/*
*  START EXPORT API
*/
/*
* alt data
*/
LPCBYTE __cdecl dbadata(PDBPROCESS dbproc, int computeid, int column)
{
	column_data_t* arow;

	if (!CheckAltColumn(dbproc, computeid, column))
		return 0;
	arow = GetAltDataPointer(dbproc, computeid - 1, column - 1);
	if (arow)
		return arow->data;
	else
		return 0;
}

DBINT __cdecl dbadlen(PDBPROCESS dbproc, int computeid, int column)
{
	column_data_t* adata = 0;

	if (!CheckAltColumn(dbproc, computeid, column))
		return DBNOERR;
	adata = GetAltDataPointer(dbproc, computeid - 1, column - 1);
	if (!adata)
		return DBNOERR;
	if (adata->len > 0 && (dbalttype(dbproc, computeid, column) == SQLNUMERIC || dbalttype(dbproc, computeid, column) == SQLDECIMAL))
		return 19;
	return adata->len;
}


int __cdecl dbaltbind(PDBPROCESS dbproc, int computeid, int column, int vartype, int varlen, LPCBYTE varaddr)
{
	int result = 0;
	BOOL flag = 0;
	altcol_link_t* acol = 0;
	col_bind_t* p_bind = 0;
	int i = 0;
	col_bind_t** bind_conv = 0;

	int ColumnType = 0;
	void* Conv_ = 0;
	void* conv1 = 0;
	acol = CheckAltColumn(dbproc, computeid, column);
	if (!acol)
		return 0;
	i = column - 1;
	ColumnType = GetColumnType(dbproc, acol->altcols[column - 1]->token, acol->altcols[column - 1]->length);
	if (!acol->altbinds)
	{
		acol->altbinds = (col_bind_t**)AllocateHeapMemory(4, dbproc, 4 * acol->n_alts, 1);
		if (!acol->altbinds)
			return FreeOnError(0, dbproc);
	}
	dbproc->isavail = 0;
	if (acol->altbinds[i])
	{
		FreeMemory(dbproc, acol->altbinds[i]);
		acol->altbinds[i] = 0;
		if (!varaddr)
			return 1;
	}
	if (varaddr)
	{
		switch (vartype)
		{
		case 1:
			conv1 = ConvertToInt;
			flag = dbwillconvert(ColumnType, SQLINT1);
			break;
		case 2:
			conv1 = ConvertToInt;
			flag = dbwillconvert(ColumnType, SQLINT2);
			break;
		case 3:
			conv1 = ConvertToLong;
			flag = dbwillconvert(ColumnType, SQLINT4);
			break;
		case 4:
		case 10:
		case 11:
		case 12:
			Conv_ = ConvertToChar2;
			flag = dbwillconvert(ColumnType, SQLCHAR);
			break;
		case 5:
		case 13:
			conv1 = ConvertToBinary;
			flag = dbwillconvert(ColumnType, SQLBINARY);
			break;
		case 6:
			conv1 = ConvertToBit;
			flag = dbwillconvert(ColumnType, SQLBIT);
			break;
		case 7:
			conv1 = ConvertToDateTime;
			flag = dbwillconvert(ColumnType, SQLDATETIME);
			break;
		case 8:
			conv1 = ConvertToMoney;
			flag = dbwillconvert(ColumnType, SQLMONEY);
			break;
		case 9:
			conv1 = ConvertToFloat;
			flag = dbwillconvert(ColumnType, SQLFLT8);
			break;
		case 14:
			conv1 = ConvertToReal;
			flag = dbwillconvert(ColumnType, SQLFLT4);
			break;
		case 15:
			conv1 = ConvertToSmallMoney;
			flag = dbwillconvert(ColumnType, SQLMONEY4);
			break;
		case 16:
			conv1 = ConvertToSmallDate;
			flag = dbwillconvert(ColumnType, SQLDATETIM4);
			break;
		case 17:
		case 18:
		case 19:
		case 20:
			conv1 = ConvertToNumericDecimal;
			flag = dbwillconvert(ColumnType, SQLNUMERIC);
			break;
		default:
			GeneralError(dbproc, 10041);
			return 0;
		}

		if (!flag)
		{
			GeneralError(dbproc, 10046);
			return 0;
		}
		bind_conv = acol->altbinds;
		bind_conv[i] = (col_bind_t*)AllocateHeapMemory(4, dbproc, 20u, 1);
		if (!bind_conv[i])
			return FreeOnError(0, dbproc);
		p_bind = bind_conv[i];
		p_bind->ncol = column;
		p_bind->bind_type = vartype;
		if (varlen)
		{
			p_bind->length = varlen;
		}
		else if (vartype == CHARBIND || vartype == STRINGBIND)
		{
			p_bind->length = GetColumnPrLength(ColumnType, 0, acol->altcols[i]->length);
			if (vartype == STRINGBIND)
				++p_bind->length;
		}
		else
		{
			p_bind->length = DBNOERR;
		}
		p_bind->buffer = (char*)varaddr;
		if (Conv_)
			p_bind->conv_func = Conv_;
		else
			p_bind->conv_func = conv1;
		result = 1;
	}
	else
	{
		GeneralError(dbproc, 10044);
		return 0;
	}
	return result;
}

int __cdecl dbaltcolid(PDBPROCESS dbproc, int computeid, int column)
{
	altcol_link_t* altcol = 0;

	altcol = CheckAltColumn(dbproc, computeid, column);
	if (altcol)
		return altcol->altcols[column - 1]->Operand;
	else
		return DBNOERR;
}
DBINT __cdecl dbaltlen(PDBPROCESS dbproc, int computeid, int column)
{
	altcol_link_t* altcol = 0;

	altcol = CheckAltColumn(dbproc, computeid, column);
	if (altcol)
		return altcol->altcols[column - 1]->length;
	else
		return DBNOERR;
}
int __cdecl dbaltop(PDBPROCESS dbproc, int computeid, int column)
{
	altcol_link_t* altcol = 0; 

	altcol = CheckAltColumn(dbproc, computeid, column);
	if (altcol)
		return altcol->altcols[column - 1]->top;
	else
		return DBNOERR;
}
int __cdecl dbalttype(PDBPROCESS dbproc, int computeid, int column)
{
	altcol_link_t* altcol = 0;

	altcol = CheckAltColumn(dbproc, computeid, column);
	if (altcol)
		return GetColumnType(dbproc, altcol->altcols[column - 1]->token, altcol->altcols[column - 1]->length);
	else
		return DBNOERR;
}
/*
* Bind a regular result column to a program variable.
* 
* column
* The column number of the row data that is to be copied to a program 
* variable. The first column is column number 1
* 
* vartype
* This describes the datatype of the binding. 
* 
* varlen
* The length of the program variable in bytes
* For values of vartype that represent a fixed-length type, such as 
* MONEYBIND or FLT8BIND, this length is ignored.
* 
* varaddr
* The address of the program variable to which the data will be copied
* 
* Return value SUCCEED or FAIL
*/
int __cdecl dbbind(PDBPROCESS dbproc, int column, int vartype, int varlen, BYTE* varaddr)
{
	int result = 0; 
	col_bind_t** binds = 0; 
	int i,bSucc = 0; 
	int ColumnType = 0;
	void* conv0 = 0, * conv1 = 0;

	if (!CheckEntry(dbproc))
		return 0;
	if (column <= dbproc->numcols && column >= 1)
	{
		i = column - 1;
		ColumnType = GetColumnType(
			dbproc,
			(BYTE)dbproc->columns_info[column - 1]->coltype,
			dbproc->columns_info[column - 1]->collen);
		if (dbproc->columns_data)
		{
			if (dbproc->binds || (dbproc->binds = (col_bind_t**)AllocateHeapMemory(4, dbproc, 4 * dbproc->numcols, 1)) != 0)
			{
				dbproc->isavail = 0;
				if (!dbproc->binds[i] || (FreeMemory(dbproc, dbproc->binds[i]), dbproc->binds[i] = 0, varaddr))
				{
					if (varaddr)
					{
						switch (vartype)
						{
						case 1:
							conv1 = ConvertToInt;
							bSucc = dbwillconvert(ColumnType, SQLINT1);
							break;
						case 2:
							conv1 = ConvertToInt;
							bSucc = dbwillconvert(ColumnType, SQLINT2);
							break;
						case 3:
							conv1 = ConvertToLong;
							bSucc = dbwillconvert(ColumnType, SQLINT4);
							break;
						case 4:
						case 10:
						case 11:
						case 12:
							conv0 = ConvertToChar2;
							bSucc = dbwillconvert(ColumnType, SQLCHAR);
							break;
						case 5:
						case 13:
							conv1 = ConvertToBinary;
							bSucc = dbwillconvert(ColumnType, SQLBINARY);
							break;
						case 6:
							conv1 = ConvertToBit;
							bSucc = dbwillconvert(ColumnType, SQLBIT);
							break;
						case 7:
							conv1 = ConvertToDateTime;
							bSucc = dbwillconvert(ColumnType, SQLDATETIME);
							break;
						case 8:
							conv1 = ConvertToMoney;
							bSucc = dbwillconvert(ColumnType, SQLMONEY);
							break;
						case 9:
							conv1 = ConvertToFloat;
							bSucc = dbwillconvert(ColumnType, SQLFLT8);
							break;
						case 14:
							conv1 = ConvertToReal;
							bSucc = dbwillconvert(ColumnType, SQLFLT4);
							break;
						case 15:
							conv1 = ConvertToSmallMoney;
							bSucc = dbwillconvert(ColumnType, SQLMONEY4);
							break;
						case 16:
							conv1 = ConvertToSmallDate;
							bSucc = dbwillconvert(ColumnType, SQLDATETIM4);
							break;
						case 17:
						case 18:
						case 19:
						case 20:
							conv1 = ConvertToNumericDecimal;
							bSucc = dbwillconvert(ColumnType, SQLDECIMAL);

							break;
						default:
							GeneralError(dbproc, 10041);
							return 0;
						}

						if (!bSucc)
						{
							GeneralError(dbproc, 10043);
							return 0;
						}
						binds = dbproc->binds;
						binds[i] = (col_bind_t*)AllocateHeapMemory(4, dbproc, 0x14u, 1);
						if (!binds[i])
							return FreeOnError(0, dbproc);

						binds[i]->ncol = column;
						binds[i]->bind_type = vartype;
						if (varlen)
						{
							binds[i]->length = varlen;
						}
						else if (vartype == CHARBIND || vartype == STRINGBIND)
						{
							binds[i]->length = GetColumnPrLength(
								(BYTE)dbproc->columns_info[i]->coltype,
								0,
								dbproc->columns_info[i]->collen);
							if (vartype == 10)
								++binds[i]->length;
						}
						else
						{
							binds[i]->length = DBNOERR;
						}
						binds[i]->buffer = (char*)varaddr;
						if (conv0)
							binds[i]->conv_func = conv0;
						else
							binds[i]->conv_func = conv1;
						result = 1;
					}
					else
					{
						GeneralError(dbproc, 10044);
						return 0;
					}
				}
				else
				{
					return SUCCEED;
				}
			}
			else
			{
				return FreeOnError(0, dbproc);
			}
		}
		else
		{
			return 0;
		}
	}
	else
	{
		GeneralError(dbproc, 10042);
		return 0;
	}
	return result;
}

LPCBYTE __cdecl dbbylist(PDBPROCESS dbproc, int computeid, LPINT size)
{
	altcol_link_t* Compute = 0; 

	if (!size)
		return 0;
	if (CheckEntry(dbproc))
	{
		Compute = GetCompute(dbproc, computeid, 1);
		if (Compute)
		{
			*size = Compute->data_length;
			return Compute->databuffer;
		}
		else
		{
			*size = 0;
			return 0;
		}
	}
	else
	{
		*size = 0;
		return 0;
	}
}

/*
* Cancel the current command batch.
* 
* Return value SUCCEED or FAIL
*/
int __cdecl dbcancel(PDBPROCESS dbproc)
{
	int result = 0; 

	if (!CheckEntry(dbproc))
		return 0;
	if ((dbproc->cmd_flag & 4) != 0)
		return 1;
	if ((dbproc->cmd_flag & 2) == 0 && !sendattention(dbproc))
		return 0;
	if ((dbproc->cmd_flag & 0x80) != 0)
		dbsqlok(dbproc);
	dbresults(dbproc);
	free_binds(dbproc);
	if (!canquery(dbproc))
		return 0;
	while (1)
	{
		result = dbresults(dbproc);
		if (result == NO_MORE_RESULTS)
			break;
		if (result == FAIL)
			return 0;
		if (!canquery(dbproc))
			return 0;
	}
	tidyproc(dbproc);

	dbzero(dbproc->CommLayer->buffer0, dbproc->CommLayer->bufsize);
	dbproc->CommLayer->wbytes = 0;
	dbproc->CommLayer->length = 0;
	dbproc->CommLayer->rbytes = 8;
	dbproc->token = 0;
	dbproc->isavail = 0;
	*dbproc->CommLayer->buffer1 = 0x46;
	return 1;
}
int __cdecl dbcanquery(PDBPROCESS dbproc)
{
	if (!CheckEntry(dbproc))
		return 0;
	free_binds(dbproc);
	return canquery(dbproc);
}
LPCSTR __cdecl dbchange(PDBPROCESS dbproc)
{
	if (CheckEntry(dbproc) && dbproc->name[0] && dbproc->change_dirty)
		return dbproc->name;
	else
		return 0;
}
null_value_t* __stdcall free_nullbinds(PDBPROCESS dbproc)
{
	null_value_t* result = 0; 
	null_value_t* nulls = 0; 

	result = (null_value_t*)dbproc;
	if (dbproc->nulls)
	{
		nulls = dbproc->nulls;
		if (nulls->p_nchar)
		{
			FreeMemory(dbproc, nulls->p_nchar);
			nulls->p_nchar = 0;
			nulls->nchar_length = 0;
		}
		if (nulls->p_nstring)
		{
			FreeMemory(dbproc, nulls->p_nstring);
			nulls->p_nstring = 0;
		}
		if (nulls->p_ntbstring)
		{
			FreeMemory(dbproc, nulls->p_ntbstring);
			nulls->p_ntbstring = 0;
		}
		if (nulls->p_nvarychar)
		{
			FreeMemory(dbproc, nulls->p_nvarychar);
			nulls->p_nvarychar = 0;
		}
		if (nulls->p_nbinary)
		{
			FreeMemory(dbproc, nulls->p_nbinary);
			nulls->p_nbinary = 0;
			nulls->nbinary_length = 0;
		}
		result = nulls;
		if (nulls->p_nvarybin)
		{
			result = (null_value_t*)FreeMemory(dbproc, nulls->p_nvarybin);
			nulls->p_nvarybin = 0;
		}
	}
	return result;
}
int __cdecl FinishXATransaction(IXATransLookup* xa_tran, ITransaction *pTrans)
{
	if (xa_tran)
		xa_tran->Release();
	if (pTrans)
		pTrans->Release();
	return 1;
}
void __cdecl dtc_free_resources(void** pTransactionExport)
{

	ITransactionExport *pExport = (ITransactionExport*)*pTransactionExport;
	if (pExport)
	{
		pExport->Release();
		*pTransactionExport = 0;
	}

}
int __cdecl dbclose(PDBPROCESS dbproc)
{
	if (dbproc)
	{
		if (dbproc->xa_transaction)
			FinishXATransaction((IXATransLookup*)dbproc->xa_transaction, 0);
		dbcancel(dbproc);
		if (CheckForValidDbproc(dbproc))
		{
			if (dbproc->b_security)
			{
				TermSession(dbproc);
				dbproc->b_security = 0;
			}
			if (dbcursorclose(dbproc) == 1)
				DeleteCriticalSection(&dbproc->cursorSem);
			EnterCriticalSection(&DbProcSem);
			DropDbproc(dbproc);
			LeaveCriticalSection(&DbProcSem);
			if (dbproc->conn_object)
			{
				if (DbCloseConnection(dbproc) != 1)
					GeneralError(dbproc, 10018);
				FreeLibrary(dbproc->CommLayer->module);
				FreeMemory(0, (LPVOID)dbproc->conn_object);
			}
			tidyproc(dbproc);
			free_cmdbuffer(dbproc);
			free_rpcbuffer(dbproc);
			if (dbproc->dtc_resources)
				dtc_free_resources(&dbproc->dtc_resources);
			free_options(dbproc);
			if (dbproc->CommLayer)
			{
				FreeMemory(0, dbproc->CommLayer->buffer_0);
				FreeMemory(0, dbproc->CommLayer->buffer_1);
				FreeMemory(0, dbproc->CommLayer);
			}
			free_nullbinds(dbproc);
			FreeMemory(dbproc, (LPVOID)dbproc->nulls);
			DropProcArray();
			HeapDestroy(dbproc->hHeap);
			dbproc->hHeap = 0;
			FreeMemory(0, dbproc);
			return 1;
		}
		else
		{
			return 0;
		}
	}
	else
	{
		GeneralError(0, SQLENULL);
		return 0;
	}
}
/*
* Drop rows from the row buffer. 
* 
* nrow 
* 
* The number of rows you want cleared from the row buffer. If you make n
* equal to or greater than the number of rows in the buffer, all but the newest 
* row will be removed. If n is less than 1, the function call is ignored.
*/
void __cdecl dbclrbuf(PDBPROCESS dbproc, int nrow)
{
	int result = 0; 

	result = CheckEntry(dbproc);
	if (result)
	{
		if (dbproc->nbufrow > 1u && nrow >= 1)
		{
			if (nrow >= dbproc->nbufrow)
				nrow = dbproc->nbufrow - 1;
			dbproc->isavail = 0;
			MoveRows(dbproc, nrow);
		}
	}

}
/*
* build cmd buffer
*/

int dbbcmd(PDBPROCESS dbproc, const char* cmd, size_t Size)
{
	buf_node_t* next = 0;

	if (!CheckEntry(dbproc))
		return 0;
	if ((dbproc->cmd_flag & 1) != 0 && (dbproc->option[8].opt & 1) == 0)
		free_cmdbuffer(dbproc);
	dbproc->cmd_flag &= ~1u;
	for (next = dbproc->cmdbuffer; next && next->next; next = next->next)
		;
	if (next)
	{
		next->next = (buf_node_t*)AllocateHeapMemory(4, dbproc, 0xCu, 1);
		if (!next->next)
			return FreeOnError(0, dbproc);
		next = next->next;
	}
	else
	{
		next = (buf_node_t*)AllocateHeapMemory(4, dbproc, 0xCu, 1);
		if (!next)
			return FreeOnError(0, dbproc);
		dbproc->cmdbuffer = next;
	}
	next->size = Size;
	if (Size)
	{
		next->data = AllocateHeapMemory(4, dbproc, next->size, 1);
		if (!next->data)
			return FreeOnError(0, dbproc);
		dbmove((void*)cmd, next->data, next->size);
		dbWinConvToServer(dbproc, (char*)next->data, Size);
	}
	next->next = 0;
	dbproc->isavail = 0;
	return 1;
}
/*
* Add text to the DBPROCESS command buffer. 
* 
* Parameters 
* 
* dbproc
* A pointer to the DBPROCESS structure that provides the connection for a 
* particular front-end/server process. It contains all the information 
* that DB-Library uses to manage communications and data between the front end and server.
* 
* cmdstring
* A null-terminated character string that dbcmd copies into the command buffer.
* 
* Return value SUCCEED or FAIL
*/
int dbcmd(PDBPROCESS dbproc, LPCSTR cmdstring)
{
	if (cmdstring && *cmdstring)
		return dbbcmd(dbproc, cmdstring, strlen(cmdstring));
	if (!CheckEntry(dbproc))
		return 0;
	if ((dbproc->cmd_flag & 1) != 0 && (dbproc->option[8].opt & 1) == 0)
		free_cmdbuffer(dbproc);
	dbproc->cmd_flag &= ~1u;
	return SUCCEED;
}

BOOL __cdecl dbcmdrow(PDBPROCESS dbproc)
{
	return dbproc && !dbproc->bclosed && dbproc->columns_info != 0;
}
/*
* Determine whether the source of a regular result column is updatable through 
* the DB-Library browse-mode facilities. 
*/
int __cdecl dbcolbrowse(PDBPROCESS dbproc, int colnum)
{
	int col_ = 0;

	if (!CheckColumn(dbproc, colnum))
		return 0;
	col_ = colnum - 1;
	if (dbproc->columns_info && dbproc->columns_info[col_])
		return dbtabbrowse(dbproc, dbproc->columns_info[col_]->ntab);
	else
		return 0;
}
/*
* Return the maximum length of the data in a regular result column. 
*/
int __cdecl dbcollen(PDBPROCESS dbproc, int column)
{
	if (CheckColumn(dbproc, column))
		return dbproc->columns_info[column - 1]->collen;
	else
		return DBNOERR;
}
/*
* Return the name of a regular result column. 
*/
LPCSTR __cdecl dbcolname(PDBPROCESS dbproc, int column)
{
	if (CheckColumn(dbproc, column))
		return dbproc->columns_info[column - 1]->name;
	else
		return 0;
}
/*
* Return a pointer to the name of the database column from which the specified 
* regular result column was derived.
*/
LPCSTR __cdecl dbcolsource(PDBPROCESS dbproc, int column)
{
	column_info_t** coldata = 0; 

	if (!CheckColumn(dbproc, column))
		return 0;
	coldata = dbproc->columns_info;
	if (!coldata || !coldata[column - 1] || (coldata[column - 1]->type & 4) != 0)
		return 0;
	if ((coldata[column - 1]->type & 0x20) != 0)
	{
		if (coldata[column - 1]->actualname)
			return coldata[column - 1]->actualname;
		else
			return 0;
	}
	else if (coldata[column - 1])
	{
		return coldata[column - 1]->name;
	}
	else
	{
		return 0;
	}
}
/*
* Return the datatype for a regular result column.
*/
int __cdecl dbcoltype(PDBPROCESS dbproc, int column)
{
	if (CheckColumn(dbproc, column))
		return GetColumnType(dbproc, dbproc->columns_info[column - 1]->coltype, dbproc->columns_info[column - 1]->collen);
	else
		return DBNOERR;
}

int __cdecl dbconvert(
	PDBPROCESS dbproc,
	int srctype,
	LPBYTE Src,
	int srclen,
	int desttype,
	LPBYTE dest,
	int destlen)
{
	int dtIn_ = 0;
	int dtOut_ = 0;
	int result = -1;
	if (!dest)
	{
		GeneralError(dbproc, 10036);
		return -1;
	}
	dtIn_ = dbconvert_getcommontype(srctype, srclen);
	if (!dtIn_)
	{
		GeneralError(dbproc, 10016);
		return -1;
	}
	dtOut_ = dbconvert_getcommontype(desttype, destlen);
	if (!dtOut_)
	{
		GeneralError(dbproc, 10016);
		return -1;
	}
	if (!srclen || !Src)
	{
		return SetTypeNull(dbproc, (BYTE*)dest, dtOut_, destlen);
	}
	if (destlen >= DBNOERR && srclen >= DBNOERR)
	{
		switch (dtOut_)
		{
		case SQLIMAGE:
		case SQLBINARY:
			result = ConvertToBinary(dbproc, dtIn_, Src, srclen, dtOut_, dest, destlen);
			break;
		case SQLTEXT:
		case SQLCHAR:
			result = ConvertToChar(dbproc, dtIn_, Src, srclen, dtOut_, (char*)dest, destlen);
			break;
		case SQLINT1:
		case SQLINT2:
			result = ConvertToInt(dbproc, dtIn_, Src, srclen, dtOut_, (int*)dest);
			break;
		case SQLBIT:
			result = ConvertToBit(dbproc, dtIn_, Src, srclen, dtOut_, (char*)dest);
			break;
		case SQLINT4:
			result = ConvertToLong(dbproc, dtIn_, Src, desttype, dtOut_, dest);
			break;
		case SQLDATETIM4:
			result = ConvertToSmallDate(dbproc, dtIn_, (SmallDateTime*)Src, desttype, dtOut_, (SmallDateTime*)dest);
			break;
		case SQLFLT4:
			result = ConvertToReal( dbproc, dtIn_, Src, desttype, dtOut_, (float*)dest);
			break;
		case SQLMONEY:
			result = ConvertToMoney(dbproc, dtIn_, (BYTE*)Src, desttype, dtOut_, (DBMONEY*)dest, destlen);
			break;
		case SQLDATETIME:
			result = ConvertToDateTime(dbproc, dtIn_, (SmallDateTime*)Src, desttype, dtOut_, (DBDATETIME*)dest);
			break;
		case SQLFLT8:
			result = ConvertToFloat(dbproc, dtIn_, Src, desttype, dtOut_, (double*)dest);
			break;
		case SQLDECIMAL:
		case SQLNUMERIC:
			result = ConvertToNumericDecimal(dbproc, dtIn_, (BYTE*)Src, desttype, dtOut_, (DBNUMERIC*)dest, destlen);
			break;
		case SQLMONEY4:
			result = ConvertToSmallMoney(dbproc, dtIn_, (BYTE*)Src, desttype, dtOut_, (DWORD*)dest, destlen);
			break;
		default:
			GeneralError(dbproc, 10016);
			result = -1;
			break;
		}
	}
	else
	{

		GeneralError(dbproc, 10016);
	}
	return result;
}
/*
* Returns the number of rows affected by a Transact-SQL command. 
*/
int __cdecl dbcount(PDBPROCESS dbproc)
{
	if (dbproc && !dbproc->bclosed)
		return dbproc->DoneRowCount;
	else
		return 0;
}
/*
* Return the number of the current command. 
*/
int __cdecl dbcurcmd(PDBPROCESS dbproc)
{
	if (dbproc && !dbproc->bclosed)
		return dbproc->curcmd;
	else
		return 0;
}
/*
* Return the number of the row currently being read.
*/
int __cdecl dbcurrow(PDBPROCESS dbproc)
{
	if (dbproc && !dbproc->bclosed)
		return dbproc->currow;
	else
		return 0;
}
/*
* Return a pointer to the data in a regular result column.
*/
LPCBYTE __cdecl dbdata(PDBPROCESS dbproc, int column)
{
	int token = 0; 
	column_data_t** column_data = 0; 

	if (!CheckColumn(dbproc, column))
		return 0;
	column_data = dbproc->columns_data;
	token = dbproc->columns_info[column - 1]->coltype;
	if (!column_data || !column_data[column - 1] || !column_data[column - 1]->data)
		return 0;
	if (token != SQLTEXT && token != SQLIMAGE)
		return column_data[column - 1]->data;

	if (column_data[column - 1]->data)
		((blob_t*)column_data[column - 1]->data)->data;
	return 0;
}
/*
* Return the length of the data in a regular result column.
* 
* The length, in bytes, of the data that would be returned for the particular 
* column. If the data has a null value, dbdatlen returns 0. If the column number 
* is not in range, dbdatlen returns -1
*/
int __cdecl dbdatlen(PDBPROCESS dbproc, int column)
{
	int token = 0; 
	column_data_t** column_data = 0; 

	if (!CheckColumn(dbproc, column))
		return DBNOERR;
	column_data = dbproc->columns_data;
	token = dbproc->columns_info[column - 1]->coltype;
	if (!column_data || !column_data[column - 1])
		return DBNOERR;
	if (token != SQLTEXT && token != SQLIMAGE)
		return column_data[column - 1]->len;
	if (column_data[column - 1]->data)
		return ((blob_t*)column_data[column - 1]->data)->len;
	return DBNOERR;
}
/*
* Determine whether a particular DBPROCESS is dead. 
*/
BOOL __cdecl dbdead(PDBPROCESS dbproc)
{
	if (dbproc && !dbproc->bclosed)
		return dbproc->bclosed;
	else
		return SUCCEED;
}
/*
* Close and deallocate all DBPROCESS structures, and clean up any structures 
* initialized by dbinit.
*/
void __cdecl dbexit()
{
	PDBPROCESS lpMem = 0;
	PDBPROCESS* START = 0;
	PDBPROCESS* END = 0;

	EnterCriticalSection(&DbProcSem);
	START = DbProcArray;
	END = &DbProcArray[DbMaxProcs];
	while (START && START < END)
	{
		lpMem = *START++;
		if (lpMem)
		{
			LeaveCriticalSection(&DbProcSem);
			dbclose(lpMem);
			EnterCriticalSection(&DbProcSem);
		}
	}
	LeaveCriticalSection(&DbProcSem);
}
/*
* Add text to the DBPROCESS command buffer using C runtime library sprintf-type formatting. 
* 
* cmdstring
* A format string of the form used by the sprintf routine.
* 
* There is an optional and variable number of arguments to dbfcmd. The 
* number and type of arguments required depends on the format specifiers 
* included in the cmdstring argument. The arguments are passed directly to 
* the C-library sprintf function. Neither dbfcmd nor the C compiler can type 
* check these arguments. As with using sprintf, the programmer must ensure 
* that each argument type matches the corresponding format specifier.
* 
* Return value
* SUCCEED or FAIL
*/
int __cdecl dbfcmd(PDBPROCESS dbproc, LPCSTR cmdstring, ...)
{
	char* lpMem = 0; 
	int result = 0;
	char* Buffer = 0; 
	va_list va;

	va_start(va, cmdstring);
	if (!CheckEntry(dbproc))
		return 0;
	if ((dbproc->cmd_flag & 1) != 0 && (dbproc->option[8].opt & 1) == 0)
		free_cmdbuffer(dbproc);
	dbproc->cmd_flag &= ~1u;
	if (!cmdstring || !*cmdstring)
		return SUCCEED;
	if (2 * strlen(cmdstring) >= 0x400)
		lpMem = (char*)AllocateHeapMemory(4, dbproc, 2 * strlen(cmdstring), 0);
	else
		lpMem = (char*)AllocateHeapMemory(4, dbproc, 0x400u, 0);
	Buffer = lpMem;
	if (!lpMem)
		return 0;
	vsprintf(lpMem, cmdstring, va);
	result = dbcmd(dbproc, Buffer);
	FreeMemory(dbproc, Buffer);
	return result;
}
/*
* Clear the command buffer. 
* 清除命令缓存
* 
* This routine clears a DBPROCESS command buffer by freeing any space 
* allocated to it. It then sets the command buffer to NULL.
* Commands are added to the command buffer with the dbcmd or dbfcmd routine. 

*/
void __cdecl dbfreebuf(PDBPROCESS dbproc)
{

	if (CheckEntry(dbproc))
		return free_cmdbuffer(dbproc);
	return ;
}
int __cdecl dbfirstrow(PDBPROCESS dbproc)
{
	if (dbproc && !dbproc->bclosed)
		return dbproc->firstrow;
	else
		return 0;
}
void __cdecl dbfreelogin(db_login_t* login)
{
	if (login)
		FreeMemory(0, login);
	return ;
}

void __cdecl dbfreequal(LPVOID lpMem)
{

	if (lpMem)
		FreeMemory(0, lpMem);
	return ;
}
/*
* Return a pointer to a character in the command buffer. 
* n 
* The position of the desired character in the command buffer. The first 
* character position is 0.
* 
* Return value
* dbgetchar returns a pointer to the nth character in the command buffer. If n is 
* not in range, dbgetchar returns NULL.
*/
LPSTR __cdecl dbgetchar(PDBPROCESS dbproc, int n)
{
	int N_ = 0;
	buf_node_t* pbuf = 0; 

	if (getcmdbuffer(dbproc, n, &pbuf, &N_) && pbuf)
		return (char*)pbuf->data + N_;
	else
		return 0;
}
short dbgetmaxprocs()
{
	return DbMaxProcs;
}
int __cdecl dbgetoff(PDBPROCESS dbproc, unsigned __int16 offtype, int startfrom)
{
	offset_t* next;

	if (!CheckEntry(dbproc))
		return DBNOERR;
	if (!dbproc->offsets)
		return DBNOERR;
	if (startfrom < 0)
		return DBNOERR;
	for (next = dbproc->offsets; next; next = next->next)
	{
		if (next->off >= startfrom && next->index == offtype)
			return next->off;
	}
	return DBNOERR;
}
int __cdecl dbgetrow(PDBPROCESS dbproc, int row)
{
	int row_ = 0;
	int i, j; 
	int BF = 0;
	rowbuffer_t* rowbuffer = 0;
	altcol_link_t* Compute = 0;

	BF = 0;
	if (!CheckEntry(dbproc))
		return 0;
	if (dbproc->nbufrow <= 1u)
		return 0;
	if (row > dbproc->nrows)
		return NO_MORE_ROWS;
	if (row > dbproc->lastrow || row < dbproc->firstrow)
		return NO_MORE_ROWS;
	row_ = dbproc->rowidx + row - dbproc->firstrow;
	if (row_ > dbproc->nbufrow)
		row_ -= dbproc->nbufrow;
	if (row_)
		rowbuffer = &dbproc->rowbuffer[row_ - 1];
	else
		rowbuffer = dbproc->rowbuffer;
	if (!rowbuffer->nrow)
		return NO_MORE_ROWS;
	if (rowbuffer->nrow == MORE_ROWS)
	{
		dbproc->columns_data = rowbuffer->columnsdata;
		for (i = 0; i < dbproc->ncols; ++i)
		{
			if (!BindVar(dbproc, i))
				BF = 1;
		}
		if (BF == 1)
			return 0;
	}
	else
	{
		Compute = GetCompute(dbproc, rowbuffer->nrow, 0);
		if (!Compute)
			return 0;
		dbproc->altrowdata = rowbuffer->altcoldata;
		for (j = 0; j < Compute->n_alts; ++j)
		{
			if (!BindAVar(dbproc, rowbuffer->nrow, j))
				BF = 1;
		}
		if (BF == 1)
			return 0;
	}
	dbproc->currow = row;
	dbproc->rowtype = rowbuffer->nrow;
	return dbproc->rowtype;
}
int __cdecl dbgettime()
{
	return DbTimeOut;
}
/*
* Initialize DB-Library. 
* 数据库初始化，包括本地特殊字符
*/
LPCSTR __cdecl dbinit()
{
	if (!GetDtmFormat())
		return 0;
	CheckForClientCursors();
	CheckForDataReadySleep();
	return "DB-Library version 8.00.194";
}
BOOL __cdecl dbisavail(PDBPROCESS dbproc)
{
	if (dbproc && !dbproc->bclosed)
		return dbproc->isavail;
	else
		return 0;
}
BOOL __cdecl dbisopt(PDBPROCESS dbproc, int option, LPCSTR param)
{
	if (!CheckEntry(dbproc))
		return 0;
	if (GetOptIndex(option) != -1)
		return IsOption(dbproc, option, param);
	GeneralError(dbproc, 10030);
	return 0;
}
int __cdecl dblastrow(PDBPROCESS dbproc)
{
	if (dbproc && !dbproc->bclosed)
		return dbproc->lastrow;
	else
		return 0;
}
void dblocklib()
{
	GlobalFix((HGLOBAL)0xFFFFFFFF);
}
/*
* Allocates a login record for use in dbopen. 
* This routine allocates a LOGINREC structure for use with dbopen.
*
* Return value
* LOGINREC
*/
db_login_t* dblogin()
{
	db_login_t* login = 0;

	login = (db_login_t*)AllocateHeapMemory(4, 0, sizeof(db_login_t), 1);
	if (!login)
		return 0;
	login->lInt2 = 3;
	login->lInt4 = 1;
	login->lChar = 6;
	login->lFloat = 10;
	login->Reservedbyte2 = 9;
	login->lUseDb = 1;
	login->lDumpLoad = 1;
	login->lType = 0;
	login->lInterface = 0;
	login->cbProgName = (char)strlen("MSDBLIB");
	login->lFloat4 = 13;
	login->lDate4 = 17;
	login->SetLang = 1;
	login->err_handler = 0;
	login->msg_handler = 0;
	login->logintime = -1;
	login->fallback = 0;
	strncpy(login->PacketSize, "000", 3u); // Send packet size defaults to 512 bytes
	login->cbPacketSize = 3;
	dbmove((void*)"MSDBLIB", login->ProgName, login->cbProgName);
	dbmove(&ProgVersion, login->ProgVersion, 4u);
	dbmove(&TdsVer, login->TDSVersion, 4u);
	GetNode((LPBYTE)login->AppType);
	return login;
}
BOOL __cdecl dbmorecmds(PDBPROCESS dbproc)
{
	return dbproc && !dbproc->bclosed && (dbproc->cmd_flag & 0x10) != 0;
}
int __cdecl dbmoretext(PDBPROCESS dbproc, int size, BYTE* text)
{
	int flag = 0;

	if (!CheckEntry(dbproc))
		return 0;
	if (size < 1)
		return 0;
	if (!text)
		return 0;
	if (!dbproc->packet_size && !*(_DWORD*)&dbproc->field_7C)
		return 0;
	dbproc->cmd_flag &= ~4u;
	if (dbproc->ver >= 0x40u)
		*dbproc->CommLayer->buffer1 = PT_BULKLOAD;
	if (!*(_DWORD*)&dbproc->field_7C)
	{
		if (!queuepacket(dbproc, (BYTE*)&dbproc->packet_size, 4u))
			return 0;
		*(_DWORD*)&dbproc->field_7C = 1;
	}
	if (dbproc->packet_size >= size)
	{
		if (queuepacket(dbproc, text, size))
		{
			dbproc->packet_size -= size;
			flag = dbproc->exec;
			dbproc->exec = 1;
			if (dbproc->packet_size || sendflush(dbproc))
			{
				dbproc->exec = flag;
				return SUCCEED;
			}
			else
			{
				dbproc->exec = flag;
				return 0;
			}
		}
		else
		{
			return 0;
		}
	}
	else
	{
		GeneralError(dbproc, 10021);
		return 0;
	}
}
const char* __cdecl dbname(PDBPROCESS dbproc)
{
	if (CheckEntry(dbproc) && dbproc->name[0])
		return dbproc->name;
	else
		return null_string;
}
int __cdecl dbnextrow(PDBPROCESS dbproc)
{
	char tag = 0;

	int Size = 0;
	int result = 0;
	rowbuffer_t* rbuf = 0;
	int i = 0;
	int row_ = 0;
	int flag = 0;
	altcol_link_t* Compute = 0;
	int Status = 0;
	int row1 = 0;
	BYTE token = 0;
	alt_column_data_t* arow = 0;

	Status = 1;
	result = 0;
	flag = 0;
	if (!CheckEntry(dbproc))
		return CheckTimeoutAndReturn(dbproc, 0);
	if (dbproc->nbufrow > 1u && dbproc->nrows)
	{
		if (dbproc->currow + 1 > dbproc->lastrow && dbproc->nextrowidx && NextRowIndex(dbproc) == dbproc->rowidx)
			return CheckTimeoutAndReturn(dbproc, -3);
		if (dbproc->currow + 1 <= dbproc->nrows
			&& dbproc->currow >= dbproc->firstrow
			&& dbproc->currow < dbproc->lastrow
			&& dbproc->nextrowidx)
		{
			row_ = ++dbproc->currow - dbproc->firstrow + dbproc->rowidx - 1;
			if (row_ >= dbproc->nbufrow)
				row_ -= dbproc->nbufrow;
			dbproc->rowtype = dbproc->rowbuffer[row_].nrow;
			if (dbproc->rowtype == -1)
			{
				dbproc->columns_data = dbproc->rowbuffer[row_].columnsdata;
				for (i = 0; i < dbproc->ncols; ++i)
				{
					if (!BindVar(dbproc, i))
						result = 1;
				}
				if (result == 1)
					return CheckTimeoutAndReturn(dbproc, 0);
			}
			else
			{
				dbproc->altrowdata = dbproc->rowbuffer[row_].altcoldata;
				Compute = GetCompute(dbproc, dbproc->rowtype, 1);
				if (!Compute)
					return CheckTimeoutAndReturn(dbproc, 0);
				for (i = 0; i < Compute->n_alts; ++i)
				{
					if (!BindAVar(dbproc, dbproc->rowtype, i))
						result = 1;
				}
				if (result == 1)
					return CheckTimeoutAndReturn(dbproc, 0);
			}
			return CheckTimeoutAndReturn(dbproc, dbproc->rowtype);
		}
	}
	if (dbproc->severity_level == EXNONFATAL || (!dbproc->severity_level || dbproc->severity_level == EXUSER) && (dbproc->cmd_flag & 2) == 0)
		return CheckTimeoutAndReturn(dbproc, NO_MORE_ROWS);
	if (!RowDataInBuffer(dbproc))
		free_rowdata(dbproc, 0);
	dbproc->currow = dbproc->lastrow;
	while (2)
	{
		token = dbproc->token;
		if (!token)
		{
			token = getbyte(dbproc, (BYTE*)&Status);
			dbproc->token = token;
		}
		if (!Status)
		{
			dbproc->token = 0;
			return CheckTimeoutAndReturn(dbproc, 0);
		}
		switch (token)
		{
		case SQLRETURNSTATUS:
		case SQLERROR:
		case SQLINFO:
		case SQLRETURNVALUE:
		case SQLROW:
		case SQLALTROW:
		case SQLENVCHANGE:
		case SQLDONE:
		case SQLDONEPROC:
		case SQLDONEINPROC:
			if (gettokenlen(dbproc, token, (BYTE*)&Size))
				break;
			return CheckTimeoutAndReturn(dbproc, 0);
		default:
			break;
		}
		switch (token)
		{
		case OLD_SQLCOLFMT:
		case SQLOFFSET:
		case SQLPROCID:
		case SQLCOLNAME:
		case SQLCOLFMT:
		case SQLTABNAME:
		case SQLCOLINFO:
		case SQLALTNAME:
		case SQLALTFMT:
		case SQLORDER:
		case SQLCONTROL:
		case SQLALTCONTROL:
		case SQLRETURN:
			dbproc->rowtype = NO_MORE_ROWS; 
			return CheckTimeoutAndReturn(dbproc, NO_MORE_ROWS);
		case SQLENVCHANGE_42: 
		case SQLENVCHANGE:
			if (!HandlerEnvChange(dbproc, token, Size))
				return CheckTimeoutAndReturn(dbproc, 0);
			goto NEXT_LABEL;
		case SQLRETURNSTATUS:
			if (!GetReturnStatus(dbproc, Size))
				return CheckTimeoutAndReturn(dbproc, 0);
			goto NEXT_LABEL;
		case SQLERROR:
		case SQLINFO:
			if (HandleInfoToken(dbproc, Size) == 1)
				goto NEXT_LABEL;
			result = FreeOnError(0, dbproc);
			return CheckTimeoutAndReturn(dbproc, result);
		case SQLRETURNVALUE:
			if (!GetReturnVal(dbproc, Size))
				return CheckTimeoutAndReturn(dbproc, 0);
			goto NEXT_LABEL;
		case SQLROW:
			if (dbproc->nbufrow <= 1u)
			{
				++dbproc->firstrow;
				if (dbproc->ncols == 1 && dbproc->packet_size)
					return CheckTimeoutAndReturn(dbproc, 0);
			}
			else
			{
				if (dbproc->nextrowidx && NextRowIndex(dbproc) == dbproc->rowidx)
					return CheckTimeoutAndReturn(dbproc, -3);
				if (dbproc->firstrow <= 0)
					dbproc->firstrow = 1;
				dbproc->nextrowidx = NextRowIndex(dbproc);
				rbuf = &dbproc->rowbuffer[dbproc->nextrowidx - 1];
				dbproc->columns_data = rbuf->columnsdata;
				rbuf->nrow = -1;
			}
			++dbproc->currow;
			++dbproc->lastrow;
			for (i = 0; i < dbproc->ncols; ++i)
			{
				Status = GetRowColumnData(dbproc, i);
				if (!Status)
					return CheckTimeoutAndReturn(dbproc, 0);
				if (Status == -1)
					result = 1;
			}
			++dbproc->nrows;
			dbproc->token = 0;
			dbproc->severity_level = EXINFO;
			dbproc->rowtype = MORE_ROWS;
			if (result != 1)
				return CheckTimeoutAndReturn(dbproc, -1);
			return CheckTimeoutAndReturn(dbproc, 0);
		case SQLALTROW:
			if ((!dbproc->altrowdata || AltDataInBuffer(dbproc)) && !AllocateAltData(dbproc))
				return CheckTimeoutAndReturn(dbproc, 0);
			if (dbproc->nbufrow <= 1u)
			{
				++dbproc->firstrow;
			}
			else
			{
				if (dbproc->nextrowidx && NextRowIndex(dbproc) == dbproc->rowidx)
					return CheckTimeoutAndReturn(dbproc, -3);
				if (dbproc->firstrow <= 0)
					dbproc->firstrow = 1;
				dbproc->nextrowidx = NextRowIndex(dbproc);
				rbuf = &dbproc->rowbuffer[dbproc->nextrowidx - 1];
			}
			++dbproc->lastrow;
			++dbproc->currow;
			if (dbproc->CommLayer->rbytes
				&& dbproc->CommLayer->wbytes >= 2u
				&& dbproc->CommLayer->length - dbproc->CommLayer->rbytes >= 2)
			{
				memmove(&row1, &dbproc->CommLayer->buffer0[dbproc->CommLayer->rbytes], 2u);
				dbproc->CommLayer->rbytes += 2;
				dbproc->CommLayer->wbytes -= 2;
				result = 1;
			}
			else
			{
				result = getbytes_internal(dbproc, (BYTE*)&row1, 2);
			}
			if (!result)
				return CheckTimeoutAndReturn(dbproc, 0);
			Compute = dbproc->altcolinfo;
			for (i = 0; i < row1 - 1; ++i)
			{
				if (!Compute)
					GeneralError(dbproc, SQLEICN);
				Compute = Compute->next;
			}
			arow = dbproc->altrowdata[row1 - 1];
			i = 0;
			while (2)
			{
				if (i >= Compute->n_alts)
				{
					dbproc->severity_level = EXINFO;
					++dbproc->nrows;
					dbproc->token = 0;
					dbproc->rowtype = row1;
					if (dbproc->nbufrow > 1u)
					{
						rbuf->nrow = row1;
						rbuf->altcoldata = dbproc->altrowdata;
					}
					if (result != 1)
						return CheckTimeoutAndReturn(dbproc, row1);
				}
				else
				{
					Status = GetAltRowColumnData(dbproc, i, Compute, arow);
					if (Status)
					{
						if (Status == -1)
							result = 1;
						++i;
						continue;
					}
				}
				break;
			}
			return CheckTimeoutAndReturn(dbproc, 0);
		case SQLDONE:
		case SQLDONEPROC:
		case SQLDONEINPROC:
			if (flag && token == SQLDONEPROC)
				tag = 2;
			else
				tag = 0;
			if (token == SQLDONEINPROC)
			{
				flag = 1;
			}
			else if (token != SQLDONEPROC)
			{
				flag = 0;
			}
			if (dbproc->nbufrow <= 1u)
			{
				dbproc->rowtype = NO_MORE_ROWS;
				if (dbproc->token != SQLDONEINPROC)
				{
					dbproc->firstrow = 0;
					dbproc->lastrow = 0;
					dbproc->currow = 0;
				}
			}
			dbproc->cmd_flag &= ~0x20u;
			dbproc->severity_level = 0;
			Status = HandleDoneToken(dbproc, Size, token, tag);
			if (Status == -5)
			{
			NEXT_LABEL:
				dbproc->token = 0;
				continue;
			}
			dbproc->token = 0;
			return CheckTimeoutAndReturn(dbproc, Status);
		default:
			// "Possible network error: Bad token from SQL Server: Datastream processing out of sync."
			GeneralError(dbproc, SQLEBTOK);
			return CheckTimeoutAndReturn(dbproc, 0);
		}
	}
}
int __cdecl dbnumalts(PDBPROCESS dbproc, int computeid)
{
	altcol_link_t* Compute = 0; 

	if (!CheckEntry(dbproc))
		return -1;
	Compute = GetCompute(dbproc, computeid, 1);
	if (Compute)
		return Compute->n_alts;
	else
		return -1;
}
int __cdecl dbnumcols(PDBPROCESS dbproc)
{
	if (CheckEntry(dbproc))
		return dbproc->numcols;
	else
		return 0;
}


int __cdecl dbnumcompute(PDBPROCESS dbproc)
{
	if (CheckEntry(dbproc))
		return dbproc->n_compute_row;
	else
		return -1;
}
int __cdecl dbnumorders(PDBPROCESS dbproc)
{
	if (dbproc && !dbproc->bclosed)
		return dbproc->n_orders;
	else
		return 0;
}
/*
* 
*/
PDBPROCESS __cdecl dbopen(db_login_t* login, LPCSTR server)
{
	int pid = 0;
	int ConnectionSize = 0;
	char* buf1 = 0;
	char* buf0 = 0;
	DWORD nSize = 0;

	HKEY phkResult = 0;
	char SubKey[500] = { 0 };
	char Buffer[16] = { 0 };
	char* servername = 0;
	int t0 = 0;
	LPVOID lpMem = 0;
	PDBPROCESS dbproc, dbproc_1;
	PacketHeader* packetheader = 0;
	char StrVerdor[264] = { 0 };
	ushort bufsize = 0;
	LPVOID Src = 0;
	char Source[32] = { 0 };
	LPVOID pConnObj = 0;
	int AnsiOem = 0;

	HMODULE hLibModule = 0;
	DWORD dwMilliseconds = 0;
	int result = 0;
	__time32_t t1, t2;

	char szServer[256] = { 0 };

	dbproc = 0;
	StrVerdor[0] = null_string[0];
	memset(&StrVerdor[1], 0, 260u);
	bufsize = 0;
	Src = 0;
	hLibModule = 0;
	SetDtmDefaults();

	dwMilliseconds = 100;
	if (login == 0)
	{
		// "Login incorrect."
		GeneralError(0, SQLEPWD);
	}
	else
	{
		if (login->err_handler)
		{
			dbproc = (PDBPROCESS)AllocateHeapMemory(4, 0, sizeof(DBPROCESS), 1);
			if (!dbproc)
			{
				// "Unable to allocate sufficient memory."
				GeneralError(0, SQLEMEM);
				goto ERR_EXIT;
			}
			// typedef int(__cdecl* DBERRHANDLE_PROC)(PDBPROCESS, INT NetlibErrCode, INT dbErrCode, INT, LPCSTR, LPCSTR);
			dbproc->err_handler = login->err_handler;
		}
		if (!OpenAnotherProc())
		{
			GeneralError(dbproc, 10029);
			goto ERR_EXIT;
		}
		Src = AllocateHeapMemory(4, 0, 48u, 1);
		if (!Src)
			goto ERR_EXIT;
		servername = (char*)AllocateHeapMemory(4, 0, 0x100u, 1);
		if (!servername)
			goto ERR_EXIT;
		lpMem = AllocateHeapMemory(4, 0, 0x1000u, 1);
		if (!lpMem)
			goto ERR_EXIT;
		strcpy(Source, "00000000");
		pid = _getpid();
		_itoa(pid, Buffer, 16);
		//strcat(Source, Buffer);
		strcpy(&Source[8 - strlen(Buffer)], Buffer);
		dbsetlname(login, Source, 5);
		t1 = (__time32_t)time(0);
		dbproc_1 = (PDBPROCESS)AllocateHeapMemory(4, 0, sizeof(DBPROCESS), 1);
		if (!dbproc_1)
		{
			GeneralError(dbproc, SQLEMEM);
			FreeMemory(0, lpMem);
			goto ERR_EXIT;
		}
		dbproc_1->b_security = 0;
		/*
		* 在这卡bug好久
		* 原来是结构DBPROCESS 分配大小为0x3DA，实际上 sizeof(DBPROCESS) != 0x3DE
		* 里边有一个字段忘记删除了
		*/
		dbproc_1->CommLayer = (commlayer_t*)AllocateHeapMemory(4, 0, 90u, 1);
		if (!dbproc_1->CommLayer)
		{
			GeneralError(dbproc, SQLEMEM);
			FreeMemory(0, lpMem);
			FreeMemory(0, dbproc_1);
			goto ERR_EXIT;
		}
		dbproc_1->xa_transaction = 0;
		dbproc_1->hHeap = HeapCreate(HEAP_NO_SERIALIZE, 0x8000u, 0);

		if (dbproc_1->hHeap == 0)
		{
			goto ERR_EXIT;
		}
		if (login->err_handler)
			dbproc_1->err_handler = login->err_handler;
		else
			dbproc_1->err_handler = DbErrHandler;
		if (login->msg_handler)
			dbproc_1->msg_handler = login->msg_handler;
		else
			dbproc_1->msg_handler = DbMsgHandler;
		dbproc_1->last_msg_handler = 0;
		dbproc_1->last_err_handler = 0;
		dbproc_1->field_196 = 1;
		dbproc_1->field_19A = 1;
		dbproc_1->timeout = -1;
		dbproc_1->ret_status |= 0x800;
		dbproc_1->CommLayer->bufsize = 4096;
		dbproc_1->CommLayer->lastbufsize = 0;
		dbproc_1->CommLayer->buffer_0 = (BYTE*)AllocateHeapMemory(4, 0, dbproc_1->CommLayer->bufsize, 1);
		dbproc_1->CommLayer->buffer_1 = (BYTE*)AllocateHeapMemory(4, 0, dbproc_1->CommLayer->bufsize, 1);
		if (!dbproc_1->CommLayer->buffer_0 || !dbproc_1->CommLayer->buffer_1)
		{
			GeneralError(dbproc, SQLEMEM);
			FreeMemory(0, lpMem);
			FreeMemory(dbproc_1, dbproc_1->CommLayer);
			HeapDestroy(dbproc_1->hHeap);
			FreeMemory(0, dbproc_1);
			goto ERR_EXIT;
		}
		if (server)
			strcpy(szServer, server);
		else
			szServer[0] = null_string[0];
		dbmove(Src, &dbproc_1->CommLayer->ConnectionObjectSize, 48u);
		FreeMemory(0, Src);
		Src = 0;
		bool LOOP;
		do
		{
			LOOP = false;
			hLibModule = LoadCommLayer(szServer, (void**)&dbproc_1->CommLayer->ConnectionObjectSize, (char*)servername, StrVerdor);
			if (!hLibModule)
			{
				GeneralError(dbproc_1, 10040);
				FreeMemory(0, servername);
				goto ERR_EXIT;
			}
			/*
			*   dbnetlib version 10.0.19041.844
			*   USHORT ConnectionObjectSize(void)
			*	{
			*	  return 1432;
			*	}
			*/
			ConnectionSize = dbproc_1->CommLayer->ConnectionObjectSize();
			pConnObj = AllocateHeapMemory(4, 0, ConnectionSize, 1);
			if (!pConnObj)
				goto ERR_EXIT;
			dbproc_1->conn_object = pConnObj;
			dbproc_1->CommLayer->module = hLibModule;
			if (login->logintime == -1)
				t0 = DbLoginTime;
			else
				t0 = login->logintime;
			while (1)
			{
				result = DbOpenConnection(dbproc_1, pConnObj, servername);
				if (result == 1)
					break;
				t2 = (__time32_t)time(0);
				if (t0)
				{
					if (t2 - t1 > t0)
						break;
				}
				DbSleep(dwMilliseconds);
				dwMilliseconds *= 2;
				if (dwMilliseconds > 1000)
					dwMilliseconds = 1000;
			}
			if (result == 1 || (login->fallback & 1) == 0)
				continue;
			phkResult = 0;
			nSize = 255;
			if (!strcmp(szServer, null_string) || !strcmp(szServer, "."))
			{
				GetComputerNameA(szServer, &nSize);
				szServer[30] = 0;
			}
			nSize = 255;
			strcpy(SubKey, "SOFTWARE\\Microsoft\\MSSQLServer\\Client\\BackupServer");
			strcat(SubKey, "\\");
			strcat(SubKey, szServer);
			if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, SubKey, 0, 0x20019u, &phkResult))
				break;
			int hkResult = RegQueryValueExA(phkResult, "BackupServer", 0, 0, (LPBYTE)szServer, &nSize);
			RegCloseKey(phkResult);
			if (hkResult == ERROR_SUCCESS)
			{
				/*
				* 继续尝试连接 BackupServer
				*/
				LOOP = true;
				t1 = (__time32_t)time(0);
				GeneralError(dbproc_1, SQLECONNFB);
				FreeMemory(0, pConnObj);
				pConnObj = 0;
				dbproc_1->conn_object = 0;
				FreeLibrary(hLibModule);
				hLibModule = 0;
				dbproc_1->CommLayer->module = 0;
			}else
				break;
	
		} while (LOOP);

		if (StrVerdor)
			strcpy(dbproc_1->dbnetlib, StrVerdor);        // "DBNETLIB.DLL"
		else
			dbproc_1->dbnetlib[0] = 0;
		if (servername)
			strcpy(dbproc_1->servername, (const char*)servername);// "LOCALHOST"
		else
			dbproc_1->servername[0] = 0;
		FreeMemory(0, servername);
		if (result != 1)
		{
			GeneralError(dbproc_1, SQLECONN);
			FreeMemory(0, pConnObj);
			FreeMemory(0, lpMem);
			if (dbproc_1->CommLayer)
			{
				FreeMemory(0, dbproc_1->CommLayer->buffer_0);
				FreeMemory(0, dbproc_1->CommLayer->buffer_1);
				FreeMemory(0, dbproc_1->CommLayer);
			}
			HeapDestroy(dbproc_1->hHeap);
			FreeMemory(0, dbproc_1);
			goto ERR_EXIT;
		}
		dbproc_1->cmd_flag = 4;
		dbproc_1->CommLayer->buffer0 = (BYTE*)dbproc_1->CommLayer->buffer_0;
		dbproc_1->CommLayer->buffer1 = (BYTE*)dbproc_1->CommLayer->buffer_1;
		dbproc_1->CommLayer->buffer1[7] = 34; // Window
		dbproc_1->CommLayer->packet_size = 8; // 协议包头长度 8
		dbproc_1->CommLayer->rbytes = 8; // 协议包头长度 8
		packetheader = (PacketHeader *)dbproc_1->CommLayer->buffer1;
		packetheader->Type = 0;
		packetheader->Status = 0;
		packetheader->Length = 0;
		packetheader->SPID = 0;
		packetheader->Packet = 0;
		packetheader->Window = 0;
		packetheader->Type = PT_LOGIN;
		packetheader->Packet = 1;
		if (!login->cbUserName)
			login->cbUserName = (char)GetEnvironmentVariableA("SYBUSER", login->UserName, 30u);
		dbproc_1->ver = 66;
		if (!login->cbRemotePassword && dbrpwset(login, 0, login->Password, login->cbPassword) != 1 || !AddDBProc(dbproc_1))
		{
			DumpDbProc(dbproc_1, lpMem);
			goto ERR_EXIT;
		}
		login->lDBLIBFlags = _stricmp("DBNMPNTW", StrVerdor) && _stricmp("DBMSRPCN", StrVerdor) && (login->lType & 8) != 0;
		bufsize = dbproc_1->CommLayer->bufsize;
		dbproc_1->CommLayer->bufsize = 512;
		/*
		* 发送登录请求协议包
		*/
		if (!queuepacket(dbproc_1, (BYTE*)login, 0x23Cu) || !sendflush(dbproc_1))
		{
			dbproc_1->CommLayer->bufsize = bufsize;
			packetheader->Type = 2;
			GeneralError(dbproc_1, SQLECONN);
			DropDbproc(dbproc_1);
			DumpDbProc(dbproc_1, lpMem);
			goto ERR_EXIT;
		}
		dbproc_1->CommLayer->bufsize = bufsize;
		/*
		* 执行 2个命令 设置 textlimit 和 textsize 均为 4096
		*/
		dbsetopt(dbproc_1, 4, "4096"); // "textlimit"
		dbsetopt(dbproc_1, 5, "4096"); // "textsize"
		dbfreebuf(dbproc_1);
		if (!InitNulls(dbproc_1))
		{
			DropDbproc(dbproc_1);
			DumpDbProc(dbproc_1, lpMem);
			goto ERR_EXIT;
		}
		dbproc_1->cmd_flag &= ~4u;
		/*
		* 查询登录结果
		*/
		while (1)
		{
			result = dbresults(dbproc_1);
			if (result == NO_MORE_RESULTS)
				break;
			if (result == FAIL)
			{
				DropDbproc(dbproc_1);
				DumpDbProc(dbproc_1, lpMem);
				goto ERR_EXIT;
			}
		}
		FreeMemory(0, lpMem);
		if (dbproc_1->ver < 66u)
		{
			GeneralError(dbproc_1, 10105);
			DropDbproc(dbproc_1);
			DumpDbProc(dbproc_1, lpMem);
			goto ERR_EXIT;
		}
		if (dbproc_1->ver == 52)
		{
			dbproc_1->cmd_flag &= ~4u;
			while (1)
			{
				result = dbresults(dbproc_1);
				if (result == NO_MORE_RESULTS)
					break;
				if (result == FAIL)
				{
					DropDbproc(dbproc_1);
					DumpDbProc(dbproc_1, lpMem);
					goto ERR_EXIT;
				}
			}
		}
		else if (dbproc_1->CommLayer->lastbufsize && dbproc_1->CommLayer->lastbufsize != dbproc_1->CommLayer->bufsize)
		{
			if (GetSQLServerVersion(dbproc_1))
				dbproc_1->CommLayer->bufsize = dbproc_1->CommLayer->lastbufsize;
			buf0 = (char*)AllocateHeapMemory(4, 0, dbproc_1->CommLayer->bufsize, 1);
			buf1 = (char*)AllocateHeapMemory(4, 0, dbproc_1->CommLayer->bufsize, 1);
			if (!buf0 || !buf1)
			{
				GeneralError(dbproc_1, SQLEMEM);
				FreeMemory(0, pConnObj);
				FreeMemory(0, lpMem);
				FreeMemory(dbproc_1, dbproc_1->CommLayer);
				HeapDestroy(dbproc_1->hHeap);
				FreeMemory(0, dbproc_1);
				goto ERR_EXIT;
			}
			FreeMemory(0, dbproc_1->CommLayer->buffer_0);
			dbproc_1->CommLayer->buffer_0 = (BYTE*)buf0;
			FreeMemory(0, dbproc_1->CommLayer->buffer_1);
			dbproc_1->CommLayer->buffer_1 = (BYTE*)buf1;
			dbproc_1->CommLayer->buffer0 = (BYTE*)dbproc_1->CommLayer->buffer_0;
			dbproc_1->CommLayer->buffer1 = (BYTE*)dbproc_1->CommLayer->buffer_1;
			dbproc_1->CommLayer->buffer1[7] = 34; // Window
		}
		InitializeCriticalSection(&dbproc_1->cursorSem);
		CheckSQLDebugOnConnect(dbproc_1);
		if ((login->fallback & 1) != 0)
			UpdateFallback(dbproc_1);
		dbproc_1->ansi = 0;
		AnsiOem = GetAnsiOem();
		if (AnsiOem == 2)
		{
			dbclropt(dbproc_1, 14, null_string);
			dbclropt(dbproc_1, 15, null_string);
		}
		else if (AnsiOem == 1)
		{
			if (dbproc_1->ver == 66 && IsServerAnsi(dbproc_1))
				dbproc_1->ansi = 1;
			if (GetConsoleCP())
			{
				if (dbproc_1->ver == 66 && (OptionDict[15].optmask & 0x20) == 0 && dbproc_1->ansi)
					dbsetopt(dbproc_1, 15, null_string);
			}
			else if (dbproc_1->ver == 66 && (OptionDict[14].optmask & 0x20) == 0 && !dbproc_1->ansi)
			{
				dbsetopt(dbproc_1, 14, null_string);
			}
		}
		if (!OptionInit(dbproc_1))
		{
			DropDbproc(dbproc_1);
			DumpDbProc(dbproc_1, lpMem);
			goto ERR_EXIT;
		}
		tidyproc(dbproc_1);
		dbproc_1->isavail = 1;
		dbproc_1->curcmd = 0;
		dbproc_1->change_dirty = 1;
		dbproc_1->dtc_resources = 0;
		if (strcmp(login->ProgVersion, (char*)ver60) >= 0 && dbproc_1->bServerType == 1 && dbproc_1->ServerMajor >= 6u)
		{
			dbproc_1->ret_status |= 0x40;
		}
		dbproc_1->ret_status &= ~0x800u;
		if (dbproc)
			FreeMemory(0, dbproc);
		return dbproc_1;
	}
ERR_EXIT:
	if (Src)
	FreeMemory(0, Src);
	if (hLibModule)
	FreeLibrary(hLibModule);
	if (dbproc)
	FreeMemory(0, dbproc);
	return 0;
}

int __cdecl dbordercol(PDBPROCESS dbproc, int order)
{
	if (!CheckEntry(dbproc))
		return -1;
	if (order >= 1 && order <= dbproc->n_orders && dbproc->ordercols)
		return dbproc->ordercols[order - 1];
	return -1;
}

LPCSTR __cdecl dbprtype(int token)
{
	LPCSTR result = 0;
	int prtType = 0; 

	switch (token)
	{
	case SQLIMAGE:
		prtType = 12;
		break;
	case SQLTEXT:
		prtType = 9;
		break;
	case SQLVARBINARY:
		prtType = 11;
		break;
	case SQLINTN:
		prtType = 13;
		break;
	case SQLVARCHAR:
		prtType = 8;
		break;
	case SQLBINARY:
		prtType = 10;
		break;
	case SQLCHAR:
		prtType = 7;
		break;
	case SQLINT1:
		prtType = 0;
		break;
	case SQLBIT:
		prtType = 6;
		break;
	case SQLINT2:
		prtType = 1;
		break;
	case SQLINT4:
		prtType = 2;
		break;
	case SQLDATETIM4:
		prtType = 22;
		break;
	case SQLFLT4:
		prtType = 24;
		break;
	case SQLMONEY:
		prtType = 3;
		break;
	case SQLDATETIME:
		prtType = 5;
		break;
	case SQLFLT8:
		prtType = 4;
		break;
	case SQLAOPCNT:
		prtType = 19;
		break;
	case SQLAOPSUM:
		prtType = 17;
		break;
	case SQLAOPAVG:
		prtType = 18;
		break;
	case SQLAOPMIN:
		prtType = 20;
		break;
	case SQLAOPMAX:
		prtType = 21;
		break;
	case SQLDECIMAL:
		prtType = 26;
		break;
	case SQLNUMERIC:
		prtType = 25;
		break;
	case SQLFLTN:
		prtType = 16;
		break;
	case SQLMONEYN:
		prtType = 15;
		break;
	case SQLDATETIMN:
		prtType = 14;
		break;
	case SQLMONEY4:
		prtType = 23;
		break;
	default:
		result = null_string;
		return result;
	}
	result = prtypes[prtType];
	return result;
}

/*
* options - DBRPCRECOMPILE
*/

int __cdecl dbrpcinit(PDBPROCESS dbproc, const char* rpcname, __int16 options)
{
	int result = 0;
	int Size = 0; 
	void* lpMem = 0; 
	BYTE* lpMema = 0; 
	char Src[136] = { 0 };

	if (!CheckEntry(dbproc))
		return 0;
	if (dbproc->ver < 0x40u)
		return 0;
	if ((options & DBRPCRESET) != 0)
	{
		if (dbproc->rpcbuffer)
		{
			free_rpcbuffer(dbproc);
			if ((dbproc->ret_status & 0x10) != 0)
				dbcancel(dbproc);
		}
	}
	if (rpcname && strlen(rpcname) > 133)
		return 0;
	if ((options & DBRPCCURSOR) != 0)
	{
		if (rpcname && *rpcname)
			return 0;
		dbproc->ret_status |= 0x8000;

	}
	if ((options & DBRPCRESET) != 0 && (!rpcname || !*rpcname))
		return SUCCEED;
	if ((options & DBRPCCURSOR) == 0 && (!rpcname || !*rpcname))
		return 0;
	if ((dbproc->ret_status & 0x80) == 0 && dbproc->rpcbuffer)
	{
		dbproc->ret_status |= 0x800;
		result = dbrpcsend(dbproc);
		dbproc->ret_status &= ~8u;
		if (!result)
			return 0;
		dbproc->ret_status |= 0x1000;
	}
	if ((options & DBRPCCURSOR) == 0)
	{
		dbproc->rpcbuffer = (buf_node_t*)AllocateHeapMemory(4, dbproc, 0xCu, 1);
		if (!dbproc->rpcbuffer)
			return FreeOnError(lpMem, dbproc);
		strcpy(Src, rpcname);
		Size = strlen(Src);
		if (Size >= 0x100)
			Size = 255;
		lpMema = (BYTE*)AllocateHeapMemory(4, dbproc, Size + 3, 0);
		if (!lpMema)
			return FreeOnError(0, dbproc);
		*lpMema = Size;
		dbmove(Src, lpMema + 1, Size);
		*(WORD*)&lpMema[Size + 1] = options & 0xFFFB; // DBRPCRESET
		dbproc->rpcbuffer->data = lpMema;
		dbproc->rpcbuffer->size = Size + 3;
		dbproc->rpcbuffer->next = 0;
	}
	return SUCCEED;
}
int __cdecl dbrpcexec(PDBPROCESS dbproc)
{
	int result = 0; 

	if (!CheckEntry(dbproc))
		return 0;
	dbproc->exec = 1;
	result = dbrpcsend(dbproc);
	dbproc->exec = 0;
	return result;
}
/*
* Add a parameter to a remote procedure call.
*/
int __cdecl dbrpcparam(PDBPROCESS dbproc, char* paramname, BYTE status, int type, DBINT maxlen, DBINT datalen, BYTE* value)
{
	int result = 0;
	int OK = 0; 
	int SiZ = 0; 
	BYTE* lpMem = 0; 
	char* Sourcec = 0; 
	char* Source = 0; 
	char* Sourcea = 0; 
	char* Sourceb = 0; 
	buf_node_t* rbuf = 0; 
	size_t dwBytes = 0; 
	size_t dwBytesa = 0; 
	int Size = 0; 
	buf_node_t* rpccmd = 0; 
	char* p1 = 0; 
	int dt = type;
	OK = 0;
	p1 = 0;
	if (!CheckEntry(dbproc))
		return 0;
	if ((dbproc->ret_status & 0x80) == 0 && !dbproc->rpcbuffer)
		return 0;
	Size = 0;
	if (paramname)
	{
		Size = strlen(paramname);
		if (*paramname != '@')
			return 0;
	}
	if (!datalen)
		OK = 1;
	switch (type)
	{
	case SQLINT1:
	case SQLBIT:
	case SQLINT2:
	case SQLINT4:
	case SQLDATETIM4:
	case SQLFLT4:
	case SQLMONEY:
	case SQLDATETIME:
	case SQLFLT8:
	case SQLDECIMAL:
	case SQLNUMERIC:
	case SQLMONEY4:
		if (maxlen == -1)
			goto LABEL_14;
		result = 0;
		break;
	default:
	LABEL_14:
		if (type == SQLTEXT || type == SQLIMAGE || datalen <= 0xFF)
		{
			if (Size >= 0x100)
			{
				Size = 255;
				paramname[255] = 0;
			}
			dwBytes = Size + 3;

			switch (type)
			{
			case 0x1F:
				SiZ = 0;
				break;
			case SQLIMAGE:
			case SQLTEXT:
				SiZ = 4;
				if (datalen >= 0)
					break;
				return 0;
			case 0x24:
			case SQLVARBINARY:
			case SQLINTN:
			case SQLVARCHAR:
			case SQLBINARY:
			case SQLCHAR:
			case SQLFLTN:
			case SQLMONEYN:
			case SQLDATETIMN:
				SiZ = 1;
				if (datalen >= 0)
					break;
				return 0;
			case SQLINT1:
				dt = SQLINTN;
				maxlen = 1;
				datalen = 1;
				SiZ = 1;
				break;
			case SQLBIT:
				if (OK)
				{
					GeneralError(dbproc, 10069);
					return 0;
				}
				SiZ = 0;
				datalen = 1;
				break;
			case SQLINT2:
				dt = SQLINTN;
				maxlen = 2;
				datalen = 2;
				SiZ = 1;
				break;
			case SQLINT4:
				dt = SQLINTN;
				maxlen = 4;
				datalen = 4;
				SiZ = 1;
				break;
			case SQLDATETIM4:
				dt = SQLDATETIMN;
				maxlen = 4;
				datalen = 4;
				SiZ = 1;
				break;
			case SQLFLT4:
				dt = SQLFLTN;
				maxlen = 4;
				datalen = 4;
				SiZ = 1;
				break;
			case SQLMONEY:
				dt = SQLMONEYN;
				maxlen = 8;
				datalen = 8;
				SiZ = 1;
				break;
			case SQLDATETIME:
				dt = SQLDATETIMN;
				maxlen = 8;
				datalen = 8;
				SiZ = 1;
				break;
			case SQLFLT8:
				dt = SQLFLTN;
				maxlen = 8;
				datalen = 8;
				SiZ = 1;
				break;
			case SQLDECIMAL:
			case SQLNUMERIC:
				dt = SQLINTN;
				if (OK || (p1 = (char*)value) != 0 && IsNumericValid((BYTE*)value))
				{
					if (p1)
					{
						maxlen = GetMaxNumericBytes(*p1);
						datalen = maxlen;
					}
					else
					{
						maxlen = GetMaxNumericBytes(38);
						datalen = 0;
					}
					SiZ = 1;
					dwBytes = Size + 5;

				}
				else
				{
					GeneralError(dbproc, 10104);
					result = 0;
				}
				break;
			case SQLMONEY4:
				dt = SQLMONEYN;
				maxlen = 4;
				datalen = 4;
				SiZ = 1;
				break;
			default:
				return 0;


			}

			if (OK)
				datalen = 0;
			dwBytesa = datalen + 2 * SiZ + dwBytes;
			lpMem = (BYTE*)AllocateHeapMemory(4, dbproc, dwBytesa, 0);
			if (lpMem)
			{
				*lpMem = Size;
				dbmove((void*)paramname, lpMem + 1, Size);
				Sourcec = (char*)&lpMem[Size + 1];
				Sourcec[0] = status;
				Sourcec[1] = dt;
				Source = Sourcec + 2;
				if (SiZ == 1)
				{
					*Source = maxlen;
					Sourcea = Source + 1;
					if (type == SQLNUMERIC || type == SQLDECIMAL)
					{
						if (OK)
						{
							*Sourcea = SQLINTN;
							Sourceb = Sourcea + 1;
							*Sourceb = 0;
						}
						else
						{
							*Sourcea = *p1;
							Sourceb = Sourcea + 1;
							*Sourceb = p1[1];
						}
						Sourcea = Sourceb + 1;
					}
					*Sourcea = datalen;
					Source = Sourcea + 1;
				}
				else if (SiZ == 4)
				{
					*(_DWORD*)Source = maxlen;
					*((_DWORD*)Source + 1) = datalen;
					Source += 8;
				}
				if (OK)
				{
					dbmove(0, Source, datalen);
				}
				else if (type == SQLNUMERIC || type == SQLDECIMAL)
				{
					dbmove(p1 + 2, Source, datalen);
				}
				else
				{
					dbmove(value, Source, datalen);
					if (type == SQLCHAR || type == SQLVARCHAR || type == SQLTEXT)
						dbWinConvToServer(dbproc, Source, datalen);
				}
				rbuf = (buf_node_t*)AllocateHeapMemory(4, dbproc, 0xCu, 0);
				if (rbuf)
				{
					rbuf->data = lpMem;
					rbuf->size = dwBytesa;
					rbuf->next = 0;
					if ((dbproc->ret_status & 0x80) == 0 || dbproc->rpcbuffer)
					{
						for (rpccmd = dbproc->rpcbuffer; rpccmd->next; rpccmd = rpccmd->next)
							;
						rpccmd->next = rbuf;
					}
					else
					{
						dbproc->rpcbuffer = rbuf;
					}
					result = 1;
				}
				else
				{
					result = FreeOnError(lpMem, dbproc);
				}
			}
			else
			{
				result = FreeOnError(0, dbproc);
			}
		}
		else
		{
			result = 0;
		}
		break;
	}
	return result;
}

BOOL __cdecl dbrpcsend(PDBPROCESS dbproc)
{
	buf_node_t* rpccmd = 0; 
	PacketHeader* packetHeader = 0;
	BYTE status = 128;

	if (!CheckEntry(dbproc))
		return 0;
	if (!dbproc->rpcbuffer)
		return 0;
	if (pMemMap)
		CheckSQLDebug(dbproc);
	if (!dbproc->CommLayer->rbytes)
		dbproc->CommLayer->ConnectionStatus(); // ConnectionStatus(dbproc->conn_object, -1, status) 这是一个空函数
	packetHeader = (PacketHeader*)dbproc->CommLayer->buffer1;
	packetHeader->Type = PT_RPC;
	packetHeader->Status = 0;
	packetHeader->Packet = 0;
	if ((dbproc->ret_status & 8) != 0 && (dbproc->ret_status & 0x10) == 0)
		dbproc->CommLayer->packet_size = 8;
	for (rpccmd = dbproc->rpcbuffer; rpccmd; rpccmd = rpccmd->next)
	{
		if (!queuepacket(dbproc, (BYTE*)rpccmd->data, rpccmd->size))
		{
			free_rpcbuffer(dbproc);
			return 0;
		}
	}
	free_rpcbuffer(dbproc);
	if ((dbproc->ret_status & 8) != 0)
		return queuepacket(dbproc, (BYTE*)&status, 1u) != 0;
	if (!sendflush(dbproc))
		return 0;
	tidyproc(dbproc);
	dbproc->cmd_flag = 0x81;
	dbproc->curcmd = 0;
	dbproc->exec = 0;
	dbproc->token = 0;
	dbproc->rpcbuffer = 0;
	dbproc->change_dirty = 0;
	dbproc->isavail = 0;
	dbproc->ret_status &= ~0x10u;
	dbproc->ret_status &= ~0x80u;
	return SUCCEED;
}

int __cdecl dbclropt(PDBPROCESS dbproc, int option, LPCSTR param)
{
	int OptIndex = 0;
	int i = 0;
	char Str[28] = { 0 };
	if (option == 99)
	{
		dbproc->ret_status &= ~0x400u;
		return SUCCEED;
	}
	OptIndex = GetOptIndex(option);
	if (OptIndex == -1)
	{
		GeneralError(dbproc, 10030);
		return 0;
	}
	if (dbproc)
	{
		if (CheckEntry(dbproc))
		{
			dbproc->isavail = 0;
			return ClearOption(dbproc, option, param);
		}
		else
		{
			return 0;
		}
	}
	else
	{
		EnterCriticalSection(&DbProcSem);
		if (DbProcArray)
		{
			for (i = 0; i < DbMaxProcs; ++i)
			{
				if (DbProcArray[i])
				{
					LeaveCriticalSection(&DbProcSem);
					if (!ClearOption(DbProcArray[i], option, param))
						return 0;
					EnterCriticalSection(&DbProcSem);
				}
			}
		}
		LeaveCriticalSection(&DbProcSem);
		if ((OptionDict[OptIndex].optmask & 4) == 0)
			return 0;
		if ((OptionDict[OptIndex].optmask & 8) != 0)
		{
			if (!param || !*param)
			{
				GeneralError(0, 10033);
				return 0;
			}
			strcpy(Str, param);
			DBCS_STRLWR(Str);
		}
		EnterCriticalSection(&OptionSem);
		OptionDict[OptIndex].optmask ^= 4u;
		OptionDict[OptIndex].optmask |= 0x20u;
		if (option == 3)
		{
			if (!strcmp(Str, "time"))
			{
				if ((OptionDict[OptIndex].option & 1) == 0)
				{
				LABEL_33:
					LeaveCriticalSection(&OptionSem);
					return 0;
				}
				OptionDict[OptIndex].option ^= 1u;
			}
			else
			{
				if ((OptionDict[OptIndex].option & 2) == 0)
					goto LABEL_33;
				OptionDict[OptIndex].option ^= 2u;
			}
		}
		else if (option == 1)
		{
			for (i = 0; i < 9; ++i)
			{
				if (!strcmp(Str, Offsets[i]))
				{
					if (((1 << i) & OptionDict[OptIndex].option) == 0)
						goto LABEL_33;
					OptionDict[OptIndex].option ^= 1 << i;
					break;
				}
			}
		}
		else if ((OptionDict[OptIndex].optmask & 1) != 0)
		{
			if (OptionDict[OptIndex].optname)
			{
				FreeMemory(0, OptionDict[OptIndex].optname);
				OptionDict[OptIndex].optname = 0;
			}
		}
		LeaveCriticalSection(&OptionSem);
		return SUCCEED;
	}
}
LPCSTR __cdecl dbqual(PDBPROCESS dbproc, int ntab, LPCSTR tabname)
{
	__int16 keytype = 0; 
	const char* pSql; 
	int l1 = 0; 
	char* p1 = 0; 
	const char* p2; 
	int l2 = 0; 
	char* p3 = 0; 
	const char* pPri; 
	int l3 = 0; 
	char* p4 = 0; 
	BYTE* data = 0; 
	char* pszSql = 0; 
	int keydata_len = 0;
	int bSucc = 0; 
	int Count = 0; 
	int ColumnPrLength = 0; 
	int l0 = 0; 
	int i1 = 0; 
	int i = 0; 
	int oLength = 0;
	int dType = 0; 
	int ntab1 = 0; 
	column_info_t** coldata = 0; 
	int dwBytes = 0;
	int n_keys = 0; 
	char* Source = 0; 
	void* Src = 0; 

	dwBytes = 6;
	oLength = 16;
	ColumnPrLength = 0;
	if (!CheckEntry(dbproc))
		return 0;
	if (ntab == -1)
		ntab1 = dbtabnum(dbproc, tabname);
	else
		ntab1 = ntab;
	if (ntab1 > dbproc->ntab || ntab1 < 1)
		return 0;
	coldata = dbproc->columns_info;
	if (!coldata || !dbproc->columns_data)
		return 0;
	n_keys = numtabkeys(dbproc, ntab1);
	data = 0;
	for (i = 0; i < dbproc->ncols; ++i)
	{
		if (coldata[i]->ntab == ntab1 && coldata[i]->usertype == SQLTIMESTAMP)
			data = dbproc->columns_data[i]->data;
	}
	if (!n_keys || !data)
		return 0;
	for (i = 1; i <= n_keys; ++i)
	{
		if (i > 1)
			dwBytes += 5;
		dwBytes += 5;
		dType = dbkeytype(dbproc, ntab1, i);
		dbkeyname(dbproc, ntab1, i, &Count);
		dwBytes += Count;
		switch (dType)
		{
		case SQLIMAGE:
		case SQLVARBINARY:
		case SQLBINARY:
			dwBytes += 2;
			break;
		case SQLTEXT:
		case SQLVARCHAR:
		case SQLCHAR:
		case SQLDATETIM4:
		case SQLDATETIME:
		case SQLDATETIMN:
			dwBytes += 7;
			break;
		case SQLMONEY:
		case SQLMONEYN:
		case SQLMONEY4:
			++dwBytes;
			break;
		default:
			break;
		}
		dbkeydata(dbproc, ntab1, i, &keydata_len);

		keytype = dbkeytype(dbproc, ntab1, i);
		ColumnPrLength = GetColumnPrLength(keytype, Count, keydata_len);
		if (ColumnPrLength > oLength)
			oLength = ColumnPrLength;
		dwBytes += ColumnPrLength;
	}
	dwBytes += 80;
	pszSql = (char*)AllocateHeapMemory(3, dbproc, dwBytes, 1);
	if (!pszSql)
		return 0;
	Source = (char*)AllocateHeapMemory(3, dbproc, oLength, 1);
	if (!Source)
	{
		FreeMemory(dbproc, pszSql);
		return 0;
	}
	strcpy(pszSql, "where ");
	for (i = 1; i <= n_keys; ++i)
	{
		bSucc = 0;
		if (i <= 1)
		{
			pSql = "(";
			l1 = strlen("(") + 1;
			p1 = &pszSql[strlen(pszSql) + 1];
		}
		else
		{
			pSql = " and (";
			l1 = strlen(" and (") + 1;
			p1 = &pszSql[strlen(pszSql) + 1];
		}
		qmemcpy(p1 - 1, pSql, l1);
		strcat(pszSql, dbkeyname(dbproc, ntab1, i, &Count));
		strcat(pszSql, " = ");
		dType = dbkeytype(dbproc, ntab1, i);
		Src = (void*)dbkeydata(dbproc, ntab1, i, &keydata_len);
		if (!keydata_len)
		{
			p2 = "NULL";
			l2 = strlen("NULL") + 1;
			p3 = &pszSql[strlen(pszSql) + 1];
		LABEL_60:
			qmemcpy(p3 - 1, p2, l2);
			goto LABEL_61;
		}
		switch (dType)
		{
		case SQLIMAGE:
		case SQLVARBINARY:
		case SQLBINARY:
			pPri = "0x";
			l3 = strlen("0x") + 1;
			p4 = &pszSql[strlen(pszSql) + 1];
			qmemcpy(p4 - 1, pPri, l3);
			break;
		case SQLTEXT:
		case SQLVARCHAR:
		case SQLCHAR:
		case SQLDATETIM4:
		case SQLDATETIME:
		case SQLDATETIMN:
			strcat(pszSql, "'");
			bSucc = 1;
			break;
		case SQLMONEY:
		case SQLMONEYN:
		case SQLMONEY4:
			pPri = "$";
			l3 = strlen("$") + 1;
			p4 = &pszSql[strlen(pszSql) + 1];
			qmemcpy(p4 - 1, pPri, l3);
			break;
		default:
			break;
		}
		Count = ConvertToChar_Local(dbproc, dType, (char*)Src, keydata_len, SQLCHAR, Source, oLength, 0, 3);
		if (dType == SQLTEXT || dType == SQLVARCHAR || dType == SQLCHAR)
		{
			i1 = 0;
			l0 = strlen(pszSql);
			while (i1 < Count)
			{
				if (Source[i1] == SQLVARCHAR)
					pszSql[l0++] = SQLVARCHAR;
				pszSql[l0++] = Source[i1++];
			}
			pszSql[l0] = 0;
		}
		else
		{
			strncat(pszSql, Source, Count);
		}
		if (bSucc)
		{
			p2 = "'";
			l2 = strlen(p2) + 1;
			p3 = &pszSql[strlen(pszSql) + 1];
			goto LABEL_60;
		}
	LABEL_61:
		strcat(pszSql, ")");
	}
	if (strlen(pszSql) > 6)
		strcat(pszSql, " and");
	strcat(pszSql, " tsequal(");
	strcat(pszSql, (const char*)dbtsname(dbproc, ntab1));
	strcat(pszSql, ", 0x");
	Count = ConvertToChar_Local(dbproc, SQLBINARY, (char*)data, 8, SQLCHAR, Source, oLength, 0, 3);
	strncat(pszSql, Source, Count);
	strcat(pszSql, ")");
	FreeMemory(0, Source);
	return pszSql;
}

BOOL __cdecl dbdataready(PDBPROCESS dbproc)
{
	commlayer_t* CommLayer = 0;
	int result = 0; 

	if (!CheckEntry(dbproc))
		return 0;
	CommLayer = dbproc->CommLayer;
	if (CommLayer->status == 3 || CommLayer->status == 1)
		return 0;
	if (CommLayer->rbytes < CommLayer->length)
		return SUCCEED;
	if ((dbproc->ret_status & 0x20) != 0 && (dbproc->cmd_flag & 0x40) == 0 && dbproc->severity_level != 3)
		return SUCCEED;
	if (dbproc->severity_level != 2 && dbproc->severity_level != 3 && (dbproc->cmd_flag & 4) == 0 || (dbproc->cmd_flag & 2) != 0)
	{
		;
	}
	else {
	
		if (!dbproc->curcmd && (dbproc->cmd_flag & 0x40) != 0)
			return SUCCEED;
		if (dbproc->curcmd && (dbproc->cmd_flag & 0x40) != 0)
		{
			if (dbproc->severity_level == 2)
				return SUCCEED;
			if (dbproc->severity_level == 3)
				return SUCCEED;
		}
		if ((dbproc->cmd_flag & 2) == 0 && (dbproc->cmd_flag & 4) != 0)
			return SUCCEED;
	}

	if (dbproc->severity_level == 3 && (dbproc->cmd_flag & 4) != 0)
		return SUCCEED;
	if (DataReadySleep != -1)
		DbSleep(DataReadySleep);

	return DbCheckConnectionForData(dbproc, &result) == 1 && result > 0;
}


int __cdecl dbreadpage(PDBPROCESS dbproc, const char* dbname, int fileid, int pageid, LPBYTE* buf)
{
	int result = 0; 
	char Buffer[20] = { 0 };
	char Src1[100] = { 0 };
	int Size = 0; 
	int hold = 0; 
	int Status = 0; 

	if (!CheckEntry(dbproc))
		return -1;
	if (pageid < 0 || !dbname || !buf)
	{
		GeneralError(dbproc, SQLEPARM);
		return -1;
	}
	if ((dbproc->cmd_flag & 4) == 0 || dbproc->severity_level != EXUSER)
	{
		GeneralError(dbproc, 10038);
		return -1;
	}
	sprintf(Buffer, "%d, %d", fileid, pageid);
	strcpy((char*)Src1, "dbcc dbrepair (");
	strcat((char*)Src1, dbname);
	strcat((char*)Src1, ", readpage, ");
	strcat((char*)Src1, Buffer);
	strcat((char*)Src1, ")");
	tidyproc(dbproc);
	dbfreebuf(dbproc);
	dbproc->curcmd = 0;
	if (!queuepacket(dbproc, (BYTE*)Src1, strlen((const char*)Src1)))
		return -1;
	if (!sendflush(dbproc))
		return -1;
	dbproc->token = getbyte(dbproc, (BYTE*)&Status);
	if (!Status)
		return -1;
	if ((dbproc->token == SQLINFO || dbproc->token == SQLERROR) && !pageerror(dbproc))
	{
		if (dbproc->token == SQLDONE)
			pagedone(dbproc);
		return -1;
	}
	if (dbproc->token == SQLDONE)
	{
		if (pagedone(dbproc))
		{
			// "General SQL Server error: Check messages from the SQL Server."
			GeneralError(dbproc, SQLESMSG);
		}
		return -1;
	}
	if (dbproc->token != 0x60)
	{
		// "Possible network error: Bad token from SQL Server: Datastream processing out of sync."
		GeneralError(dbproc, SQLEBTOK);
		return -1;
	}
	if (dbproc->CommLayer->rbytes
		&& dbproc->CommLayer->wbytes >= 4u
		&& dbproc->CommLayer->length - dbproc->CommLayer->rbytes >= 4)
	{
		memmove(&Size, &dbproc->CommLayer->buffer0[dbproc->CommLayer->rbytes], 4u);
		dbproc->CommLayer->rbytes += 4;
		dbproc->CommLayer->wbytes -= 4;
		result = 1;
	}
	else
	{
		result = getbytes_internal(dbproc, (BYTE*)&Size, 4);
	}
	if (!result)
		return -1;
	Size -= 4;
	if (dbproc->CommLayer->rbytes
		&& dbproc->CommLayer->wbytes >= 4u
		&& dbproc->CommLayer->length - dbproc->CommLayer->rbytes >= 4)
	{
		memmove(&hold, &dbproc->CommLayer->buffer0[dbproc->CommLayer->rbytes], 4u);
		dbproc->CommLayer->rbytes += 4;
		dbproc->CommLayer->wbytes -= 4;
		result = 1;
	}
	else
	{
		result = getbytes_internal(dbproc, (BYTE*)&hold, 4);
	}
	if (!result)
		return -1;
	if (dbproc->CommLayer->rbytes
		&& (int)Size <= dbproc->CommLayer->wbytes
		&& (int)Size <= dbproc->CommLayer->length - dbproc->CommLayer->rbytes)
	{
		memmove(buf, &dbproc->CommLayer->buffer0[dbproc->CommLayer->rbytes], Size);
		dbproc->CommLayer->rbytes += Size;
		dbproc->CommLayer->wbytes -= Size;
		result = 1;
	}
	else
	{
		result = getbytes_internal(dbproc, (BYTE*)buf, Size);
	}
	if (!result)
		return -1;
	dbproc->token = getbyte(dbproc, (BYTE*)&Status);
	if (!Status)
		return -1;
	if (dbproc->token != SQLINFO && dbproc->token != SQLERROR || pageerror(dbproc))
	{
		if (dbproc->token == SQLDONE)
		{
			if (!pagedone(dbproc))
				return -1;
			if (dbproc->severity_level == EXNONFATAL)
				return -1;
			return Size;
		}
		// "Possible network error: Bad token from SQL Server: Datastream processing out of sync."
		GeneralError(dbproc, SQLEBTOK);
		return -1;
	}
	if (dbproc->token == SQLDONE)
		pagedone(dbproc);
	return -1;
}
BOOL __cdecl dbrows(PDBPROCESS dbproc)
{
	return dbproc && !dbproc->bclosed && (dbproc->cmd_flag & 0x20) != 0;
}
int __cdecl dbrowtype(PDBPROCESS dbproc)
{
	if (dbproc && !dbproc->bclosed)
		return dbproc->rowtype;
	else
		return 0;
}
void __cdecl dbsetavail(PDBPROCESS dbproc)
{
	int result = 0; 

	result = CheckEntry(dbproc);
	if (result)
		dbproc->isavail = 1;
	return ;
}
int __cdecl dbsetlogintime(int seconds)
{
	if (seconds >= 0)
	{
		DbLoginTime = seconds;
		return SUCCEED;
	}
	else
	{
		GeneralError(0, 10028);
		return 0;
	}
}
int __cdecl dbsetmaxprocs(__int16 n)
{
	int Count = 0;
	int i = 0;
	PDBPROCESS* ppproc = 0; 

	Count = 0;
	i = 0;
	if (n >= 1)
	{
		EnterCriticalSection(&DbProcSem);
		if (n < DbMaxProcs && DbProcArray)
		{
			while (i < DbMaxProcs)
			{
				if (DbProcArray[i++])
					++Count;
			}
			if (Count > n)
			{
				LeaveCriticalSection(&DbProcSem);
				return 0;
			}
		}
		ppproc = (PDBPROCESS*)AllocateHeapMemory(4, 0, 4 * n, 1);
		if (!ppproc)
		{
			LeaveCriticalSection(&DbProcSem);
			return 0;
		}
		else
		{
			i = 0;
			Count = 0;
			if (DbProcArray)
			{
				while (Count < DbMaxProcs)
				{
					if (DbProcArray[Count])
						ppproc[i++] = DbProcArray[Count];
					++Count;
				}
				FreeMemory(0, DbProcArray);
				DbProcArray = ppproc;
			}
			else
			{
				DbProcArray = ppproc;
			}
			DbMaxProcs = n;
			LeaveCriticalSection(&DbProcSem);
			return SUCCEED;
		}
	}
	else
	{
		GeneralError(0, 10073);
		return 0;
	}
}
int __cdecl dbsetnull(PDBPROCESS dbproc, int bindtype, int bindlen, LPCBYTE bindval)
{
	int result = 0;
	int bindSiZ = 0;
	null_value_t* nulls = 0;
	DBVARYCHAR* pVar = 0;
	if (!CheckEntry(dbproc))
		return 0;
	if (!bindval)
		return 0;
	dbproc->isavail = 0;
	nulls = dbproc->nulls;
	bindSiZ = bindlen;
	switch (bindtype)
	{
	case CHARBIND:
	case BINARYBIND:
		if (bindlen >= 1)
		{
			bindSiZ = bindlen;
			goto LABEL_12;
		}
		return 0;
	case STRINGBIND:
	case NTBSTRINGBIND:
		bindSiZ = strlen((const char*)bindval) + 1;
		goto LABEL_12;
	case VARYCHARBIND:
		bindSiZ = *(__int16*)bindval + 2;
		goto LABEL_12;
	case VARYBINBIND:
		bindSiZ = *(__int16*)bindval + 2;
		goto LABEL_12;
	default:
	LABEL_12:
		switch (bindtype)
		{
		case CHARBIND:
		case BINARYBIND:
		case STRINGBIND:
		case NTBSTRINGBIND:
		case VARYCHARBIND:
		case VARYBINBIND:
			pVar = (DBVARYCHAR*)AllocateHeapMemory(4, dbproc, bindSiZ, 1);
			if (pVar)
				goto LABEL_15;
			result = 0;
			break;
		default:
		LABEL_15:
			switch (bindtype)
			{
			case TINYBIND:
				nulls->ntiny = *bindval;
				result = 1;
				break;
			case SMALLBIND:
				nulls->nsmall = *(WORD*)bindval;
				result = 1;
				break;
			case INTBIND:
				nulls->nint = *(_DWORD*)bindval;
				result = 1;
				break;
			case CHARBIND:
				if (nulls->p_nchar)
					FreeMemory(dbproc, nulls->p_nchar);
				nulls->nchar_length = bindSiZ;
				dbmove((void*)bindval, pVar, bindSiZ);
				nulls->p_nchar = (char*)pVar;
				result = 1;
				break;
			case BINARYBIND:
				if (nulls->p_nbinary)
					FreeMemory(dbproc, nulls->p_nbinary);
				nulls->nbinary_length = (short)bindSiZ;
				nulls->p_nbinary = pVar;
				dbmove((void*)bindval, pVar, bindSiZ);
				result = 1;
				break;
			case BITBIND:
				nulls->nbit = *bindval;
				result = 1;
				break;
			case DATETIMEBIND:
				dbmove((void*)bindval, &nulls->ndatetime, 8u);
				result = 1;
				break;
			case MONEYBIND:
				dbmove((void*)bindval, &nulls->nmoney, 8u);
				result = 1;
				break;
			case FLT8BIND:
				nulls->nfloat8 = *(double*)bindval;
				result = 1;
				break;
			case STRINGBIND:
				if (nulls->p_nstring)
					FreeMemory(dbproc, nulls->p_nstring);
				strcpy((char*)pVar, (const char*)bindval);
				nulls->p_nstring = (char*)pVar;
				result = 1;
				break;
			case NTBSTRINGBIND:
				if (nulls->p_ntbstring)
					FreeMemory(dbproc, nulls->p_ntbstring);
				strcpy((char*)pVar, (const char*)bindval);
				nulls->p_ntbstring = (char*)pVar;
				result = 1;
				break;
			case VARYCHARBIND:
				if (nulls->p_nvarychar)
					FreeMemory(dbproc, nulls->p_nvarychar);
				dbmove((void*)bindval, pVar, bindSiZ);
				nulls->p_nvarychar = pVar;
				result = 1;
				break;
			case VARYBINBIND:
				if (nulls->p_nvarybin)
					FreeMemory(dbproc, nulls->p_nvarybin);
				dbmove((void*)bindval, pVar, bindSiZ);
				nulls->p_nvarybin = (DBVARYBIN*)pVar;
				result = 1;
				break;
			case FLT4BIND:
				dbmove((void*)bindval, &nulls->nfloat4, 4u);
				result = 1;
				break;
			case SMALLMONEYBIND:
				dbmove((void*)bindval, &nulls->nsmallmoney, 4u);
				result = 1;
				break;
			case SMALLDATETIBIND:
				dbmove((void*)bindval, &nulls->nsmalldate, 4u);
				result = 1;
				break;
			case DECIMALBIND:
			case SRCDECIMALBIND:
				memcpy(&nulls->ndecimal, bindval, 19u);
				result = 1;
				break;
			case NUMERICBIND:
			case SRCNUMERICBIND:
				memcpy(&nulls->nnumeric, bindval, 19u);
				result = 1;
				break;
			default:
				GeneralError(dbproc, 10041);
				result = 0;
				break;
			}
			break;
		}
		break;
	}
	return result;
}

int __cdecl dbsetlname(db_login_t* login, LPCSTR Source, int which)
{
	int result = 0;
	char fb[4] = { 0 };
	int Count = 0;
	int T, L;
	if (login)
	{
		if (which == DBSETLOGINTIME || (!Source ? (L = 0) : (L = strlen(Source)), Count = L, L <= 30))
		{
			switch (which)
			{
			case DBSETHOST:
				dbzero(login, 30);
				strncpy(login->HostName, Source, Count);
				login->cbHostName = (char)Count;
				return SUCCEED;
			case DBSETUSER:
				dbzero(login->UserName, 30);
				strncpy(login->UserName, Source, Count);
				login->cbUserName = (char)Count;
				return SUCCEED;
			case DBSETPWD:
				dbzero(login->Password, 30);
				strncpy(login->Password, Source, Count);
				login->cbPassword = (char)Count;
				return SUCCEED;
			case DBSETAPP:
				dbzero(login->AppName, 30);
				strncpy(login->AppName, Source, Count);
				login->cbAppName = (char)Count;
				return SUCCEED;
			case DBSETID:
				if (Count > 8)
					Count = 8;
				dbzero(login->HostProc, 8u);
				strncpy(login->HostProc, Source, Count);
				login->cbHostProc = (char)Count;
				return SUCCEED;
			case DBSETLANG:
				dbzero(login->Language, 30);
				strncpy(login->Language, Source, Count);
				login->cbLanguage = (char)Count;
				return SUCCEED;
			case DBSETSECURE:
				login->lType |= 8u;
				return SUCCEED;
			case DBVER42:
				return SUCCEED;
			case DBVER60:
				dbmove(ver60, login->ProgVersion, 4u);
				return SUCCEED;
			case DBSETLOGINTIME:
				T = (int)Source;
				if (T > 1200 && T != -1)
				{
					GeneralError(0, SQLEPARM);
					return 0;
				}
				login->logintime = T;
				return SUCCEED;
			case DBSETPACKET:
				dbmove((void*)Source, login->AppType, 6u);
				return SUCCEED;
			case DBSETFALLBACK:
				if (Source && strlen(Source) <= 3)
				{
					strcpy(fb, Source);
					DBCS_STRLWR(fb);
					if (!strcmp(fb, "on") || !strcmp(fb, "off"))
					{
						if (!strcmp(fb, "on"))
							login->fallback |= 1;
						else
							login->fallback &= SQLDONEPROC;
						result = 1;
					}
					else
					{
						GeneralError(0, SQLEPARM);
						result = 0;
					}
				}
				else
				{
					GeneralError(0, SQLEPARM);
					result = 0;
				}
				break;
			default:
				GeneralError(0, 10032);
				return 0;
			}
		}
		else
		{
			GeneralError(0, 10023);
			return 0;
		}
	}
	else
	{
		GeneralError(0, 10031);
		return 0;
	}
	return result;
}

int dbsetopt(PDBPROCESS dbproc, int option, LPCSTR param)
{
	int idx = 0;
	int i = 0;
	char Destination[28] = { 0 };

	if (option == 99)
	{
		dbproc->ret_status |= 0x400;

		SetUsDtmDefaults();
		return SUCCEED;
	}
	idx = GetOptIndex(option);
	if (idx == -1)
	{
		GeneralError(dbproc, 10030);
		return 0;
	}
	if (dbproc)
	{
		if (CheckEntry(dbproc))
		{
			dbproc->isavail = 0;
			return SetDBOption(dbproc, option, param);
		}
		else
		{
			return 0;
		}
	}
	else
	{
		EnterCriticalSection(&DbProcSem);
		if (DbProcArray)
		{
			for (i = 0; i < DbMaxProcs; ++i)
			{
				if (DbProcArray[i])
				{
					LeaveCriticalSection(&DbProcSem);
					if (!SetDBOption(DbProcArray[i], option, param))
						return 0;
					EnterCriticalSection(&DbProcSem);
				}
			}
		}
		LeaveCriticalSection(&DbProcSem);
		if ((OptionDict[idx].optmask & 1) != 0)
		{
			if (!param || !*param)
			{
				GeneralError(0, 10033);
				return 0;
			}
			strncpy(Destination, param, 0x19u);
			Destination[24] = 0;
			DBCS_STRLWR(Destination);
		}
		EnterCriticalSection(&OptionSem);
		OptionDict[idx].optmask |= 4u;
		if ((OptionDict[idx].optmask & 0x20) != 0)
			OptionDict[idx].optmask ^= 0x20u;
		if (option == 3)
		{
			short op = OptionDict[idx].option;
			if (!strcmp(Destination, "time"))
				op = op | 1;
			else
				op = op | 2;
			OptionDict[idx].option = op;
		}
		else if (option == 1)
		{
			for (i = 0; i < 9; ++i)
			{
				if (!strcmp(Destination, Offsets[i]))
				{
					OptionDict[idx].option |= 1 << i;
					break;
				}
			}
		}
		else if ((OptionDict[idx].optmask & 1) != 0)
		{
			if (OptionDict[idx].optname)
			{
				FreeMemory(0, OptionDict[idx].optname);
				OptionDict[idx].optname = 0;
			}
			OptionDict[idx].optname = (char*)AllocateHeapMemory(4, 0, strlen(Destination) + 1, 1);
			if (!OptionDict[idx].optname)
			{
				LeaveCriticalSection(&OptionSem);
				return FreeOnError(0, 0);
			}
			strcpy((char*)OptionDict[idx].optname, Destination);
		}
		LeaveCriticalSection(&OptionSem);
		return SUCCEED;
	}
}
int __cdecl dbsettime(int seconds)
{
	if (seconds >= 0)
	{
		DbTimeOut = seconds;
		return SUCCEED;
	}
	else
	{
		GeneralError(0, 10028);
		return 0;
	}
}
/*
* Send a command batch to the server. 
* 
* Return value SUCCEED or FAIL.
*/
int __cdecl dbsqlexec(PDBPROCESS dbproc)
{
	if (!CheckEntry(dbproc))
		return 0;
	dbproc->exec = 1;
	if (dbsqlsend(dbproc))
		return dbsqlok(dbproc);
	dbproc->exec = 0;
	return FAIL;
}
/*
* Wait for results from the server and verify the correctness of the instructions 
* the server is responding to.
* 
* Return value SUCCEED or FAIL.
*/
int __cdecl dbsqlok(PDBPROCESS dbproc)
{

	BYTE msk = 0;
	int result = 0;
	int t = 0;
	int Size = 0;
	void* lpMem = 0;
	int flag = 0;
	int done = 0;
	BYTE dType = 0;
	size_t dwBytes = 0;

	lpMem = 0;
	dwBytes = 0;
	t = 1;
	done = 1;
	flag = 0;
	if (!CheckEntry(dbproc))
		return 0;
	dbproc->cmd_flag &= ~0x80u;
	if ((dbproc->cmd_flag & 4) != 0)
	{
		GeneralError(dbproc, 10038);
		return 0;
	}
	dwBytes = dbproc->CommLayer->bufsize;
	Size = dwBytes;
	lpMem = AllocateHeapMemory(4, dbproc, dwBytes, 1);
	if (!lpMem)
		return FreeOnError(0, dbproc);
	dbproc->DoneRowCount = 0;
	dbproc->severity_level = 0;
	dbproc->isavail = 0;
	while (2)
	{
		dType = 0;
		dbproc->token = 0;
		dType = getbyte(dbproc, (BYTE*)&done);
		dbproc->token = dType;
		if (!done)
		{
			if ((dbproc->opmask & 8) == 0)
			{
				dbproc->token = 0;
				return FreeOnError(lpMem, dbproc);
			}
			flag = 1;
			dbproc->opmask &= ~8u;
			if (!dbdataready(dbproc))
			{
				tidyproc(dbproc);
				dbproc->token = 0;
				dbproc->isavail = 1;
				return 0;
			}
			t = 0;
		}
		switch (dType)
		{
		case SQLOFFSET:
		case SQLRETURNSTATUS:
		case SQLERROR:
		case SQLINFO:
		case SQLRETURNVALUE:
		case SQLENVCHANGE:
		case SQLDONE:
		case SQLDONEPROC:
		case SQLDONEINPROC:
			if (gettokenlen(dbproc, dType, (BYTE*)&Size))
				goto LABEL_17;
			return CheckTimeoutAndReturn(dbproc, 0);
		default:
		LABEL_17:
			if ((int)Size > (int)dwBytes)
			{
				FreeMemory(dbproc, lpMem);
				dwBytes = Size;
				lpMem = AllocateHeapMemory(4, dbproc, Size, 1);
				if (!lpMem)
					return FreeOnError(0, dbproc);
			}
			break;
		}
		switch (dType)
		{
		case OLD_SQLCOLFMT:
		case SQLPROCID:
		case SQLCOLFMT:
		case SQLTABNAME:
		case SQLCOLINFO:
		case SQLALTNAME:
		case SQLALTFMT:
		case SQLORDER:
		case SQLCONTROL:
		case SQLALTCONTROL:
			goto LABEL_84;
		case SQLOFFSET:
			if (!GetOffsetInfo(dbproc))
				goto LABEL_40;
			goto LABEL_90;
		case SQLRETURNSTATUS:
			if (GetReturnStatus(dbproc, Size))
				goto LABEL_90;
			goto LABEL_40;
		case SQLCOLNAME:
		case SQLROW:
		case SQLALTROW:
			dbproc->cmd_flag |= 0x10u;
			goto LABEL_84;
		case SQLERROR:
			t = 0;
			dbproc->severity_level = EXNONFATAL;
			goto LABEL_22;
		case SQLINFO:
		LABEL_22:
			if (dbproc->CommLayer->rbytes
				&& (int)Size <= dbproc->CommLayer->wbytes
				&& (int)Size <= dbproc->CommLayer->length - dbproc->CommLayer->rbytes)
			{
				memmove(lpMem, &dbproc->CommLayer->buffer0[dbproc->CommLayer->rbytes], Size);
				dbproc->CommLayer->rbytes += (ushort)Size;
				dbproc->CommLayer->wbytes -= (ushort)Size;
				result = 1;
			}
			else
			{
				result = getbytes_internal(dbproc, (BYTE*)lpMem, Size);
			}
			if (result)
				goto LABEL_33;
			if ((dbproc->opmask & 8) == 0)
			{
				result = FreeOnError(lpMem, dbproc);
				return CheckTimeoutAndReturn(dbproc, result);
			}
			flag = 1;
			dbproc->opmask &= ~8u;
			if (!dbdataready(dbproc))
			{
				tidyproc(dbproc);
				dbproc->token = 0;
				dbproc->isavail = 1;
				FreeMemory(dbproc, lpMem);
				return CheckTimeoutAndReturn(dbproc, 0);
			}
			t = 0;
		LABEL_33:
			PrintMessage(dbproc, (char*)lpMem, Size);
			goto LABEL_90;
		case SQLRETURNVALUE:
			if (GetReturnVal(dbproc, Size))
				goto LABEL_90;
		LABEL_40:
			FreeMemory(dbproc, lpMem);
			return CheckTimeoutAndReturn(dbproc, 0);
		case SQLDONE:
		case SQLDONEPROC:
		case SQLDONEINPROC:
			if (dType == SQLDONE && (t || flag))
				goto LABEL_84;
			if (dbproc->CommLayer->rbytes
				&& dbproc->CommLayer->wbytes >= 8u
				&& dbproc->CommLayer->length - dbproc->CommLayer->rbytes >= 8)
			{
				memmove(lpMem, &dbproc->CommLayer->buffer0[dbproc->CommLayer->rbytes], 8u);
				dbproc->CommLayer->rbytes += 8;
				dbproc->CommLayer->wbytes -= 8;
				result = 1;
			}
			else
			{
				result = getbytes_internal(dbproc, (BYTE*)lpMem, 8);
			}
			if (!result)
				return FreeOnError(lpMem, dbproc);
			if ((*(WORD*)lpMem & 0x10) != 0)
			{
				dbproc->DoneRowCount = *((_DWORD*)lpMem + 1);
				msk = dbproc->opmask | 1;
			}
			else
			{
				msk = dbproc->opmask & SQLDONEPROC;
			}
			dbproc->opmask = msk;
			if ((*(WORD*)lpMem & 2) != 0)
			{
				// "General SQL Server error: Check messages from the SQL Server."
				GeneralError(dbproc, SQLESMSG);
				t = 0;
			}
			if ((*(WORD*)lpMem & 1) == 0 || (*(WORD*)lpMem & 0x80) != 0)
			{
				if ((*(WORD*)lpMem & 0x80) != 0)
				{
					dbproc->ret_status |= 0x20;

				}
				if ((*(WORD*)lpMem & 1) != 0)
					msk = dbproc->cmd_flag | 0x10;
				else
					msk = dbproc->cmd_flag & 0xEF;
				dbproc->cmd_flag = msk;
				if ((dbproc->cmd_flag & 2) != 0)
				{
					if ((*(WORD*)lpMem & 0x20) != 0)
					{
						dbproc->cmd_flag &= ~2u;
						if (dType == SQLDONE)
						{
							dbproc->severity_level = EXUSER;
							dbproc->cmd_flag &= ~8u;
							dbproc->cmd_flag |= 4u;
						}
					}
					else
					{
						dbproc->cmd_flag |= 8u;
					}
					if (dType != SQLDONE)
						dbproc->severity_level = 0;
				}
				else
				{
					if (dbproc->severity_level != EXNONFATAL)
					{
						dbproc->severity_level = EXUSER;
						dbproc->cmd_flag |= 0x40u;
					}
					dbproc->cmd_flag &= ~8u;
					dbproc->cmd_flag |= 4u;
				}
				dbproc->token = 0;
				FreeMemory(dbproc, lpMem);
				return CheckTimeoutAndReturn(dbproc, t);
			}
			dbproc->cmd_flag |= 0x10u;
			if ((*(WORD*)lpMem & 0x20) == 0 || (*(WORD*)lpMem & 1) != 0)
			{
				if (dType == SQLDONE)
				{
					FreeMemory(dbproc, lpMem);
					dbproc->token = 0;
					return CheckTimeoutAndReturn(dbproc, t);
				}
			LABEL_90:
				dbproc->token = 0;
				continue;
			}
			dbproc->cmd_flag &= ~2u;
			if ((dbproc->cmd_flag & 8) != 0)
			{
				dbproc->cmd_flag &= ~8u;
				if (dbproc->severity_level != EXNONFATAL)
				{
					dbproc->severity_level = EXUSER;
					dbproc->cmd_flag |= 0x40u;
				}
				dbproc->cmd_flag |= 4u;
				dbproc->token = 0;
			}
		LABEL_84:
			FreeMemory(dbproc, lpMem);
			return CheckTimeoutAndReturn(dbproc, t);
		default:
			if (HandlerEnvChange(dbproc, dType, Size))
				goto LABEL_90;
			// "Possible network error: Bad token from SQL Server: Datastream processing out of sync."
			GeneralError(dbproc, SQLEBTOK);
			result = FreeOnError(lpMem, dbproc);
			return CheckTimeoutAndReturn(dbproc, result);
		}
	}
}

/*
* Send a command batch to the server and do not wait for a response. 
* 
* Return value SUCCEED or FAIL.
*/

int __cdecl dbsqlsend(PDBPROCESS dbproc)
{
	int result = 0;
	int timeout = 0;
	PacketHeader* packetHeader = 0;
	buf_node_t* packet_next = 0;

	if (!CheckEntry(dbproc))
		return 0;
	if (pMemMap)
		CheckSQLDebug(dbproc);
	dbproc->cmd_flag |= 1u;
	if ((dbproc->cmd_flag & 4) != 0)
	{
		packet_next = dbproc->cmdbuffer;
		if (packet_next)
		{
			packetHeader = (PacketHeader*)dbproc->CommLayer->buffer1;
			if (dbproc->ver < 0x40u)
				packetHeader->Type = 0x46;
			else
				packetHeader->Type = PT_SQLBATCH;
			while (packet_next)
			{
				if (packet_next->size && !queuepacket(dbproc, (BYTE*)packet_next->data, packet_next->size))
					return 0;
				packet_next = packet_next->next;
			}
			if (sendflush(dbproc))
			{
				if (dbproc->exec)
				{
					if (dbproc)
					{
						if (dbisopt(dbproc, 17, 0))
							timeout = dbproc->timeout;
						else
							timeout = DbTimeOut;
						result = timeout;
					}
					else
					{
						result = DbTimeOut;
					}
					if (result)
					{
						dbproc->CommLayer->rbytes = 8;
						dbproc->CommLayer->length = 0;
						dbproc->CommLayer->wbytes = 0;
						if (dbproc->ver < 0x40u)
							*dbproc->CommLayer->buffer1 = 0x46;
						else
							*dbproc->CommLayer->buffer1 = PT_SQLBATCH;
					}
					dbproc->exec = 0;
				}
				dbproc->token = 0;
				tidyproc(dbproc);
				dbproc->cmd_flag = 0x81;
				dbproc->curcmd = 0;
				if (dbproc->ver < 0x40u)
					*dbproc->CommLayer->buffer1 = 0x46;
				else
					*dbproc->CommLayer->buffer1 = PT_SQLBATCH;
				dbproc->change_dirty = 0;
				dbproc->isavail = 0;
				return SUCCEED;
			}
			else
			{
				return 0;
			}
		}
		else
		{
			GeneralError(dbproc, 10022);
			return 0;
		}
	}
	else
	{
		GeneralError(dbproc, 10038);
		return 0;
	}
}
/*
* Copy all or a portion of the command buffer. 
* 
* Return value SUCCEED or FAIL
*/
int __cdecl dbstrcpy(PDBPROCESS dbproc, int start, int numbytes, LPSTR dest)
{
	int bSucc = 0; 
	int offset = 0; 
	int l1 = 0; 
	int l2 = 0; 
	int Size = 0; 
	buf_node_t* next = 0; 

	if (dest)
	{
		bSucc = getcmdbuffer(dbproc, start, &next, &offset);
		if (bSucc && next)
		{
			l1 = 0;
			if (numbytes >= 0)
				l2 = numbytes;
			else
				l2 = -1;
			while (next && l1 < l2)
			{
				Size = next->size - offset;
				if (Size + l1 > l2)
					Size = l2 - l1;
				dbmove((char*)next->data + offset, &dest[l1], Size);
				offset = 0;
				l1 += Size;
				next = next->next;
			}
			dest[l1] = 0;
			return SUCCEED;
		}
		else
		{
			*(BYTE*)dest = 0;
			return bSucc;
		}
	}
	else
	{
		GeneralError(dbproc, 10036);
		return 0;
	}
}
/*
* Return the length, in characters, of the command buffer.
* 
* Return value 
* The length, in characters, of the command buffer.
*/
int __cdecl dbstrlen(PDBPROCESS dbproc)
{
	int result = 0; 
	buf_node_t* next = 0; 

	result = 0;
	if (!CheckEntrySkipDead(dbproc))
		return 0;
	next = dbproc->cmdbuffer;
	if (!next)
		return 0;
	while (next)
	{
		result += next->size;
		next = next->next;
	}
	return result;
}
BOOL __cdecl dbtabbrowse(PDBPROCESS dbproc, int tabnum)
{
	if (!CheckEntry(dbproc))
		return 0;
	if (!dbtabname(dbproc, tabnum))
		return 0;
	if (numtabkeys(dbproc, tabnum))
		return dbtsname(dbproc, tabnum) != 0;
	return 0;
}
int __cdecl dbtabcount(PDBPROCESS dbproc)
{
	if (CheckEntry(dbproc))
		return dbproc->ntab;
	else
		return -1;
}
LPCSTR __cdecl dbtabname(PDBPROCESS dbproc, int tabnum)
{
	if (!CheckEntry(dbproc))
		return 0;
	if (dbproc->tabnames && tabnum <= dbproc->ntab && tabnum >= 1 && dbproc->tabnames[tabnum - 1])
		return dbproc->tabnames[tabnum - 1];
	return 0;
}

LPCSTR __cdecl dbtabsource(PDBPROCESS dbproc, int colnum, int* tabnum)
{
	int ntab; 
	const char* pname; 

	if (CheckColumn(dbproc, colnum))
	{
		ntab = dbproc->columns_info[colnum - 1]->ntab;
		pname = dbtabname(dbproc, ntab);
		if (tabnum && pname)
		{
			*tabnum = ntab;
		}
		else if (tabnum)
		{
			*tabnum = -1;
		}
		return pname;
	}
	else
	{
		if (tabnum)
			*tabnum = -1;
		return 0;
	}
}
/*
* ts - TimeStamp
*/
int __cdecl dbtsnewlen(PDBPROCESS dbproc)
{
	int TimeStampIndex = 0; 

	if (!CheckEntry(dbproc))
		return -1;
	if (dbproc->nretval <= 0)
		return -1;
	TimeStampIndex = FindTimeStampIndex(dbproc);
	if (TimeStampIndex == -1)
		return -1;
	else
		return dbproc->retvals[TimeStampIndex]->retlen;
}
/*
* timestamp
*/
BYTE* __cdecl dbtsnewval(PDBPROCESS dbproc)
{
	int TimeStampIndex = 0;

	if (!CheckEntry(dbproc))
		return 0;
	if (dbproc->nretval <= 0)
		return 0;
	TimeStampIndex = FindTimeStampIndex(dbproc);
	if (TimeStampIndex == -1)
		return 0;
	else
		return dbproc->retvals[TimeStampIndex]->values;
}
int __cdecl dbtsput(PDBPROCESS dbproc, void* Src, int newtslen, int tabnum, LPCSTR tabname)
{
	int i = 0; 
	column_info_t** coldata = 0; 
	column_data_t** column_data = 0; 

	if (!CheckEntry(dbproc))
		return 0;
	if (tabnum > dbproc->ntab || tabnum < 1 && tabnum != -1)
		return 0;
	if (Src && newtslen >= 1)
	{
		if (tabnum == -1 && tabname)
			tabnum = dbtabnum(dbproc, tabname);
		if (tabnum == -1)
		{
			GeneralError(dbproc, SQLEPARM);
			return 0;
		}
		else
		{
			coldata = dbproc->columns_info;
			column_data = dbproc->columns_data;
			if (coldata && column_data)
			{
				for (i = 0; ; ++i)
				{
					if (i >= dbproc->ncols)
						return 0;
					if (coldata[i]->ntab == tabnum && coldata[i]->usertype == SQLTIMESTAMP)
						break;
				}
				if (column_data[i]->len >= newtslen)
				{
					dbmove(Src, column_data[i]->data, newtslen);
					column_data[i]->len = newtslen;
					return SUCCEED;
				}
				if (column_data[i]->data)
					FreeMemory(dbproc, column_data[i]->data);
				column_data[i]->data = (BYTE*)AllocateHeapMemory(4, dbproc, newtslen, 0);
				if (column_data[i]->data)
				{
					dbmove(Src, column_data[i]->data, newtslen);
					column_data[i]->len = newtslen;
					return SUCCEED;
				}
				else
				{
					return FreeOnError(0, dbproc);
				}
			}
			else
			{
				GeneralError(dbproc, SQLEAUTN);
				return 0;
			}
		}
	}
	else
	{
		GeneralError(dbproc, SQLETSIT);
		return 0;
	}
}
/*
* text data ptr
*/
BYTE* __cdecl dbtxptr(PDBPROCESS dbproc, int column)
{
	int token = 0;
	column_data_t* r = 0;
	blob_t* pdata = 0;

	if (!CheckColumn(dbproc, column))
		return 0;
	token = dbproc->columns_info[column - 1]->coltype;
	if (token == SQLTEXT || token == SQLIMAGE)
	{
		r = dbproc->columns_data[column - 1];

		pdata = (blob_t*)r->data;
		if (pdata)
		{	
			if (pdata->size)
				return pdata->txptr;
			else
				return 0;
		}
		else
		{
			return 0;
		}
	}
	else
	{
		GeneralError(dbproc, 10019);
		return 0;
	}
}
/*
* text timestamp
*/
BYTE* __cdecl dbtxtimestamp(PDBPROCESS dbproc, int column)
{
	int token = 0; 
	column_data_t* r = 0; 
	blob_t* ptext = 0;

	if (!CheckColumn(dbproc, column))
		return 0;
	r = dbproc->columns_data[column - 1];
	token = dbproc->columns_info[column - 1]->coltype;
	if (token == SQLTEXT || token == SQLIMAGE)
	{
		if (r && r->data)
		{
			ptext = (blob_t*)r->data;

			if (!IsTimeStamp((BYTE*)&ptext->timestamp))
				return 0;
			else
				return (BYTE*)&ptext->timestamp;
		}
		else
		{
			return 0;
		}
	}
	else
	{
		GeneralError(dbproc, 10019);
		return 0;
	}
}
/*
* text timestamp
*/
BYTE* __cdecl dbtxtsnewval(PDBPROCESS dbproc)
{
	BYTE* values = 0; 
	retval_t** retvals = 0;
	int i = 0; 

	values = 0;
	if (!CheckEntry(dbproc))
		return 0;
	retvals = dbproc->retvals;
	if (!retvals)
		return 0;
	for (i = 0; i < dbproc->nretval; ++i)
	{
		if (retvals[i]
			&& retvals[i]->type == SQLVARBINARY
			&& retvals[i]->name
			&& !strcmp((const char*)retvals[i]->name, "txts"))
		{
			values = (BYTE*)retvals[i]->values;
			break;
		}
	}
	if (values && IsTimeStamp(values))
		return values;
	else
		return 0;
}
/*
* text timestamp
*/
int __cdecl dbtxtsput(PDBPROCESS dbproc, BYTE* newtxts, int colnum)
{
	BYTE* ts = 0;
	int token = 0; 
	column_data_t* r = 0;

	if (!CheckColumn(dbproc, colnum))
		return 0;
	token = dbproc->columns_info[colnum - 1]->coltype;
	if (token == SQLTEXT || token == SQLIMAGE)
	{
		r = dbproc->columns_data[colnum - 1];
		if (r && r->data)
		{
			blob_t* ptext = (blob_t*)r->data;
			ts = (BYTE*)ptext->timestamp;
			if (newtxts)
				dbmove(newtxts, ts, 8u);
			else
				dbzero(ts, 8u);
			return SUCCEED;
		}
		else
		{
			return 0;
		}
	}
	else
	{
		GeneralError(dbproc, 10019);
		return 0;
	}
}
void __cdecl dbunlocklib()
{
	GlobalUnfix((HGLOBAL)0xFFFFFFFF);
}
int __cdecl dbuse_msghandler(int , int id)
{
	if (id == 918 || id == 921 || id == 922)
	{
		word_7335B844 = 1;
		return SUCCEED;
	}
	else
	{
		if (id == 5701)
			word_7335B844 = 2;
		return 2;
	}
}
/*
* Use a particular database.
* 
* Return value SUCCEED or FAIL
*/
int __cdecl dbuse(PDBPROCESS dbproc, LPCSTR dbname)
{
	int result = 0; 
	char cmd[40] = { 0 };

	if (!CheckEntry(dbproc))
		return 0;
	if (!dbname || !*dbname)
		return 0;
	if (strlen(dbname) > 30)
		*((BYTE*)dbname + 30) = 0;
	EnterCriticalSection(&UseSem);
	dbprocmsghandle_super(dbproc, (DBMSGHANDLE_PROC)dbuse_msghandler, 1);
	word_7335B844 = 3;
	dbproc->isavail = 0;
	dbfreebuf(dbproc);
	strcpy(cmd, "use  ");
	if (dbisopt(dbproc, 18, 0)) // quoted_identifier
		strcat(cmd, "\"");
	strcat(cmd, dbname);
	if (dbisopt(dbproc, 18, 0)) // quoted_identifier
		strcat(cmd, "\"");
	while (1)
	{
		if (!dbcmd(dbproc, cmd))
		{
			result = 0;
			break;
		}
		if (dbsqlexec(dbproc) == FAIL || dbresults(dbproc) == FAIL)
		{
			result = 0;
			break;
		}
		if (word_7335B844 == 2)
		{
			dbproc->change_dirty = 1;
			result = 1;
			break;
		}
		if (word_7335B844 == 1)
			DbSleep(1000u);
	}

	dbfreebuf(dbproc);
	dbprocmsghandle_super(dbproc, 0, 1);
	LeaveCriticalSection(&UseSem);
	return result;
}

BOOL __cdecl dbwillconvert(int srctype, int desttype)
{
	int ct = 0;
	int dt = 0;

	ct = TypeToConvert(srctype);
	dt = TypeToConvert(desttype);
	if (dt == -1 || ct == -1)
		return 0;
	else
		return ConvertArray[16 * ct + dt];
}
void dbwinexit()
{
	;
}
/*
* Syntax
* dbcc dbrepair(database_name, ltmignore)
*/

int __cdecl dbwritepage(PDBPROCESS dbproc, const char* dbname, int fileno, int pageno, int size, BYTE* buf)
{
	char Buffer[20] = { 0 };
	char Src[100] = { 0 };
	int l0 = 0; 
	int l1 = 0;
	int bytl = 0;

	l0 = 0;
	if (!CheckEntry(dbproc))
		return 0;
	if (pageno >= 0 && dbname && buf && size > 0)
	{
		if ((dbproc->cmd_flag & 4) != 0 && dbproc->severity_level == 2)
		{
			sprintf(Buffer, "%d, %d", fileno, pageno);
			strcpy((char*)Src, "dbcc dbrepair (");
			strcat((char*)Src, dbname);
			strcat((char*)Src, ", writepage, ");
			strcat((char*)Src, Buffer);
			strcat((char*)Src, ")");
			tidyproc(dbproc);
			dbfreebuf(dbproc);
			dbproc->curcmd = 0;
			if (queuepacket(dbproc, (BYTE*)Src, strlen((const char*)Src)))
			{
				if (sendflush(dbproc))
				{
					dbproc->token = getbyte(dbproc, (BYTE*)&bytl);
					if (bytl)
					{
						if ((dbproc->token == SQLINFO || dbproc->token == SQLERROR) && !pageerror(dbproc))
						{
							if (dbproc->token == SQLDONE)
								pagedone(dbproc);
							return 0;
						}
						else if (dbproc->token != SQLDONE || pagedone(dbproc))
						{
							if (dbproc->severity_level == 3)
							{
								return 0;
							}
							else
							{
								l1 = size + 4;
								*dbproc->CommLayer->buffer0 = PT_SQLBATCH;
								*dbproc->CommLayer->buffer1 = PT_SQLBATCH;
								if (queuepacket(dbproc, (BYTE*)&l1, 4u))
								{
									if (queuepacket(dbproc, (BYTE*)&l0, 4u))
									{
										if (queuepacket(dbproc, (BYTE*)buf, size))
										{
											if (sendflush(dbproc))
											{
												dbproc->token = getbyte(dbproc, (BYTE*)&bytl);
												if (bytl)
												{
													if ((dbproc->token == SQLINFO || dbproc->token == SQLERROR) && !pageerror(dbproc))
													{
														if (dbproc->token == SQLDONE)
															pagedone(dbproc);
														return 0;
													}
													else if (dbproc->token == SQLDONE)
													{
														return pagedone(dbproc) && dbproc->severity_level != 3;
													}
													else
													{
														// "Possible network error: Bad token from SQL Server: Datastream processing out of sync."
														GeneralError(dbproc, SQLEBTOK);
														return 0;
													}
												}
												else
												{
													return 0;
												}
											}
											else
											{
												return 0;
											}
										}
										else
										{
											return 0;
										}
									}
									else
									{
										return 0;
									}
								}
								else
								{
									return 0;
								}
							}
						}
						else
						{
							return 0;
						}
					}
					else
					{
						return 0;
					}
				}
				else
				{
					return 0;
				}
			}
			else
			{
				return 0;
			}
		}
		else
		{
			GeneralError(dbproc, 10038);
			return 0;
		}
	}
	else
	{
		GeneralError(dbproc, SQLEPARM);
		return 0;
	}
}
/*
	WRITETEXT[BULK]
	{ table.column text_ptr }
	[WITH LOG] { data }
*/
int __cdecl dbwritetext(
	PDBPROCESS dbproc,
	LPCSTR objname,
	DBBINARY* textptr, // DBBINARY
	DBTINYINT textptrlen, // DBTINYINT
	DBBINARY* timestamp, // DBBINARY
	BOOL withlog,
	int size,
	LPCBYTE text)
{

	const char* p0; 
	int l0 = 0; 
	char* p1 = 0; 
	char Destination[132] = { 0 };
	char* lpOutBuffer = 0; 
	char* lpMem = 0;
	int exec = 0; 

	if (!CheckEntry(dbproc))
		return 0;
	dbfreebuf(dbproc);
	if (!objname || !*objname)
		return 0;
	GetFullName(dbproc, Destination, (char*)objname, 4);
	if (size < 1)
		return 0;
	lpMem = (char*)AllocateHeapMemory(4, 0, strlen(Destination) + 120, 1);
	if (!lpMem)
		return 0;
	lpOutBuffer = (char*)AllocateHeapMemory(4, 0, 80u, 1);
	if (!lpOutBuffer)
		return FreeOnError(lpMem, 0);
	strcpy((char*)lpMem, "writetext bulk ");
	strcat((char*)lpMem, Destination);
	if (textptr)
	{
		if (ConvertToChar(dbproc, SQLBINARY, (BYTE*)textptr, textptrlen, SQLCHAR, lpOutBuffer, -1) == -1)
		{
			FreeMemory(0, lpMem);
			return FreeOnError(lpOutBuffer, 0);
		}
		strcat((char*)lpMem, " 0x");
		p0 = (char*)lpOutBuffer;
		l0 = strlen((const char*)lpOutBuffer) + 1;
		p1 = (char*)lpMem + strlen((const char*)lpMem) + 1;
	}
	else
	{
		p0 = " NULL";
		l0 = strlen(p0) + 1;
		p1 = (char*)lpMem + strlen((const char*)lpMem) + 1;
	}
	qmemcpy(p1 - 1, p0, l0);
	if (timestamp)
	{
		if (ConvertToChar(dbproc, SQLBINARY, (BYTE*)timestamp, 8, SQLCHAR, lpOutBuffer, -1) == -1)
		{
			FreeMemory(0, lpMem);
			return FreeOnError(lpOutBuffer, 0);
		}
		strcat((char*)lpMem, " timestamp = 0x");
		strcat((char*)lpMem, (const char*)lpOutBuffer);
	}
	if (withlog)
		strcat((char*)lpMem, " with log");
	if (!dbcmd(dbproc, (char*)lpMem))
	{
		FreeMemory(0, lpMem);
		return FreeOnError(lpOutBuffer, 0);
	}
	exec = dbproc->exec;
	dbproc->exec = 1;
	if (!dbsqlsend(dbproc))
	{
		FreeMemory(0, lpMem);
		return FreeOnError(lpOutBuffer, 0);
	}
	dbproc->exec = exec;
	*(_DWORD*)&dbproc->field_7C = 0;
	dbproc->packet_size = size;
	if (text)
	{
		if (!dbsqlok(dbproc)
			|| dbresults(dbproc) == FAIL
			|| dbmoretext(dbproc, size, (BYTE*)text) == FAIL
			|| dbsqlok(dbproc) == FAIL
			|| dbresults(dbproc) == FAIL)
		{
			FreeMemory(0, lpMem);
			return FreeOnError(lpOutBuffer, 0);
		}
	}
	FreeMemory(0, lpMem);
	FreeMemory(0, lpOutBuffer);
	return SUCCEED;
}
/*
* bcp
*/

int __stdcall bcpErrorHandle(PDBPROCESS dbproc, int eCode, char* tablename, int maxrow, int nrow)
{
	char* estr = 0;
	int result = 0;
	char Buffer[512] = { 0 };

	estr = dberrstr(eCode);
	if (!estr)
		return GeneralError(dbproc, eCode);
	switch (eCode)
	{
	case 10049:
	case 10051:
		sprintf(Buffer, estr, maxrow);
		return dbdoerror(dbproc, 1, eCode, 0xFFFFFFFF, Buffer);
	case 10097:
	case 10100:
		sprintf(Buffer, estr, tablename, maxrow);
		result = dbdoerror(dbproc, 7, eCode, 0xFFFFFFFF, Buffer);
		break;
	case 10098:
	case 10099:
		sprintf(Buffer, estr, tablename, maxrow, nrow);
		result = dbdoerror(dbproc, 7, eCode, 0xFFFFFFFF, Buffer);
		break;
	default:
		result = dbdoerror(dbproc, 7, eCode, 0xFFFFFFFF, Buffer);
		break;
	}
	return result;
}

int __stdcall bcpCheckEntry(PDBPROCESS dbproc)
{
	int result = 0;

	result = CheckEntry(dbproc);
	if (result)
	{
		if (dbproc->bcpinfo)
		{
			return SUCCEED;
		}
		else
		{
			GeneralError(dbproc, 10055);
			return 0;
		}
	}
	return result;
}
BOOL __stdcall bcpWrite(PDBPROCESS dbproc, bcp_t* bcp, DWORD NumberOfBytesWritten, LPCVOID lpBuffer)
{
	DWORD Size = 0; 
	BOOL result = 0; 
	DWORD BytesWritten = 0;

	Size = NumberOfBytesWritten;
	if (NumberOfBytesWritten != 0xFFFFFFFF && bcp->m_nToWriteSize + (unsigned __int64)NumberOfBytesWritten <= 0x1000)
	{
		goto LABEL_5;
	}
	result = WriteFile(bcp->m_hFile, bcp->m_pBuffer, (DWORD)bcp->m_nToWriteSize, &BytesWritten, 0);
	if (!result)
		return result;
	bcp->m_nToWriteSize = 0i64;
	if (Size != 0xFFFFFFFF)
	{
	LABEL_5:
		if (Size <= 0x1000)
		{
			memmove((char*)bcp->m_pBuffer + bcp->m_nToWriteSize, lpBuffer, Size);
			bcp->m_nToWriteSize += Size;
		}
		else
		{
			result = WriteFile(bcp->m_hFile, lpBuffer, Size, &BytesWritten, 0);
			if (!result)
				return result;
			if (BytesWritten != Size)
				return 0;
		}
	}
	return SUCCEED;
}
int __stdcall bcpClose(PDBPROCESS dbproc, bcp_t* bcp)
{

	if (!bcp)
		return SUCCEED;
	if (bcp->m_nToWriteSize)
		bcpWrite(dbproc, bcp, 0xFFFFFFFF, 0);
	if (bcp->m_pMap)
	{
		UnmapViewOfFile(bcp->m_pMap);
		bcp->m_pMap = 0;
	}

	if (bcp->m_hFileMapping)
	{
		CloseHandle(bcp->m_hFileMapping);
		bcp->m_hFileMapping = 0;
	}
	if (bcp->m_hFile)
	{
		CloseHandle(bcp->m_hFile);
		bcp->m_hFile = 0;
	}
	return SUCCEED;
}
bcp_t* __stdcall bcpOpen(PDBPROCESS dbproc, LPCSTR lpFileName, int readonly)
{
	bcp_t* p_bcp = 0;

	BYTE* pbuf = 0;
	DWORD FileSizeHigh = 0;
	DWORD FileSize = 0;

	__try
	{
		p_bcp = (bcp_t*)AllocateHeapMemory(4, dbproc, SQLINT1, 1);

		if (!p_bcp
			|| (p_bcp->m_hFile = 0,
				p_bcp->m_hFileMapping = 0,
				p_bcp->m_pMap = 0,
				p_bcp->m_hFile = CreateFileA(lpFileName, readonly != 1 ? GENERIC_READ | GENERIC_WRITE : GENERIC_READ, 1u, 0, 3 - (readonly != 1), 0x8000080u, 0),
				p_bcp->m_hFile == (HANDLE)-1))
		{
			return 0;
		}
		else
		{
			FileSize = GetFileSize(p_bcp->m_hFile, &FileSizeHigh);
			p_bcp->m_nFileSize = FileSize + ((unsigned __int64)FileSizeHigh << 32);
			p_bcp->m_nToWriteSize = 0;
			p_bcp->m_nMapSize = 0;

			if (readonly != 2 || (pbuf = (BYTE*)AllocateHeapMemory(4, dbproc, 0x1000u, 0), (p_bcp->m_pBuffer = pbuf) != 0))
			{
				p_bcp->m_bMaped = 0;
				if (readonly == 1)
				{
					if (p_bcp->m_nFileSize)
					{
						p_bcp->m_hFileMapping = CreateFileMappingA(p_bcp->m_hFile, 0, PAGE_READONLY, 0, 0, 0);
						if (p_bcp->m_hFileMapping)
						{
							p_bcp->m_pMap = (BYTE*)MapViewOfFile(p_bcp->m_hFileMapping, FILE_MAP_READ, 0, 0, 0);
							if (p_bcp->m_pMap)
								p_bcp->m_bMaped = 1;
						}
					}
				}
				
				//__leave;

			}
			else
			{

				return 0;
			}
		}
	}
	__finally
	{
		if (AbnormalTermination()) {
			if (p_bcp)
				bcpClose(dbproc, p_bcp);
			return 0;
		}else
			return p_bcp;
	}

	
}
DWORD __cdecl ReadFileNT(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead)
{
	BOOL flag = 0; 

	flag = ReadFile(hFile, lpBuffer, nNumberOfBytesToRead, &nNumberOfBytesToRead, 0);
	return flag ? nNumberOfBytesToRead : 0;
}
int __stdcall bcpSeek64(PDBPROCESS dbproc, bcp_t* bcp, __int64 Size)
{
	int SizH = HIDWORD(Size);
	if (dbproc->bcpinfo->blkbuffer)
	{
		dbproc->bcpinfo->read_pos  = Size;
	}
	else
	{
		SetFilePointer(bcp->m_hFile, DWORD(Size), (PLONG)&SizH, 0);
	}
	return SUCCEED;
}
int __cdecl get_col_data(PDBPROCESS dbproc, bcp_t* bcp, bcp_column_t* bindcol, int* lpoffset)
{
	bcp_info_t* bcpinfo = 0; 

	int i = 0; 
	char* p1,* p0,* p2;

	int result = 0; 
	__int64 read_size = 0;
	const void* pbf; 
	BYTE* pp = 0;

	__int64 mSiZ = 0;
	int Size_ = 0;
	bcpinfo = dbproc->bcpinfo;

	i = 0;

	if (bcp->m_bMaped)
	{
		mSiZ = bcp->m_nMapSize;
	}
	else
	{
		mSiZ = bcpinfo->read_pos;
	}

	if (!bindcol->terminator || bindcol->termlen == 0)
		return SUCCEED;
	if (bcp->m_bMaped)
	{

		p1 = (char*)&bcp->m_pMap[LODWORD(bcp->m_nMapSize)];
		p0 = p1;
		p2 = (char*)&bcp->m_pMap[LODWORD(bcp->m_nFileSize) - 1];
		if (bindcol->termlen == 1)
		{
			if (p1 <= p2)
			{
				while (*p1 != *bindcol->terminator)
				{
					if (++p1 > p2)
						goto LABEL_11;
				}

				if (lpoffset == 0)
				{
					bcp->m_nMapSize = bindcol->termlen + p1 - p0;
				}else
					*lpoffset = p1 - p0;
				return SUCCEED;
			}
		}
		else if (p1 <= p2)
		{
			while (bindcol->termlen > (unsigned int)(p2 - p1 + 1) || memcmp(p1, bindcol->terminator, bindcol->termlen))
			{
				if (++p1 > p2)
					goto LABEL_11;
			}

			if (lpoffset == 0)
			{
				bcp->m_nMapSize += bindcol->termlen + p1 - p0;
				return SUCCEED;
			}
			*lpoffset = p1 - p0;
			return SUCCEED;
		}
	LABEL_11:

		if (p1 - p0 <= 0)
			return 100;
		if (lpoffset)
		{
			*lpoffset = p1 - p0;
			return SUCCEED;
		}
		return SUCCEED;
	}
	if (lpoffset == 0)
		lpoffset = &Size_;

	/* read the data, finally */
	if (bcpinfo->blkbuffer)
	{
		while (1)
		{
			read_size = bcpinfo->read_size;
			if (bcpinfo->read_pos > read_size || read_size == -1)
			{
				result = bcpRead(dbproc, bcp, 0x800u, 0);
				if (result != 1)
					break;
			}

			pbf = (const void*)(bcpinfo->read_pos + bcpinfo->blkbuffer - bcpinfo->total_size);
			pp = (BYTE*)memchr(pbf, *bindcol->terminator, (size_t)(bcpinfo->read_size - bcpinfo->read_pos + 1));
			if (pp)
			{
				*lpoffset += pp - (BYTE*)pbf;
				bcpinfo->read_pos += pp - (BYTE*)pbf + 1;

				if (bindcol->termlen > 1 && bcpinfo->read_pos + bindcol->termlen - 1 > bcpinfo->read_size)
				{
					result = bcpRead(dbproc, bcp, 0x800u, 0);
					if (result != 1)
						return result;
				}
				if (++i >= bindcol->termlen)
					goto LABEL_54;
				while (*(char*)(bcpinfo->blkbuffer - bcpinfo->total_size + bcpinfo->read_pos) == bindcol->terminator[i])
				{
					bcpinfo->read_pos += 1;
					++i;
					if (i >= bindcol->termlen)
						goto LABEL_40;
				}
				*lpoffset = i + *lpoffset;
				i = 0;
			LABEL_40:
				if (i >= bindcol->termlen)
				{
				LABEL_54:

					if (Size_ == bindcol->termlen)
						return SUCCEED;
					if (bcp->m_bMaped)
					{
						bcp->m_nMapSize = mSiZ;
						return SUCCEED;
					}
					else
					{
						return bcpSeek64(dbproc, bcp, mSiZ);
					}
				}

			}
			else
			{

				*lpoffset += LODWORD(bcpinfo->read_size) - LODWORD(bcpinfo->read_pos) + 1;
				bcpinfo->read_pos = bcpinfo->read_size + 1;
			}
		}
	}
	else
	{
		BYTE term = 0;
		result = bcpRead(dbproc, bcp, 1u, &term);

		if (bindcol->termlen)
		{
			while (result == 1)
			{
				if (term == *bindcol->terminator)
				{
					if (++i < bindcol->termlen)
					{
						do
						{
							result = bcpRead(dbproc, bcp, 1u, &term);
							if (result != 1)
								return result;
							if (term != bindcol->terminator[i])
							{
								*lpoffset = i + *lpoffset;
								i = 0;

								break;
							}
						} while (++i < bindcol->termlen);
					}
				}
				else
				{
					++*lpoffset;
					result = bcpRead(dbproc, bcp, 1u, &term);
				}

				if (i >= bindcol->termlen)
					goto LABEL_55;
			}
		}
		else
		{
		LABEL_55:
			if (Size_ == bindcol->termlen)
				return SUCCEED;
			if (bcp->m_bMaped)
			{
				bcp->m_nMapSize = mSiZ;
				return SUCCEED;
			}
			else
			{
				return bcpSeek64(dbproc, bcp, mSiZ);
			}
		}
	}
	return result;
}
int __stdcall bcpError(PDBPROCESS dbproc, int eCode) {
	bcp_info_t* bcpinfo = 0; 

	int i = 0; 

	bcpinfo = dbproc->bcpinfo;
	if (bcpinfo)
	{
		if (bcpinfo->columns)
		{
			if (bcpinfo->b_loaded)
			{
				i = 0;
				if (bcpinfo->num_cols)
				{
					do
					{
						if (bcpinfo->columns[i].terminator)
							FreeMemory(dbproc, (LPVOID)bcpinfo->columns[i].terminator);
						++i;

					} while (i < bcpinfo->num_cols);
				}
			}
			else
			{
				if (bcpinfo->ncols)
				{
					i = 0;
					do
					{
						if (bcpinfo->columns[i].vardata)
							FreeMemory(dbproc, bcpinfo->columns[i].vardata);
						if (bcpinfo->columns[i].varaddr)
							FreeMemory(dbproc, (LPVOID)bcpinfo->columns[i].varaddr);
						if (bcpinfo->columns[i].terminator)
							FreeMemory(dbproc, (LPVOID)bcpinfo->columns[i].terminator);

						++i;
					} while (i < bcpinfo->ncols);
				}
			}
			FreeMemory(dbproc, bcpinfo->columns);
		}
		if (bcpinfo->bindinfo)
		{
			if (bcpinfo->num_cols)
			{
				i = 0;
				do
				{
					if (bcpinfo->bindinfo[i].vardata)
						FreeMemory(dbproc, bcpinfo->bindinfo[i].vardata);
					if (bcpinfo->bindinfo[i].name)
						FreeMemory(dbproc, bcpinfo->bindinfo[i].name);
					++i;
				} while (i < bcpinfo->num_cols);
			}
			FreeMemory(dbproc, bcpinfo->bindinfo);
		}
		if (bcpinfo->offset_val)
			FreeMemory(dbproc, bcpinfo->offset_val);
		if (bcpinfo->textdata)
			FreeMemory(dbproc, bcpinfo->textdata);
		if (bcpinfo->p_tabname)
			FreeMemory(dbproc, bcpinfo->p_tabname);
		if (bcpinfo->dbproc)
			*(DWORD*)&bcpinfo->dbproc->ver = bcpinfo->dcol;
		bcpClose(dbproc, bcpinfo->bcpdata);
		bcpClose(dbproc, bcpinfo->bcplog);
		FreeMemory(dbproc, dbproc->bcpinfo);
		dbproc->bcpinfo = 0;
	}
	if (eCode)
		GeneralError(dbproc, eCode);
	return 0;
}
int __stdcall bcpSkipWhiteSp(bcp_t* bcp, unsigned __int8 B)
{
	int i = 0;
	int B0, B1; 
	char C = 0,C1 = 0;
	B0 = 0;
	i = 0;
	if (bcpRead(0, bcp, 1u, &C) != 1)
		return 0;
	while (1)
	{
		C1 = C;
		++i;
		if (C == '\n')
			break;
		if (__mb_cur_max <= 1)
		{
			B1 = _pctype[C] & 8;
		}
		else
		{
			B1 = _isctype(C, 8);
			C1 = C;
		}
		if (!B1)
		{
			goto LABEL_10;
		}
		if (bcpRead(0, bcp, 1u, &C) != 1)
			return 0;
	}
	B0 = 1;
	++i;
LABEL_10:
	if (__mb_cur_max <= 1)
	{
		B1 = _pctype[C1] & 8;
	}
	else
	{
		B1 = _isctype(C1, 8);
		C1 = C;
	}
	if (B1 && C1 != '\n' || i <= 1 || B0 != B)
		return 0;
	if (C1 != 10)
	{
		if (bcp->m_bMaped)
		{
			bcp->m_nMapSize--;
			return SUCCEED;
		}
		SetFilePointer(bcp, -1, 0, 1u);
	}
	return SUCCEED;
}
int __stdcall bcpReadNumber(bcp_t* bcp, char* lpBuffer)
{
	char* p0 = 0; 
	char* p2 = 0; 
	char C = 0;
	int result = 0; 
	char* p1 = 0;

	p0 = lpBuffer - 1;
	p2 = lpBuffer;
	if (bcpRead(0, bcp, 1u, lpBuffer) != 1)
		return 0;
	while (1)
	{
		C = *++p0;
		++p2;
		if (C < '0' || C > '9' || p0 >= lpBuffer + 31)
			break;
		if (bcpRead(0, bcp, 1u, p2) != 1)
			return 0;
	}
	if (*p0 != '-')
		goto LABEL_23;
	p1 = p0 + 1;
	if (bcpRead(0, bcp, 1u, p1) != 1)
		return 0;
	if (*p1 != 49)
		return 0;
	p0 = p1 + 1;
	if (bcpRead(0, bcp, 1u, p0) != 1)
		return 0;
	result = __mb_cur_max <= 1 ? _pctype[*p0] & 8 : _isctype(*p0, 8);
	if (result)
	{
	LABEL_23:
		if (bcp->m_bMaped)
		{
			bcp->m_nMapSize--;
			result = 1;
			*p0 = 0;
		}
		else
		{
			SetFilePointer(bcp, -1, 0, 1u);
			*p0 = 0;
			return SUCCEED;
		}
	}
	return result;
}
int __stdcall bcpReadChars(bcp_t* bcp, char* lpBuffer)
{
	char* p0 = 0;
	char* p1 = 0; 
	int C = 0; 
	int result = 0; 

	p0 = lpBuffer - 1;
	p1 = lpBuffer;
	if (bcpRead(0, bcp, 1u, lpBuffer) != 1)
		return 0;
	while (1)
	{
		++p0;
		++p1;
		C = __mb_cur_max <= 1 ? _pctype[(unsigned __int8)*p0] & 8 : _isctype((unsigned __int8)*p0, 8);
		if (C || p0 >= lpBuffer + 31)
			break;
		if (bcpRead(0, bcp, 1u, p1) != 1)
			return 0;
	}
	if (lpBuffer == p0)
		return 0;
	if (bcp->m_bMaped)
	{
		bcp->m_nMapSize--;
		result = 1;
		*p0 = 0;
	}
	else
	{
		SetFilePointer(bcp, -1, 0, 1u);
		*p0 = 0;
		return SUCCEED;
	}
	return result;
}
int __stdcall bcpSetUp(PDBPROCESS dbproc)
{
	bcp_info_t* bcpinfo = 0; 
	BYTE* pbyt1 = 0; 
	BYTE typ = 0; 

	BYTE token = 0; 
	int len = 0; 

	char C = 0; 
	char* p0 = 0; 
	char* pdbname = 0; 

	int l1 = 0; 

	int i = 0; 
	short offset = 0; 

	char Buffer[32] = {0};
	char Src[80] = { 0 };

	bcpinfo = dbproc->bcpinfo;

	strcpy(bcpinfo->dbname, dbname(dbproc));
	if (bcpinfo->tablename[0] && !dbuse(dbproc, bcpinfo->tablename))
		return bcpError(dbproc, 0);
	PrepareFullName(dbproc, bcpinfo, 0);
	if (bcpinfo->direction == DB_IN
		&& !bcpCmd(
			dbproc,
			"select minlen, maxlen from sysindexes where id = object_id('%s') and indid < 2 ",
			bcpinfo->object_id))
	{
		return bcpError(dbproc, 0);
	}
	if (!bcpCmd(dbproc, "select count(id) from syscolumns where id = object_id('%s') ", bcpinfo->object_id)
		|| !bcpCmd(
			dbproc,
			"select count(id) from syscolumns where id = object_id('%s') and type in (%d, %d) ",
			bcpinfo->object_id,
			SQLTEXT,
			SQLIMAGE))
	{
		return bcpError(dbproc, 0);
	}
	if (dbsqlexec(dbproc) != 1)
		return bcpError(dbproc, 10072);
	if (bcpinfo->direction == DB_IN)
	{
		if (dbresults(dbproc) != SUCCEED || dbnextrow(dbproc) != MORE_ROWS)
			return bcpError(dbproc, 10072);
		pbyt1 = dbdata(dbproc, 1);
		dbmove(pbyt1, &bcpinfo->minlen, 2u);
		pbyt1 = dbdata(dbproc, 2);
		dbmove(pbyt1, &bcpinfo->maxlen, 2u);
		if (dbnextrow(dbproc) != NO_MORE_ROWS)
			return bcpError(dbproc, 0);
	}
	if (dbresults(dbproc) != SUCCEED)
		return bcpError(dbproc, 0);
	if (dbnextrow(dbproc) != MORE_ROWS)
		return bcpError(dbproc, 0);

	pbyt1 = dbdata(dbproc, 1);
	dbmove(pbyt1, &bcpinfo->num_cols, 2u);
	if (!bcpinfo->num_cols)
		return bcpError(dbproc, 0);
	if (dbnextrow(dbproc) != NO_MORE_ROWS)
		return bcpError(dbproc, 0);
	if (dbresults(dbproc) != SUCCEED)
		return bcpError(dbproc, 0);
	if (dbnextrow(dbproc) != NO_MORE_ROWS)
		return bcpError(dbproc, 0);

	pbyt1 = dbdata(dbproc, 1);
	dbmove(pbyt1, &bcpinfo->textcount, 2u);
	if (dbnextrow(dbproc) != NO_MORE_ROWS)
		return bcpError(dbproc, 0);
	if (bcpinfo->textcount)
	{
		bcpinfo->textdata = (bcp_blob_t*)AllocateHeapMemory(4, dbproc, 22 * bcpinfo->textcount, 1);
		if (!bcpinfo->textdata)
			return bcpError(dbproc, 0);
	}
	const char *str1= "select name, length, offset, colid, type, status, cdefault, prec, scale from syscolumns where id = object_id(',\','%s',\',') ";
	if (dbproc->bServerType != 1 || (dbproc->ServerMajor < 5u))
		str1 = "select name, length, offset, colid, type, status, cdefault from syscolumns where id = object_id(',\','%s',\',') ";
	if (!bcpCmd(dbproc, str1, bcpinfo->object_id))
		return bcpError(dbproc, 0);
	if (dbsqlexec(dbproc) != 1)
		return bcpError(dbproc, 0);
	if (dbresults(dbproc) != SUCCEED)
		return bcpError(dbproc, 0);
	if (bcpinfo->direction == DB_IN)
	{
		bcpinfo->offset_val = (char*)AllocateHeapMemory(4, dbproc, (unsigned __int16)bcpinfo->maxlen + bcpinfo->minlen + 11, 1);
		if (!bcpinfo->offset_val)
			return bcpError(dbproc, 0);
	}
	bcpinfo->bindinfo = (bcp_bindinfo_t*)AllocateHeapMemory(4, dbproc, 52 * bcpinfo->num_cols, 1);
	if (!bcpinfo->bindinfo)
		return bcpError(dbproc, 0);

	i = 0;
	if (bcpinfo->num_cols != 0)
	{

		while (dbnextrow(dbproc) == MORE_ROWS)
		{
			pbyt1 = dbdata(dbproc, 2); // length
			dbmove(pbyt1, (char*)&bcpinfo->bindinfo[i].length, 1u);
			pbyt1 = dbdata(dbproc, 3); // offset
			dbmove(pbyt1, &offset, 2u);
			typ = bcpinfo->bindinfo[i].usertype;
			pbyt1 = dbdata(dbproc, 5); // type
			dbmove(pbyt1, &bcpinfo->bindinfo[i].usertype, 1u);
			if (bcpinfo->bindinfo[i].usertype == 0x3F)
				typ = SQLNUMERIC;
			if (typ == 0x37)
				typ = SQLDECIMAL;
			bcpinfo->bindinfo[i].commontype = (BYTE)dbconvert_getcommontype(typ, bcpinfo->bindinfo[i].length);

			if (bcpinfo->direction == DB_OUT)
			{
				bcpinfo->bindinfo[i].convfunc = ConvertToChar;
			}
			else
			{
				switch (bcpinfo->bindinfo[i].commontype)
				{
				case SQLIMAGE:
				case SQLBINARY:
					bcpinfo->bindinfo[i].convfunc = ConvertToBinary;
					break;
				case SQLTEXT:
				case SQLCHAR:
					bcpinfo->bindinfo[i].convfunc = ConvertToChar;
					break;
				case SQLINT1:
				case SQLINT2:
					bcpinfo->bindinfo[i].convfunc = ConvertToInt;
					break;
				case SQLBIT:
					bcpinfo->bindinfo[i].convfunc = ConvertToBit;
					break;
				case SQLINT4:
					bcpinfo->bindinfo[i].convfunc = ConvertToLong;
					break;
				case SQLDATETIM4:
					bcpinfo->bindinfo[i].convfunc = ConvertToSmallDate;
					break;
				case SQLFLT4:
					bcpinfo->bindinfo[i].convfunc = ConvertToReal;
					break;
				case SQLMONEY:
					bcpinfo->bindinfo[i].convfunc = ConvertToMoney;
					break;
				case SQLDATETIME:
					bcpinfo->bindinfo[i].convfunc = ConvertToDateTime;
					break;
				case SQLFLT8:
					bcpinfo->bindinfo[i].convfunc = ConvertToFloat;
					break;
				case SQLDECIMAL:
				case SQLNUMERIC:
					bcpinfo->bindinfo[i].convfunc = ConvertToNumericDecimal;
					break;
				case SQLMONEY4:
					bcpinfo->bindinfo[i].convfunc = ConvertToSmallMoney;
					break;
				default:
					break;
				}
			}
			pbyt1 = dbdata(dbproc, 6); // status
			dbmove(pbyt1, (char*)bcpinfo->bindinfo[i].status, 1u);
			pbyt1 = dbdata(dbproc, 7); // cdefault
			dbmove(pbyt1, (char*)bcpinfo->bindinfo[i].cdefault, 4u);
			token = (*dbproc->columns_info)->coltype;
			if (token == SQLTEXT || token == SQLIMAGE)
			{
				blob_t* pblob = (blob_t*)dbproc->columns_data[0]->data;
				len = pblob->len;
			}
			else
				len = dbproc->columns_data[0]->len;
			bcpinfo->bindinfo[i].name = (char*)AllocateHeapMemory(4, dbproc, len + 1, 0);
	
			if (!bcpinfo->bindinfo[i].name)
			{
				return bcpError(dbproc, 0);
			}

			pbyt1 = dbdata(dbproc, 1); // name
			dbmove(pbyt1, bcpinfo->bindinfo[i].name, len);
			bcpinfo->bindinfo[i].name[len] = 0;
			if (dbproc->bServerType == 1 && dbproc->ServerMajor >= 5u)
			{
				pbyt1 = dbdata(dbproc, 8); // prec
				dbmove(pbyt1, (char*)&bcpinfo->bindinfo[i].precision, 1u);
				pbyt1 = dbdata(dbproc, 9); // scale
				dbmove(pbyt1, (char*)&bcpinfo->bindinfo[i].scale, 1u);
			}
			if (offset > 0)
			{
				bcpinfo->bindinfo[i].offset_val = (char*)bcpinfo->offset_val + offset;
			}
			else
			{
				bcpinfo->bindinfo[i].offset_val = 0;
				bcpinfo->bindinfo[i].offset = -offset;
			}
			if (bcpinfo->bindinfo[i].cdefault == 0)
			{
				bcpinfo->bindinfo[i].datsize = 0;
				bcpinfo->bindinfo[i].vardata = 0;
			}

			if (bcpinfo->bindinfo[i].usertype == SQLINTN 
				|| bcpinfo->bindinfo[i].usertype > SQLNUMERIC && bcpinfo->bindinfo[i].usertype <= SQLDATETIMN)
				bcpinfo->bindinfo[i].type |= 0x80u;

			if (++i >= bcpinfo->num_cols)
			{
				break;
			}
		}
		
	}

	if (dbnextrow(dbproc) == NO_MORE_ROWS)
	{
		if (bcpinfo->direction != 1)
			return SUCCEED;
		i = 0;
		if (bcpinfo->num_cols)
		{
			while (1)
			{
				if (bcpinfo->bindinfo[i].cdefault)
				{
					strcpy(Buffer, dbprtype(bcpinfo->bindinfo[i].commontype));
					C = Buffer[0];
					p0 = Buffer;
					if (Buffer[0])
					{
						while (C != '-')
						{
							C = *++p0;
							if (!C)
								goto LABEL_82;
						}
						*p0 = 0;
					}
				LABEL_82:
					switch (bcpinfo->bindinfo[i].commontype)
					{
					case SQLVARBINARY:
					case SQLVARCHAR:
					case SQLBINARY:
					case SQLCHAR:
						strcat(Buffer, "(");
						_itoa(bcpinfo->bindinfo[i].length, &Buffer[strlen(Buffer)], 10);
						goto LABEL_85;
					case SQLDECIMAL:
					case SQLNUMERIC:
						strcat(Buffer, "(");
						_itoa(bcpinfo->bindinfo[i].precision, &Buffer[strlen(Buffer)], 10);
						strcat(Buffer, ",");
						_itoa(bcpinfo->bindinfo[i].scale, &Buffer[strlen(Buffer)], 10);
					LABEL_85:
						strcat(Buffer, ")");
						break;
					default:
						break;
					}

					pdbname = (char*)dbname(dbproc);
					sprintf(Src, "select x = convert(%s, getdefault('%s', %ld)) ", Buffer, pdbname, bcpinfo->bindinfo[i].cdefault);
					if (!dbcmd(dbproc, Src) || dbsqlexec(dbproc) != 1 || dbresults(dbproc) != SUCCEED || dbnextrow(dbproc) != MORE_ROWS)
						break;

					if ((*dbproc->columns_info)->coltype == SQLTEXT || (*dbproc->columns_info)->coltype == SQLIMAGE)
					{
						blob_t* pblob = (blob_t*)dbproc->columns_data[0]->data;
						l1 = pblob->len;
					}
					else
						l1 = dbproc->columns_data[0]->len;
					bcpinfo->bindinfo[i].cdefault = l1;
					bcpinfo->bindinfo[i].vardata = (BYTE*)AllocateHeapMemory(4, dbproc, l1, 1);
	
					if (!bcpinfo->bindinfo[i].vardata)
						break;

					pbyt1 = dbdata(dbproc, 1);
					dbmove(pbyt1, bcpinfo->bindinfo[i].vardata, bcpinfo->bindinfo[i].cdefault);
					if (dbnextrow(dbproc) != NO_MORE_ROWS)
						break;
				}

				if (++i >= bcpinfo->num_cols)
				{
					goto LABEL_98;
				}
			}
			return bcpError(dbproc, 0);
		}
	LABEL_98:
		if (bcpinfo->direction != 1 || bcpInsert(dbproc) == 1)
			return SUCCEED;
	}
	return bcpError(dbproc, 0);
}


int __stdcall bcpLog(PDBPROCESS dbproc, int eid, int column)
{
	bcp_info_t* bcpinfo = 0;

	char* psql = 0;
	int i = 0;
	int errid = 0;
	BOOL bSucc = 0;
	int l1 = 0, l2 = 0;
	int l0 = 0; 
	char* lpMem = 0;
	BOOL bwErr = 0;
	BYTE* pold = 0;
	__int64 SiZ = 0;
	char Buffer[36] = {0};
	BOOL b1 = 0;

	bcpinfo = dbproc->bcpinfo;
	SiZ = 0;

	l0 = strlen("<Unable to display>");
	if (!bcpinfo->bcplog)
		return 0;
	psql = (char*)AllocateHeapMemory(4, dbproc, 512u, 0);
	if (!psql)
		return bcpError(dbproc, 0);
	_ltoa((unsigned __int16)++bcpinfo->lcol + bcpinfo->dcol, Buffer, 10);
	if (!*_errno())
	{
		if (eid != 0)
		{
			strcpy(psql, "#@ ");
			strcat(psql, szRow); // "Row"
			strcat(psql, " ");
			strcat(psql, Buffer); // nrow
			strcat(psql, ", ");
			strcat(psql, szCol); // "Column"
			strcat(psql, " ");
			_ltoa(column + 1, Buffer, 10);
			strcat(psql, Buffer);
			strcat(psql, ": ");
			errid = eid;
			if (eid < 0)
				errid = -eid;
			strcat(psql, dberrstr(errid));
			strcat(psql, " @#\r\n");
			LocalAnsiToOem(dbproc, psql);
			if (bcpinfo->bcplog->m_bMaped)
			{
				if (bcpinfo->bcplog->m_nToWriteSize + strlen(psql) <= 0x1000)
				{
					memmove((char*)bcpinfo->bcplog->m_pBuffer + LODWORD(bcpinfo->bcplog->m_nToWriteSize), psql, strlen(psql));
					bcpinfo->bcplog->m_nToWriteSize += lstrlen(psql);
				}
				else
					bSucc = bcpWrite(dbproc, bcpinfo->bcplog, strlen(psql), psql);
			}
			else
			{
				bSucc = bcpWrite(dbproc, bcpinfo->bcplog, strlen(psql), psql);

			}
			if (bSucc == 0)
			{
				FreeMemory(dbproc, psql);
				return bcpError(dbproc, 10065);
			}
		}

	}
	else
	{
		strcpy(psql, "#@ ");
		strcat(psql, szRow);
		strcat(psql, " ");
		strcat(psql, Buffer);
		strcat(psql, ", ");
		strcat(psql, szCol);
		strcat(psql, " ");
		_ltoa(column + 1, Buffer, 10);
		strcat(psql, Buffer);
		strcat(psql, ": ");

		strcat(psql, dberrstr(*_errno()));
		strcat(psql, " @#\r\n");
		LocalAnsiToOem(dbproc, psql);
		if (bcpinfo->bcplog->m_bMaped)
		{
			if (bcpinfo->bcplog->m_nToWriteSize + strlen(psql) <= 0x1000)
			{
				memmove((char*)bcpinfo->bcplog->m_pBuffer + LODWORD(bcpinfo->bcplog->m_nToWriteSize), psql, strlen(psql));
				bcpinfo->bcplog->m_nToWriteSize += strlen(psql);
				
			}else
				bSucc = bcpWrite(dbproc, bcpinfo->bcplog, strlen(psql), psql);
		}
		else
		{
			bSucc = bcpWrite(dbproc, bcpinfo->bcplog, strlen(psql), psql);
		}

		if (bSucc)
		{
			*_errno() = 0;
		}
		else
		{
			FreeMemory(dbproc, psql);
			return bcpError(dbproc, 10065);
		}

	}

	bwErr = 0;
	if (bcpinfo->direction == DB_IN)
	{
		i = 0;
		if (bcpinfo->num_cols)
		{
			while (1)
			{
				l2 = -1;
				b1 = 0;

				if (bcpinfo->columns)
				{
					l1 = bcpinfo->columns[i].varlen;
				}

				if (bcpinfo->bindinfo[i].usertype == SQLIMAGE 
					|| bcpinfo->bindinfo[i].usertype == SQLTEXT)
				{
					if (bcpinfo->columns[i].vardata)
					{
						if (bcpinfo->columns[i].varlen == 0)
						{
							l1 = bcpinfo->columns[i].collen;
						}
						else if (bcpinfo->columns[i].collen == 0 
							|| bcpinfo->columns[i].collen >= bcpinfo->columns[i].varlen)
						{
							l1 = bcpinfo->columns[i].varlen;
						}
						else
						{
							l1 = bcpinfo->columns[i].collen;
						}
					}
					else
					{

						if (bcpinfo->bcpdata->m_bMaped)
						{
							SiZ = bcpinfo->bcpdata->m_nMapSize;
						}
						else
						{
							SiZ = dbproc->bcpinfo->read_pos;
						}
						if (bcpinfo->bcpdata->m_bMaped)
						{
							bcpinfo->bcpdata->m_nMapSize = bcpinfo->columns[i].data_pos;
						}
						else if (!bcpSeek64(dbproc, bcpinfo->bcpdata, bcpinfo->columns[i].data_pos))
						{
							return 0;
						}

						if (bcpinfo->columns[i].column_datsize <= 2048)
						{
							l1 = 2 * l0 + 1;
							if (bcpinfo->columns[i].column_datsize > l1)
								l1 = bcpinfo->columns[i].column_datsize;
						}
						else
						{
							l1 = 2048;
						}

						pold = bcpinfo->columns[i].vardata;
						b1 = 1;
						bcpinfo->columns[i].vardata = (BYTE*)AllocateHeapMemory(4, dbproc, l1, 1);
						if (bcpRead(dbproc, bcpinfo->bcpdata, l1, bcpinfo->columns[i].vardata) == 1)
						{
							if (bcpinfo->columns[i].column_datsize <= 0x800)
							{
								l1 = bcpinfo->columns[i].column_datsize;
							}
							else
							{
								l1 = 2048;
							}

						}
						else if (bcpinfo->bindinfo[i].usertype == SQLIMAGE)
						{
							dbconvert(dbproc, SQLCHAR, (BYTE*)"<Unable to display>", l0, SQLIMAGE, bcpinfo->columns[i].vardata, l1);
						}else
						{
							strcpy((char*)bcpinfo->columns[i].vardata, "<Unable to display>");
							l1 = l0;
						}								
					}
				}
		
				if (bcpinfo->columns[i].usertype == SQLIMAGE)
				{
					lpMem = (char*)AllocateHeapMemory(4, dbproc, 2 * l1 + 1, 0);
					if (lpMem)
					{
						if (bcpinfo->columns)
						{
							if (bcpinfo->columns[i].vardata)
							{
								l2 = dbconvert(dbproc, SQLIMAGE, (BYTE*)bcpinfo->columns[i].vardata, l1, SQLCHAR, (LPBYTE)lpMem, 2 * l1 + 1);
							}
						}
					}
					else
					{
						strcpy(psql, "<Large IMAGE value>");
					}
				}
				else if (bcpinfo->columns[i].usertype == SQLTEXT)
				{
					lpMem = (char*)AllocateHeapMemory(4, dbproc, l1 + 1, 0);
					if (lpMem)
					{
						if (bcpinfo->columns)
						{
							if (bcpinfo->columns[i].vardata)
							{
								memmove(lpMem, bcpinfo->columns[i].vardata, l1);
							}
						}
					}
					else
					{
						strcpy(psql, "<Large TEXT value>");
					}
				}
				else
				{
					if (bcpinfo->columns)
					{
						if (bcpinfo->columns[i].vardata)
						{
							lpMem = 0;
							l2 = dbconvert(dbproc, bcpinfo->columns[i].usertype, bcpinfo->columns[i].vardata, l1, SQLCHAR, (LPBYTE)psql, 512);

						}
					}
				}
				if (l2 >= 0)
				{
					psql[l2] = 0;
				}
				else
				{
					strcpy(psql, "<Unable to display>");
				}
				if (i < bcpinfo->num_cols)
					strcat(psql, "\t");
				if (bcpinfo->bcplog->m_bMaped && bcpinfo->bcplog->m_nToWriteSize + strlen(psql) <= 0x1000)
				{
					memmove((char*)bcpinfo->bcplog->m_pBuffer + LODWORD(bcpinfo->bcplog->m_nToWriteSize), psql, strlen(psql));
					bcpinfo->bcplog->m_nToWriteSize += strlen(psql) + 1;
				}
				else
				{
					if (!bcpWrite(dbproc, bcpinfo->bcplog, strlen(psql), psql))
						bwErr = 1;
				}
				if (lpMem)
					FreeMemory(dbproc, lpMem);

				if (bcpinfo->bindinfo[i].usertype == SQLIMAGE || bcpinfo->bindinfo[i].usertype == SQLTEXT)
				{
					if (b1)
						FreeMemory(dbproc, bcpinfo->columns[i].vardata);
					bcpinfo->columns[i].vardata = pold;
					if (!bcpinfo->columns[i].vardata)
					{
						if (bcpinfo->bcpdata->m_bMaped)
						{
							bcpinfo->bcpdata->m_nMapSize = SiZ;
						}
						else if (!bcpSeek64(dbproc, bcpinfo->bcpdata, SiZ))
						{
							return 0;
						}
					}
				}
				if (++i >= bcpinfo->num_cols)
				{
					break;
				}
			}
		}
	}
	FreeMemory(dbproc, psql);
	if (bcpinfo->bcplog->m_bMaped && bcpinfo->bcplog->m_nToWriteSize + 1 <= 0x1000)
	{
		memmove((char*)bcpinfo->bcplog->m_pBuffer + LODWORD(bcpinfo->bcplog->m_nToWriteSize), "\n", 1u);
		bcpinfo->bcplog->m_nToWriteSize++;
	}
	else  if (!bcpWrite(dbproc, bcpinfo->bcplog, 1u, "\n") || bwErr)
	{
		GeneralError(dbproc, 10065);
	}

	if (eid > 0)
		GeneralError(dbproc, eid);
	return 0;
}
int __stdcall bcpSendText(PDBPROCESS dbproc, int index, int charset)
{
	bcp_info_t* bcpinfo = 0;
	bcp_column_t* columns = 0;
	int datsize = 0;
	bcp_bindinfo_t* bindinfo = 0;
	BYTE* vardata = 0;
	int length = 0;
	bcp_t* bcpdata = 0;

	int result = 0;
	int varlen = 0;

	BYTE* lpMem = 0; 


	int l0 = 0,l1 = 0,l3 = 0,l4 = 0;
	int OutLen = 0; 

	int flag; 

	__int64 SiZ = 0;
	BYTE locvar[256] = { 0 };

	bcpinfo = dbproc->bcpinfo;
	OutLen = 0;
	result = 1;
	flag = 0;
	columns = bcpinfo->textdata[index].columns;
	if (columns->column_datsize || (datsize = bcpinfo->textdata[index].bindinfo->datsize) == 0)
	{
		if (columns->vardata)
		{
			varlen = columns->varlen;
			length = columns->collen;
			if (varlen && (!length || length >= varlen))
				length = columns->varlen;
			if (!length)
			{
				if (++bcpinfo->textindex >= bcpinfo->maxcount)
					bcpinfo->maxcount = 0;
				return SUCCEED;
			}
			vardata = columns->vardata;
		}
		else
		{
			bcpdata = bcpinfo->bcpdata;
			if (bcpdata->m_bMaped)
			{
				SiZ = bcpdata->m_nMapSize;
			}
			else
			{
				SiZ = bcpinfo->read_pos;
			}

			if (bcpdata->m_bMaped)
			{
				bcpdata->m_nMapSize = columns->data_pos;
			}
			else
			{
				result = bcpSeek64(dbproc, bcpdata, columns->data_pos);
				if (!result)
					return result;

			}
			length = columns->column_datsize;
			if (length > 2048)
				length = 2048;
			vardata = (BYTE*)AllocateHeapMemory(4, dbproc, length, 0);
			if (!vardata)
				return 0;
		}
	}
	else
	{
		columns->column_datsize = datsize;
		bindinfo = bcpinfo->textdata[index].bindinfo;
		flag = 1;
		bcpinfo->textdata[index].datsize = bcpinfo->textdata[index].bindinfo->datsize;
		vardata = (BYTE*)bindinfo->vardata;
		length = bindinfo->datsize;
	}
	if (!bcpinfo->b_loaded && columns->vardata && columns->usertype == bcpinfo->textdata[index].type)
	{}
	else 
	{
		if (bcpinfo->textdata[index].type == SQLTEXT)
		{
			if (columns->usertype == SQLCHAR || columns->usertype == SQLTEXT)
			{}
			else 
			{
				l1 = bcpLengthConversion(columns->usertype, columns->varlen, SQLTEXT, 1);
				bcpinfo->textdata[index].datsize = l1;
				OutLen = l1 + 1;
			}

		}
		else
		{
			if (columns->usertype != SQLCHAR && columns->usertype != SQLTEXT)
			{}else
			{
				bcpinfo->textdata[index].datsize = (unsigned int)(columns->column_datsize + 1) >> 1;
				OutLen = (length + 1) >> 1;
			}

		}

	}
	if (OutLen)
	{
		lpMem = (BYTE*)AllocateHeapMemory(4, dbproc, OutLen, 0);
		if (!lpMem)
		{
			if (!flag && !columns->vardata)
				FreeMemory(dbproc, vardata);
			return 0;
		}

	}

	l3 = 0;
	l4 = 0;
	if (columns->column_datsize > 0)
	{
		while (1)
		{
			l4 = columns->column_datsize - l3;
			if (l4 < length)
				length = l4;
			if (!flag && !columns->vardata)
			{
				result = bcpRead(dbproc, bcpdata, length, vardata);
				if (result != 1)
					break;
			}
			if (OutLen)
			{
				if (columns->usertype == bcpinfo->textdata[index].type)
				{
					memmove(lpMem, vardata, length);
					l0 = length;
				}
				else
				{
					l0 = dbconvert(
						dbproc,
						(unsigned __int8)columns->usertype,
						(BYTE*)vardata,
						length,
						bcpinfo->textdata[index].type,
						lpMem,
						OutLen);
				}
				if (columns->vardata)
					bcpinfo->textdata[index].datsize = l0;
				if (l0 == -1)
				{
					result = 0;
					break;
				}
			}
			else
			{
				lpMem = vardata;
				l0 = length;
			}
			if (result == 1)
			{
				if (bcpinfo->textdata[index].type == SQLTEXT)
				{
					if ((dbproc->ret_status & 0x400) != 0)
					{
						LocalCharSetConvert(dbproc, (char*)lpMem, l0, 0);
					}

					if (charset)
					{
						if (dbproc->ansi)
						{
							LocalCharSetConvert(dbproc, (char*)lpMem, l0, 1);
						}
					}
					else if (!dbproc->ansi)
					{
						LocalCharSetConvert(dbproc, (char*)lpMem, l0, 2);
					}
				} 
				result = bcp_moretext(dbproc, l0, lpMem);

			}

			if (result == FAIL)
				break;

			l3 = length + l4;
			l4 += length;
			if (l4 >= columns->column_datsize)
				break;
		}


	}

	if (!columns->column_datsize && ++bcpinfo->textindex >= bcpinfo->maxcount)
		bcpinfo->maxcount = 0;
	if (!flag && columns->vardata)
	{
		FreeMemory(dbproc, vardata);
	}
	if (OutLen)
		FreeMemory(dbproc, lpMem);

	if (result == 1 && !columns->vardata && !flag)
	{
		if (bcpdata->m_bMaped)
		{
			bcpdata->m_nMapSize = SiZ;
			return SUCCEED;
		}
		else
		{
			return bcpSeek64(dbproc, bcpdata, SiZ);
		}
	}
	return result;
}
int __stdcall bcpSendRow(PDBPROCESS dbproc, int codepage)
{
	bcp_info_t* bcpinfo = 0; 
	bcp_column_t* columns = 0; 
	int SiZ = 0; 
	BYTE usertype = 0; 
	char* vardata = 0; 

	bcp_blob_t* meta = 0;
	int dSiz = 0; 
	int collen = 0; 

	char C, C1, C2, C3;
	int i, i0, i1,i2;
	int result = 0; 

	__int64 SZ = 0;

	int rSiz = 0; 

	char* Source = 0; 
	size_t Size = 0; 
	char* p1,* p0,* pe, * p2, * p3, * p4;

	char* pbuf = 0;
	BYTE typ0, typ;

	int l1, l2, l3; 
	bool B1 = 0;
	BOOL B3 = 0;
	int B2, B4, B5, B6, B7, BF;

	char buf1[4] = {0};

	bcp_bindinfo_t* bindinfo = 0; 
	DBNUMERIC numeric ;
	char buffer[256] = { 0 };

	bcpinfo = dbproc->bcpinfo;
	int l0 = bcpinfo->minlen;

	bcpinfo->maxcount = 0;
	bcpinfo->textindex = 0;
	bindinfo = bcpinfo->bindinfo;

	B4 = 0;
	B6 = 0;
	B7 = 0;
	B5 = 0;

	pbuf = bcpinfo->offset_val;
	if (dbproc->bServerType != 1 || (B1 = dbproc->ServerMajor < 5u, B2 = 1, B1))
		B2 = 0;

	buf1[0] = 0;
	memset(buffer, 0, sizeof(buffer));
	pe = &buffer[255];
	p1 = buf1;
	memset(bcpinfo->offset_val, 0, bcpinfo->maxlen + l0 + 11);
	if (l0 < bcpinfo->maxlen)
	{
		l1 = bcpinfo->maxlen;
		p0 = (char*)pbuf + l0 + 2;
	}
	else
	{
		p0 = 0;
		l1 = 0;
	}

	i = 0;

	if (bcpinfo->num_cols != 0)
	{
		while (1)
		{
			BF = 0;
			*_errno() = 0;

			columns = bindinfo[i].columnsinfo;

			if (columns)
			{
				SiZ = columns->varlen;
				if (SiZ || !bindinfo[i].vardata || (bindinfo[i].status & 8) != 0 && bcpinfo->keepnul)
				{
					vardata = (char*)columns->vardata;
					usertype = columns->usertype;
					goto LABEL_27;
				}
			}
			else if (!bindinfo[i].vardata)
			{
				if (bindinfo[i].type >= 0 && (bindinfo[i].status & 8) == 0)
					return bcpLog(dbproc, -10053, i);
				if (bindinfo[i].usertype == SQLTEXT || bindinfo[i].usertype == SQLIMAGE)
					++bcpinfo->maxcount;
				SiZ = 0;
				goto LABEL_16;
			}
			SiZ = bindinfo[i].datsize;
			usertype = (BYTE)bindinfo[i].commontype;
			BF = 1;
			vardata = (char*)bindinfo[i].vardata;
		LABEL_27:

			typ0 = usertype;
			if (bindinfo[i].usertype == SQLTEXT || bindinfo[i].usertype == SQLIMAGE)
			{

				typ0 = bindinfo[i].usertype;
				if (columns->column_datsize || !bindinfo[i].datsize)
				{
					vardata = (char*)pbuf;
					SiZ = columns->column_datsize != 0 ? 0x10 : 0;
				}
				else
				{
					BF = 1;
					vardata = (char*)bindinfo[i].vardata;
					SiZ = 16;
				}
				meta = &bcpinfo->textdata[bcpinfo->maxcount++];

				meta->bindinfo = &bindinfo[i];
				meta->columns = columns;
				meta->textsize = 0;
				meta->field_C = 0;
				meta->type = bindinfo[i].usertype;
				meta->offset = -LOBYTE(bindinfo[i].offset);
				meta->length = (WORD)(p0 - pbuf);
				if (columns->vardata)
				{
					dSiz = columns->varlen;
					if (dSiz)
					{
						collen = columns->collen;
						if (collen && collen < dSiz)
							dSiz = columns->collen;
					}
					else
					{
						dSiz = columns->collen;
					}

					meta->datsize = dSiz;
				}
				else
				{
					meta->datsize = columns->column_datsize;
				}
			}
			if (!SiZ && (bindinfo[i].status & 8) == 0)
				return bcpLog(dbproc, -10053, i);
			if (bindinfo[i].offset_val)
			{
				Source = (char*)bindinfo[i].offset_val;
				Size = bindinfo[i].length;
			}
			else
			{
				Source = p0;
				Size = l1;
			}
			if ((typ0 == SQLDECIMAL || typ0 == SQLNUMERIC) && SiZ)
				SiZ -= 2;
			B3 = !B2 || typ0 != SQLDECIMAL && typ0 != SQLNUMERIC || *vardata == bindinfo[i].precision && vardata[1] == bindinfo[i].scale;
			if (typ0 != bindinfo[i].usertype || !B3)
			{
				switch (bindinfo[i].usertype)
				{
				case SQLVARBINARY:
					typ = SQLBINARY;
					goto LABEL_119;
				case SQLINTN:
					if (bindinfo[i].length == 1)
					{
						typ = SQLINT1;
					}
					else if (bindinfo[i].length == 2)
					{
						typ = SQLINT2;
					}
					else
					{
						typ = SQLINT4;
					}
					goto LABEL_119;
				case SQLVARCHAR:
					i0 = 0;
					typ = SQLCHAR;

					if (!columns || columns->termlen != 1 || *columns->terminator)
						goto LABEL_89;
					if (SiZ <= 0)
					{
						if (!SiZ)
						{
							Size = 0;
							goto LABEL_119;
						}
						B7 = 1;

						SiZ = strlen(vardata);
						Size = strlen(vardata);
					}
					else
					{
						while (vardata[i0])
						{
							if (++i0 >= SiZ)
								goto LABEL_89;
						}
						if (i0 < SiZ)
						{
							SiZ = i0;
							Size = i0 + 1;
						}
					}
				LABEL_89:
					if (SiZ <= 0)
						goto LABEL_119;
					C = vardata[SiZ - 1];
					B7 = 0;
					if (C == ' ')
					{
						i1 = SiZ - 1;
						if (vardata[SiZ - 1] == ' ')
						{
							do
							{
								if (i1 <= 0)
									break;
								C = vardata[--i1];
							} while (C == ' ');
						}
						SiZ = i1 + 1;
					}
					goto LABEL_121;
				case SQLFLTN:
					typ = SQLFLT8;
					if (bindinfo[i].length == 4)
					{
						typ = SQLFLT4;
					}
					goto LABEL_119;
				case SQLMONEYN:
					typ = SQLMONEY;
					if (bindinfo[i].length == 4)
					{
						typ = SQLMONEY4;
					}
					goto LABEL_119;
				case SQLDATETIMN:
					typ = SQLDATETIME;
					if (typ0 != SQLCHAR && typ0 != SQLVARCHAR)
						goto LABEL_113;
					i1 = 0;
					if (SiZ <= 0)
						goto LABEL_112;
					while (1)
					{
						C = vardata[i1];
						if (C != ' ')
						{
							if (C)
								break;
						}
						if (C)
						{
							if (++i1 < SiZ)
								continue;
						}
					LABEL_112:
						SiZ = 0;
						break;
					}
				LABEL_113:
					if (bindinfo[i].length == 4)
					{
						typ = SQLDATETIM4;
					}
					goto LABEL_119;
				default:
					if (bindinfo[i].usertype == SQLIMAGE || bindinfo[i].usertype == SQLTEXT)
					{
						memset(Source, 0, SiZ);
						goto LABEL_144;
					}
					if (bindinfo[i].usertype == SQLBIT)
						C2 = *Source;
				LABEL_119:
					if (B7 && !Size)
						goto LABEL_136;
				LABEL_121:
					if (SiZ)
					{
						if (typ0 == bindinfo[i].usertype && B3)
						{
							if (SiZ <= bindinfo[i].length)
							{
							}
							else
							{
								if (!BF)
									GeneralError(dbproc, 10054);
								SiZ = Size;
								if (bindinfo[i].length <= Size)
									SiZ = bindinfo[i].length;
							}
							memmove(Source, vardata, SiZ);
						}
						else if (bindinfo[i].usertype == SQLDECIMAL || bindinfo[i].usertype == SQLNUMERIC)
						{
							numeric.precision = bindinfo[i].precision;
							numeric.scale = bindinfo[i].scale;
	
							if (((CONVERTFUNC)bindinfo[i].convfunc)(
								dbproc,
								typ0,
								(BYTE*)vardata,
								SiZ,
								typ,
								(char*)&numeric,
								Size) == -1)
								goto LABEL_176;
							SiZ = (unsigned __int8)GetMaxNumericBytes(numeric.precision);
							memmove(Source, &numeric.sign, SiZ);
						}
						else
						{

							SiZ = ((CONVERTFUNC)bindinfo[i].convfunc)(
								dbproc,
								typ0,
								(BYTE*)vardata,
								SiZ,
								(unsigned __int8)typ,
								Source,
								Size);
						}
					}
					else
					{
				LABEL_136:;
					}
					if (B7 == 1)
					{
						if ((int)Size > SiZ + 1)
						{
							Size = Size - 1;
							memset(&Source[SiZ], ' ',(Size - SiZ) );
						}
						SiZ = Size;
						B7 = 0;
					}
					if (bindinfo[i].usertype == SQLBIT)
					{
						C2 |= *Source << bindinfo[i].status;
						*Source = C2;
					}
				LABEL_144:
					if (SiZ >= 0)
						goto LABEL_145;
				LABEL_176:
					result = bcpLog(dbproc, -10039, i);
					break;
				}
				return result;
			}
			if (B2 && (typ0 == SQLDECIMAL || typ0 == SQLNUMERIC))
				SiZ = (unsigned __int8)GetMaxNumericBytes(*vardata);
			if (SiZ <= (int)Size)
			{
			}
			else
			{
				if (!BF)
					GeneralError(dbproc, 10054);
				SiZ = Size;
			}
			switch (typ0)
			{
			case SQLIMAGE:
			case SQLTEXT:
				memset(Source, 0, SiZ);
				break;
			case SQLBIT:
				if (*vardata)
				{
					C3 = (1 << bindinfo[i].status) | *Source;
					C2 = 1 << bindinfo[i].status;
					*Source = C3;
				}
				else
				{
					C2 = 0;
					*Source = *Source;
				}
				break;
			case SQLDECIMAL:
			case SQLNUMERIC:
				memmove(Source, vardata + 2, SiZ);
				break;
			default:
				memmove(Source, vardata, SiZ);
				break;
			}
		LABEL_145:
			if (bindinfo[i].usertype == SQLCHAR || bindinfo[i].usertype == SQLVARCHAR)
			{
				if ((dbproc->ret_status & 0x400) != 0)
				{
					LocalCharSetConvert(dbproc, Source, SiZ, 0);
				}
				else
				{
	
					if (codepage)
					{
						if (dbproc->ansi)
							LocalCharSetConvert(dbproc, Source, SiZ, 1);
					}
					else if (!dbproc->ansi)
					{
						LocalCharSetConvert(dbproc, Source, SiZ, 2);
					}
				}
			}
			if (bindinfo[i].offset_val)
			{
				if (SiZ < (int)Size)
				{
					if (bindinfo[i].usertype == SQLCHAR || bindinfo[i].usertype == SQLVARCHAR)
					{
						C = ' ';
						l2 = Size - SiZ;
					}
					else
					{
						l2 = Size - SiZ;
						C = 0;
					}
					memset(&Source[l2 + SiZ], C, l2);
				}

				goto LABEL_162;
			}
		LABEL_16:

			C = *(char*)pbuf;
			*pe = (char)(p0 - pbuf);
			pe--;

			if (C == 0)
			{
				l2 = (p0 - pbuf) / 256;
				if (l2 > 0)
				{
					do
					{
						*p1-- = 1;
						--l2;
					} while (l2);

				}

			}
			if (B5)
			{
				if (!SiZ)
					goto LABEL_173;
				B4 = 1;
				B5 = 0;
				*p1 = C + 1;
				p1--;
			}
			else
			{
				B4 = 0;
			}
			if (SiZ)
			{
				B6 = 0;
				if ((p0 - pbuf) / 256 != (int)&p0[SiZ - (_DWORD)pbuf] / 256)
					B5 = 1;
				p0 += SiZ;
				l1 -= SiZ;
				*pbuf = C + 1;
				goto LABEL_162;
			}
		LABEL_173:
			B6 = 1;
			*pbuf = C + 1;
		LABEL_162:
			i++;

			if (i >= bcpinfo->num_cols)
			{
				break;
			}
		}
	}


	C = *pbuf;
	if (!*pbuf)
		goto LABEL_197;
	if (B6)
	{
		l2 = C - 1;
		pe++;
		*pbuf = C - 1;
		if (C != 1)
		{
			do
			{
				if (*pe != pe[1])
					break;
				++pe;
				*pbuf = --l2;
			} while (l2);

		}
		if (B4)
			++p1;
		p2 = p1 + 1;
		C = *pbuf;
		if (p1[1] > *pbuf)
		{
			do
			{
				if (p2 >= buf1)
					break;
				C1 = *++p2;
				++p1;
			} while (C1 > l2);
		}
	}
	if (C)
	{
		p3 = pe;
		*pe = (char)(p0 - pbuf);

		*p1 = C + 1;
		if (p1 >= &buf1[1])
		{
			p4 = p0;
		}
		else
		{
			qmemcpy(p0, p1, &buf1[1] - p1);
			p3 = pe;
			p4 = &p0[&buf1[1] - p1];
		}
		if (p3 < &buffer[256])
		{
			qmemcpy(p4, p3, (char*)&buffer[256] - (char*)p3);
			p4 += (char*)&buffer[256] - (char*)p3;
		}

		l3 = p4 - pbuf;
		*(WORD*)((char*)pbuf + l0) = (WORD)((int)p4 - (int)pbuf);
		l0 = l3;
	}
	else
	{
	LABEL_197:
		l3 = l0;
	}
	if (l0 > 1962u || l0 > bcpinfo->maxlen)
		return bcpLog(dbproc, -10106, i);
	result = queuepacket(dbproc, (BYTE*)&l3, 2u);
	if (result)
	{
		if (queuepacket(dbproc, (BYTE*)pbuf, l3))
		{

			++bcpinfo->dcol;
			++bcpinfo->result;
			if (bcpinfo->maxcount != 0)
			{
				i2 = 0;
				while (1)
				{
					bcp_column_t *pcol = &bcpinfo->textdata->columns[i2];
					if (!pcol || bcpinfo->b_loaded && !pcol->vardata)
						break;
					if (!bcpSendText(dbproc, i2, codepage))
						return 0;
					if (!bcpinfo->b_loaded && i2 >= bcpinfo->maxcount)
					{

						if (bcpinfo->bcpdata->m_bMaped)
						{
							SZ = bcpinfo->bcpdata->m_nMapSize;
						}
						else
						{
							SZ = dbproc->bcpinfo->read_pos;
						}
						rSiz = bcpRead(dbproc, bcpinfo->bcpdata, 1u, &C2);

						if (bcpinfo->bcpdata->m_bMaped)
						{
							bcpinfo->bcpdata->m_nMapSize = SZ;
						}
						else
						{
							bcpSeek64(dbproc, bcpinfo->bcpdata, SZ);
						}
						if (rSiz == 100)
							return 100;
					}

					++i2;

					if (i2 >= bcpinfo->maxcount)
						return SUCCEED;

				}
			}
			return SUCCEED;
		}
		else
		{
			return 0;
		}
	}
	return result;
}


int __stdcall bcpSendRecord(PDBPROCESS dbproc, int bSend)
{
	bcp_info_t* bcpinfo = 0; 
	int result = 0; 
	__int64 SiZ = 0;
	int l0 = 0; 
	char C = 0; 
	BYTE* pvar = 0; 

	int prefixlen = 0,rLength = 0;
	int i = 0; 
	int bnolog = 0; 


	bcp_bindinfo_t* bindinfo = 0; 

	bcpinfo = dbproc->bcpinfo;

	i = 0;
	if (bcpinfo->ncols)
	{
		while (1)
		{

			bindinfo = bcpinfo->columns[i].bindinfo;

			bnolog = 0;
			if (bcpinfo->columns[i].prefixlen == 0)
			{
				rLength = bcpinfo->columns[i].termlen == 0 ? bcpinfo->columns[i].collen : 0;
				prefixlen = rLength;
			}
			else
			{
				rLength = 0;
				/*
				* 读长度
				*/
				result = bcpRead(dbproc, bcpinfo->bcpdata, bcpinfo->columns[i].prefixlen, &rLength);
				if (result != 1)
					return result;
				prefixlen = rLength;
			}
			if (bSend && bindinfo)
			{
				if (prefixlen == 0)
				{
					result = get_col_data(dbproc, bcpinfo->bcpdata, &bcpinfo->columns[i], &rLength);
					if (result != 1)
						return result;
					prefixlen = rLength;
				}
				if (bcpinfo->columns[i].vardata == 0 || prefixlen == 0)
				{
					if (bcpinfo->bcpdata->m_bMaped)
					{
						SiZ = bcpinfo->bcpdata->m_nMapSize;
					}
					else
					{
						SiZ = dbproc->bcpinfo->read_pos;
					}
					bcpinfo->columns[i].data_pos = SiZ;
					bcpinfo->columns[i].column_datsize = rLength;
					bcpinfo->columns[i].varlen = 0;

					if (SiZ + (unsigned int)rLength + bcpinfo->columns[i].termlen > dbproc->bcpinfo->filesize)
					{
						GeneralError(dbproc, 10067);
						return 0;
					}

					if (bcpinfo->bcpdata->m_bMaped)
					{
						bcpinfo->bcpdata->m_nMapSize = bcpinfo->columns[i].termlen + bcpinfo->columns[i].data_pos + rLength;
					}
					else if (!bcpSeek64(dbproc, bcpinfo->bcpdata, bcpinfo->columns[i].termlen + bcpinfo->columns[i].data_pos + rLength))
					{
						return 0;
					}

					if (rLength < bcpinfo->columns[i].collen)
					{
						if (bcpinfo->columns[i].usertype == SQLCHAR || bcpinfo->columns[i].usertype == SQLVARCHAR)
						{
							l0 = bcpinfo->columns[i].collen - rLength;
							C = ' ';
						}
						else
						{
							l0 = bcpinfo->columns[i].collen - rLength;
							C = 0;
						}
						pvar = &bcpinfo->columns[i].vardata[rLength];
						memset(pvar, C, l0);
					}

				}
				else 
				{
					if (bcpinfo->columns[i].balloced)
					{
						FreeMemory(dbproc, bcpinfo->columns[i].vardata);
						prefixlen = rLength;
					}
					int ll = 0;
					if (bcpinfo->columns[i].collen >= prefixlen)
					{
						ll = bcpinfo->columns[i].collen;
						prefixlen = rLength;
					}
					else
					{
						ll = prefixlen;
						prefixlen = rLength;
					}
					bcpinfo->columns[i].vardata = (BYTE*)AllocateHeapMemory(4, dbproc, ll, 1);

					result = bcpRead(dbproc, bcpinfo->bcpdata, prefixlen, bcpinfo->columns[i].vardata);
					if (rLength && result != 1)
						return result;

					bcpinfo->columns[i].varlen = rLength;
					bcpinfo->columns[i].column_datsize = rLength;
					if (bcpinfo->columns[i].termlen)
					{
						if (bcpinfo->bcpdata->m_bMaped)
						{
							bcpinfo->bcpdata->m_nMapSize += bcpinfo->columns[i].termlen;

						}
						else if (!bcpSeek64(dbproc, bcpinfo->bcpdata, dbproc->bcpinfo->read_pos + bcpinfo->columns[i].termlen))
						{
							return 0;
						}
					}

					if (rLength < bcpinfo->columns[i].collen)
					{
						if (bcpinfo->columns[i].usertype == SQLCHAR || bcpinfo->columns[i].usertype == SQLVARCHAR)
						{
							l0 = bcpinfo->columns[i].collen - rLength;
							C = ' ';
						}
						else
						{
							l0 = bcpinfo->columns[i].collen - rLength;
							C = 0;
						}
						pvar = &bcpinfo->columns[i].vardata[rLength];
						memset(pvar, C, l0);
					}
				}

			}
			else 
			{
				bnolog = 1;
				if (prefixlen)
				{
					if (bcpinfo->bcpdata->m_bMaped)
					{
						bcpinfo->bcpdata->m_nMapSize += prefixlen;
					}
					else if (!bcpSeek64(dbproc, bcpinfo->bcpdata, prefixlen + dbproc->bcpinfo->read_pos))
					{
						return 0;
					}
				}
				else
				{
					result = get_col_data(dbproc, bcpinfo->bcpdata, &bcpinfo->columns[i], 0);
					if (result != 1)
						return result;
				}
			}

			if (bindinfo
				&& (bindinfo->status & 8) == 0
				&& !bindinfo->vardata
				&& !bcpinfo->columns[i].varlen
				&& !bcpinfo->columns[i].column_datsize
				&& bSend
				&& !bnolog)
			{
				return bcpLog(dbproc, -10053, i);
			}

			if (++i >= bcpinfo->ncols)
				break;

		}
	
	}

	result = 1;
	if (bSend == 1)
		return bcpSendRow(dbproc, 1);
	return result;
}
int __stdcall bcpRead(PDBPROCESS dbproc, bcp_t* bcp, size_t Size, void* lpBuffer)
{
	bcp_info_t* bcpinfo = 0; 

	DWORD rSize = 0;
 
	unsigned int hig = 0; 
	unsigned int low = 0; 
	__int64 SiZ = 0;
	BYTE* pold = 0; 

	if (!bcp->m_bMaped)
	{
		bcpinfo = dbproc->bcpinfo;
		if (bcpinfo->blkbuffer == 0)
		{
			rSize = -(ReadFileNT(bcp->m_hFile, lpBuffer, Size) != 0);
			BYTE a = rSize & 0x9D;
			return a + 100;
		}

		if (Size <= 0x2000)
		{
			if (bcpinfo->read_size == -1)
			{
				rSize = ReadFileNT(bcp->m_hFile, bcpinfo->blkbuffer, 0x2000u);
				if (!rSize)
					return 100;
				bcpinfo->read_fail = rSize != 0x2000;
				bcpinfo->read_size = rSize - 1;
			}
			if (bcpinfo->read_fail && bcpinfo->read_pos > bcpinfo->read_size)
				return 100;
			hig = HIDWORD(bcpinfo->read_pos);
			low = (DWORD)bcpinfo->read_pos;
			if (bcpinfo->read_pos < bcpinfo->total_size || bcpinfo->read_pos + Size > bcpinfo->read_size)
			{
				if (hig || low >= 2048)
				{
					SiZ = bcpinfo->read_pos - 2048;
				}
				else
				{
					SiZ = 0;
				}
				pold = bcpinfo->blkbuffer;
				bcpinfo->blkbuffer = 0;

				if (bcp->m_bMaped)
				{
					bcp->m_nMapSize = SiZ;
				}
				else
				{
					bcpSeek64(dbproc, bcp, SiZ);
				}
				bcpinfo->blkbuffer = pold;
				rSize = ReadFileNT(bcp->m_hFile, pold, 0x2000u);
				if (!rSize)
					return 100;

				bcpinfo->total_size = SiZ;
				bcpinfo->read_size = SiZ + rSize - 1;
				bcpinfo->read_fail = rSize != 0x2000;

			}
			if (!lpBuffer)
				return SUCCEED;
			memmove(lpBuffer, (const void*)(bcpinfo->blkbuffer + bcpinfo->read_pos - bcpinfo->total_size), Size);
		}
		else if (!ReadFileNT(bcp->m_hFile, lpBuffer, Size))
		{
			return 100;
		}

		bcpinfo->read_pos += Size;

		return SUCCEED;
	}
	if ((__int64)Size + bcp->m_nMapSize > bcp->m_nFileSize)
		return 100;
	qmemcpy(lpBuffer, (char*)bcp->m_pMap + bcp->m_nMapSize, Size);
	bcp->m_nMapSize += Size;

	return SUCCEED;
}

int __stdcall bcpSend(PDBPROCESS dbproc)
{
	bcp_info_t* bcpinfo = 0; 
 
	int l1 = 0; 
	int l0 = 0;
	__int64 SiZ = 0;
	int result = 0; 
	int batch = 0; 
	int i = 0; 
	int last = 0; 
	int nrow = 0; 
	int l2 = 0; 

	i = 0;

	bcpinfo = dbproc->bcpinfo;
	nrow = 0;

	if (bcpinfo->bcpdata->m_hFile)
		bcpinfo->filesize = GetFileSize(bcpinfo->bcpdata->m_hFile, 0);
	else
		bcpinfo->filesize = 0;

	l1 = 1;
	l2 = 1;
	if (bcpinfo->first <= 1)
	{
	LABEL_9:
		if (l1 <= bcpinfo->last)
		{
			while (1)
			{
				if ((dbproc->ret_status & 0x100) != 0)
					goto LABEL_33;
				if (bcpinfo->bcpdata->m_bMaped)
				{
					SiZ = bcpinfo->bcpdata->m_nMapSize;
				}
				else
				{
					SiZ = dbproc->bcpinfo->read_pos;
				}
				result = bcpSendRecord(dbproc, 1);
				if (result == 100)
					break;
				if (result != 1)
				{
					if ((unsigned __int16)++nrow >= (unsigned int)bcpinfo->maxerrs)
					{
						if (sendflush(dbproc))
						{
							if (dbsqlok(dbproc))
							{
								for (int ret = dbresults(dbproc); ret != NO_MORE_RESULTS; ret = dbresults(dbproc))
								{
									if (ret == FAIL)
										break;
								}
							}
						}
						return bcpError(dbproc, 0);
					}

					if (bcpinfo->bcpdata->m_bMaped)
					{
						bcpinfo->bcpdata->m_nMapSize = SiZ;
					}
					else
					{
						bcpSeek64(dbproc, bcpinfo->bcpdata, SiZ);
					}
					bcpSendRecord(dbproc, 0);
				}
				batch = bcpinfo->batch;
				++l2;

				++i;
				if (batch > 0 && bcpinfo->result >= batch)
				{
					if (bcp_batch(dbproc) == -1)
						return 0;
					GeneralError(dbproc, 10050);
				}
				if (i == 1000)
				{
					i = 0;
					if (!bcpinfo->batch)
						bcpErrorHandle(dbproc, 10051, 0, nrow, 0);
				}
				if (l2 > bcpinfo->last)
					goto LABEL_33;
			}
			if (l2 >= bcpinfo->first)
				goto LABEL_33;
			return bcpError(dbproc, 0);
		}
	LABEL_33:
		if (bcp_batch(dbproc) == -1)
		{
			return 0;
		}
		else
		{
			last = bcpinfo->last;
			if (last != 0x7FFFFFFF && bcpinfo->dcol < last - bcpinfo->first + 1)
				GeneralError(dbproc, 10067);
			if (!bcpinfo->dcol && l2 == 100)
				GeneralError(dbproc, 10067);
			return SUCCEED;
		}
	}
	else
	{
		while (1)
		{
			if ((dbproc->ret_status & 0x100) != 0)
			{
			LABEL_8:
				l2 = l1;
				goto LABEL_9;
			}
			if (bcpSendRecord(dbproc, 0) != 1)
				break;
			if (++l1 >= bcpinfo->first)
				goto LABEL_8;
		}
		l0 = bcpinfo->dcol;
		if (l1 >= bcpinfo->first)
			bcpErrorHandle(dbproc, 10097, bcpinfo->p_tabname, l1, 0);
		bcpinfo->dcol = l1;
		bcpLog(dbproc, 10067, 0);
		bcpinfo->dcol = l0;
		bcpClose(dbproc, bcpinfo->bcpdata);
		bcpClose(dbproc, bcpinfo->bcplog);
		return bcpError(dbproc, 0);
	}
}
BYTE __stdcall bcpDataNameToToken(char* pname)
{
	char* p0 = 0; 


	if (pname[0] == 'S' && (pname[1] == 'Y' && pname[2] == 'B' || pname[1] == 'Q' && pname[2] == 'L'))
	{
		p0 = pname + 3;
		switch (strlen(p0))
		{
		case 3u:
			if (*p0 == 'I' && pname[4] == 'N' && pname[5] == 'T')
				return SQLINT4;
			if (*p0 != 'B' || pname[4] != 'I' || pname[5] != 'T')
				return 0;
			return SQLBIT;
		case 4u:
			if (!strncmp(p0, "char", 4u))
				return SQLCHAR;
			if (!strncmp(p0, "FLT", 3u))
			{
				if (pname[6] == '4')
					return SQLFLT4;
				if (pname[6] == '8')
					return SQLFLT8;
				return 0;
			}
			if (strncmp(p0, "TEXT", 4u))
				return 0;
			return SQLTEXT;
		case 5u:
			if (!strncmp(p0, "MONEY", 5u))
				return 60;
			if (strncmp(p0, "IMAGE", 5u))
				return 0;
			return SQLIMAGE;
		case 6u:
			if (*p0 == 'B')
			{
				if (strncmp(p0, "BINARY", 6u))
					return 0;
				return SQLBINARY;
			}
			else
			{
				if (strncmp(p0, "MONEY4", 6u))
					return 0;
				return SQLMONEY4;
			}
		case 7u:
			if (*p0 == 'T')
			{
				if (strncmp(p0, "TINYINT", 7u))
					return 0;
				return SQLINT1;
			}
			if (!strncmp(p0, "VARYBIN", 7u))
				return SQLVARBINARY;
			if (!strncmp(p0, "DECIMAL", 7u))
				return SQLDECIMAL;
			if (!strncmp(p0, "NUMERIC", 7u))
				return SQLNUMERIC;
			return 0;
		case 8u:
			if (*p0 == 'S')
			{
				if (strncmp(p0, "SMALLINT", 8u))
					return 0;
				return SQLINT2;
			}
			if (*p0 == 'V')
			{
				if (strncmp(p0, "VARYCHAR", 8u))
					return 0;
				return 39;
			}
			if (strncmp(p0, "DATETIM", 7u))
				return 0;
			if (pname[10] == 'E')
				return SQLDATETIME;
			if (pname[10] == '4')
				return SQLDATETIM4;
			break;
		default:
			return 0;
		}
	}
	return 0;
}
int __stdcall bcpDataTokenToName(BYTE token, char* lpName)
{
	int index = -1; 

	switch (token)
	{
	case SQLIMAGE:
	case SQLBINARY:
		index = 6;
		break;
	case SQLTEXT:
	case SQLCHAR:
		index = 2;
		break;
	case SQLVARBINARY:
		index = 11;
		break;
	case SQLINTN:
	case SQLINT4:
		index = 1;
		break;
	case SQLVARCHAR:
		index = 10;
		break;
	case SQLINT1:
		index = 8;
		break;
	case SQLBIT:
		index = 0;
		break;
	case SQLINT2:
		index = 9;
		break;
	case 0x37u:
	case SQLDECIMAL:
		index = 15;
		break;
	case SQLDATETIM4:
		index = 13;
		break;
	case SQLFLT4:
		index = 4;
		break;
	case SQLMONEY:
	case SQLMONEYN:
		index = 5;
		break;
	case SQLDATETIME:
	case SQLDATETIMN:
		index = 12;
		break;
	case SQLFLT8:
	case SQLFLTN:
		index = 3;
		break;
	case 0x3Fu:
	case SQLNUMERIC:
		index = 14;
		break;
	case SQLMONEY4:
		index = 7;
		break;
	default:
		return 0;

	}

	dbmove((void*)bcpdatatypes[index], lpName, strlen(bcpdatatypes[index]) + 1);

	return SUCCEED;
}

int __stdcall bcpParse(PDBPROCESS dbproc, LPCSTR tblname, char* Destination)
{

	char C = 0; 
	char* p0,* p1; 
	int l0 = 0; 
	int l1 = 0; 
	const char* p2 = 0; 

	if (!tblname)
		return bcpError(dbproc, 10069);
	C = *tblname;
	for (p0 = (char*)tblname; C; C = *++p0)
	{
		if (C == '.')
			break;
	}
	if (*p0 == '.')
	{
		l0 = p0 - tblname;
		tblname = ++p0;
		p1 = p0;
	}
	else
	{
		p1 = (char*)tblname;
		l0 = 0;
	}
	for (C = *p0; C; C = *++p0)
	{
		if (C == '.')
			break;
	}
	if (*p0 == '.')
	{
		l1 = p0 - p1;
		p2 = p0 + 1;
		if (l0 >= 31)
			return bcpError(dbproc, SQLEPARM);
	}
	else
	{
		l1 = l0;
		l0 = 0;
		p2 = p1;

	}
	if (l1 < 31 && strlen(p2) < 31)
	{
		strncpy(Destination, tblname, l0);
		Destination[l0] = 0;
		strncpy(Destination + 31, tblname, l1);
		Destination[l1 + 31] = 0;
		strcpy(Destination + 62, p2);
		return SUCCEED;
	}
	return bcpError(dbproc, SQLEPARM);
}
int __stdcall bcpConvertLiteralToBinary(char* lpBufferIn, char* lpBufferOut)
{
	char* p0,* p1,* p2,*p3;
	char c0, c1, c3, c4,c5; 
	int c2 = 0; 
	char C, C1, C2;

	p0 = lpBufferIn;
	C = *lpBufferIn;
	if (!*lpBufferIn)
	{

		*lpBufferOut = 0;
		return SUCCEED;
	}
	while (C != '\\')
	{
		*p0++ = *lpBufferOut++;
	LABEL_45:
		C = *p0;
		if (!*p0)
		{
			*lpBufferOut = 0;
			return SUCCEED;
		}
	}
	C1 = p0[1];
	if (C1 >= '0' && C1 <= '7')
	{
		C1 = p0[1];
		C2 = p0[2];
		p1 = p0 + 1;
		c1 = C1 - '0';
		if (C2 >= '0' && C2 <= '7')
		{
			c1 = *++p1 + 8 * (c1 + 26);
			c5 = p1[1];
			if (c5 >= '0' && c5 <= '7')
			{
				c1 = *++p1 + 8 * (c1 + 26);
			}
		}
		p0 = p1 + 1;
		*lpBufferOut++ = c1;
		goto LABEL_45;
	}
	if (C1 != 'x')
	{
		c2 = p0[1];
		p2 = p0 + 1;
		switch (c2)
		{
		case SQLIMAGE:
			*lpBufferOut = SQLIMAGE;
			break;
		case SQLVARCHAR:
			*lpBufferOut = SQLVARCHAR;
			break;
		case 0x3F:
			*lpBufferOut = 0x3F;
			break;
		case 0x5C:
			*lpBufferOut = 0x5C;
			break;
		case 0x61:
			*lpBufferOut = 7;
			break;
		case 0x62:
			*lpBufferOut = 8;
			break;
		case 0x66:
			*lpBufferOut = 12;
			break;
		case SQLMONEYN:
			*lpBufferOut = 10;
			break;
		case 0x72:
			*lpBufferOut = 13;
			break;
		case 0x74:
			*lpBufferOut = 9;
			break;
		case 0x76:
			*lpBufferOut = 11;
			break;
		default:
			return 0;
		}
		++lpBufferOut;
		p0 = p2 + 1;
		goto LABEL_45;
	}
	c3 = p0[2];
	p3 = p0 + 2;
	if (c3 >= '0' && c3 <= '9')
	{
		c0 = c3 - '0';
	LABEL_22:
		c4 = p3[1];
		p0 = p3 + 1;
		if (c4 < '0' || c4 > '9')
		{
			if (c4 < 'A' || c4 > 'F')
			{
				if (c4 >= 'a' && c4 <= 'f')
				{
					c0 = c4 + 16 * c0 - 'W';
					++p0;
				}
				*lpBufferOut++ = c0;
			}
			else
			{
				++p0;
				*lpBufferOut++ = c4 + 16 * c0 - '7';
			}
		}
		else
		{
			++p0;
			*lpBufferOut++ = c4 + 16 * (c0 + 13);
		}
		goto LABEL_45;
	}
	if (c3 >= 'A' && c3 <= 'F')
	{
		c0 = c3 - '7';
		goto LABEL_22;
	}
	if (c3 >= 'a' && c3 <= 'f')
	{
		c0 = c3 - 'W';
		goto LABEL_22;
	}
	return 0;
}
BYTE* __stdcall bcpConvertBinaryToLiteral(BYTE* Src, char* Dst, int length)
{
	BYTE* p = 0; 
	BYTE* result = 0;

	p = Src;
	if (Src >= &Src[length])
	{
		result = (BYTE*)Dst;
		*Dst = 0;
	}
	else
	{
		result = (BYTE*)Dst;
		do
		{
			switch (*p)
			{
			case 7u:
				*result++ = '\\';
				*result = 'a';
				break;
			case 8u:
				*result++ = '\\';
				*result = 'b';
				break;
			case 9u:
				*result++ = '\\';
				*result = 't';
				break;
			case 0xAu:
				*result++ = '\\';
				*result = 'n';
				break;
			case 0xBu:
				*result++ = '\\';
				*result = 'v';
				break;
			case 0xCu:
				*result++ = '\\';
				*result = 'f';
				break;
			case 0xDu:
				*result++ = '\\';
				*result = 'r';
				break;
			case 0x22:
				*result++ = '\\';
				*result = '"';
				break;
			case 0x27:
				*result++ = '\\';
				*result = '\'';
				break;
			case 0x3Fu: // ?
				*result++ = '\\';
				*result = '?';
				break;
			case 0x5Cu:
				*result++ = '\\';
				*result = '\\';
				break;
			default:
				*result = *p;
				break;
			}
			++result;
			++p;
		} while (p < &Src[length]);
		*result = 0;
	}
	return result;
}
int __stdcall bcpLengthConversion(char type, int length, char usertype, int direction)
{
	int result = 0; 

	switch (usertype)
	{
	case SQLIMAGE:
	case SQLVARBINARY:
	case SQLBINARY:
		if (type == SQLTEXT || type == SQLIMAGE)
			return 0;
		result = length;
		break;
	case SQLTEXT:
	case SQLVARCHAR:
	case SQLCHAR:
		switch (type)
		{
		case SQLIMAGE:
		case SQLTEXT:
			return 0;
		case SQLVARBINARY:
		case SQLBINARY:
			result = 2 * length + 1;
			break;
		case SQLVARCHAR:
		case SQLCHAR:
			result = length;
			break;
		case SQLINT1:
			result = 5;
			break;
		case SQLBIT:
			result = 3;
			break;
		case SQLINT2:
			result = 7;
			break;
		case 0x37:
		case 0x3F:
		case SQLDECIMAL:
		case SQLNUMERIC:
			result = 41;
			break;
		case SQLINT4:
			result = 12;
			break;
		case SQLDATETIM4:
		case SQLFLT4:
		case SQLMONEY:
		case SQLDATETIME:
		case SQLFLT8:
		case SQLFLTN:
		case SQLMONEYN:
		case SQLDATETIMN:
		case SQLMONEY4:
			result = 30;
			break;
		default:
			result = length / 3 + 2 * length + 3;
			break;
		}
		break;
	case SQLINTN:
	case SQLINT4:
	case SQLDATETIM4:
	case SQLFLT4:
	case SQLMONEY4:
		result = 4;
		break;
	case SQLINT1:
	case SQLBIT:
		result = 1;
		break;
	case SQLINT2:
		result = 2;
		break;
	case 0x37:
	case 0x3F:
	case SQLDECIMAL:
	case SQLNUMERIC:
		result = 19;
		break;
	case SQLMONEY:
	case SQLDATETIME:
	case SQLFLT8:
	case SQLFLTN:
	case SQLMONEYN:
	case SQLDATETIMN:
		result = 8;
		break;
	default:

		result = 0;
		break;
	}
	return result = 0;
}
int __stdcall bcpDefaultLength(PDBPROCESS dbproc, int usertype, int table_column)
{
	bcp_bindinfo_t* ci = 0;
	int typ, length;

	if (table_column <= 0)
	{
		typ = length = 0;
	}
	else
	{
		ci = &dbproc->bcpinfo->bindinfo[table_column-1];
		typ = ci->usertype;
		length = ci->length;
	}
	return bcpLengthConversion(typ, length, usertype, dbproc->bcpinfo->direction);
}
int __cdecl bcpCmd(PDBPROCESS dbproc, const char* Src, ...)
{
	char* p0 = 0; 
	char* p1 = 0; 
	char** p_Src = 0; 
	char C = 0; 
	char* str = 0; 
	int lval = 0; 
	char Buffer[12] = { 0 };

	EnterCriticalSection(&bcpCmdSem);
	p0 = (char*)Src;
	p1 = (char*)Src;
	if (*Src)
	{
		p_Src = (char**)&Src;
		do
		{
			if (*p1 == '%')
			{
				*p1 = 0;
				if (!dbcmd(dbproc, p0))
				{
					LeaveCriticalSection(&bcpCmdSem);
					return bcpError(dbproc, 0);
				}
				*p1 = '%';
				C = *++p1;
				switch (C)
				{
				case 'd':
					_itoa(*(unsigned __int16*)++p_Src, Buffer, 10);
					if (!dbcmd(dbproc, Buffer))
					{
						LeaveCriticalSection(&bcpCmdSem);
						return bcpError(dbproc, 0);
					}
					break;
				case 'l':
					lval = (int)p_Src[1];
					++p_Src;
					_ltoa(lval, Buffer, 10);
					if (!dbcmd(dbproc, Buffer))
					{
						LeaveCriticalSection(&bcpCmdSem);
						return bcpError(dbproc, 0);
					}
					break;
				case 's':
					str = p_Src[1];
					++p_Src;
					if (!dbcmd(dbproc, str))
					{
						LeaveCriticalSection(&bcpCmdSem);
						return bcpError(dbproc, 0);
					}
					break;
				}
				p0 = p1 + 1;
			}
		} while (*++p1);
	}
	if (dbcmd(dbproc, p0))
	{
		LeaveCriticalSection(&bcpCmdSem);
		return SUCCEED;
	}
	else
	{
		LeaveCriticalSection(&bcpCmdSem);
		return bcpError(dbproc, 0);
	}
}
int __cdecl PrepareFullName(PDBPROCESS dbproc, bcp_info_t* bcpinfo, int b)
{
	int bquot = 0; 
	char* p2 = 0; 
	int result = 0; 


	if (b && dbisopt(dbproc, 18, 0)) // quoted_identifier
	{
		bquot = 1;
		strcpy(bcpinfo->object_id, "\"");
	}
	else
	{
		bquot = 0;
		bcpinfo->object_id[0] = 0;
	}
	if (!bcpinfo->field_63[0])
	{
		result = 0;
		strcat(bcpinfo->object_id, bcpinfo->tabname1);
		if (bquot)
			strcat(bcpinfo->object_id, "\"");
		return result;
	}
	strcat(bcpinfo->object_id, bcpinfo->field_63);
	if (bquot)
		strcat(bcpinfo->object_id, "\"");

	p2 = &bcpinfo->object_id[strlen(bcpinfo->object_id)];
	strcat(p2, ".");

	if (bquot)
	{
		p2 = &bcpinfo->object_id[strlen(bcpinfo->object_id)];
		strcat(p2, "\"");
	}
	result = 0;
	strcat(bcpinfo->object_id, bcpinfo->tabname1);
	if (bquot)
	{
		result = 0;
		strcat(bcpinfo->object_id, "\"");
		if (bquot)
			strcat(bcpinfo->object_id, "\"");
		return result;
	}
	return result;
}
int __stdcall bcpInsert(PDBPROCESS dbproc)
{
	PrepareFullName(dbproc, dbproc->bcpinfo, 1);
	bcpCmd(dbproc, "insert bulk %s ", dbproc->bcpinfo->object_id);
	if (!dbsqlexec(dbproc) || dbresults(dbproc) == FAIL)
		return 0;
	dbproc->cmd_flag = dbproc->cmd_flag & SQLMONEY4 | 0x81;
	return SUCCEED;
}
DBINT __cdecl bcp_batch(PDBPROCESS dbproc)
{
	bcp_info_t* bcpinfo = 0;
	DBINT ival = 0; 
	int result = 0; 

	if (!bcpCheckEntry(dbproc))
		return -1;
	bcpinfo = dbproc->bcpinfo;
	ival = bcpinfo->result;
	bcpinfo->result = 0;
	if (!ival)
		return 0;
	if (!sendflush(dbproc))
	{
		bcpError(dbproc, 0);
		return -1;
	}
	if (ival == -1)
	{
		bcpError(dbproc, 0);
		return ival;
	}
	if (!dbsqlok(dbproc))
	{
		bcpError(dbproc, 0);
		return -1;
	}
	result = dbresults(dbproc);
	if (result != NO_MORE_RESULTS)
	{
		while (result)
		{
			result = dbresults(dbproc);
			if (result == NO_MORE_RESULTS)
			{
				if (!bcpInsert(dbproc))
				{
					bcpError(dbproc, 0);
					return -1;
				}else
					return ival;
			}
		}
		bcpError(dbproc, 0);
		return -1;
	}

	if (!bcpInsert(dbproc))
	{
		bcpError(dbproc, 0);
		return -1;
	}
	return ival;
}
/*
* Set the LOGINREC for bulk copy operations into the database. 
*/
int __cdecl bcp_setl(db_login_t* login, bool b_value)
{
	int result = 0; 

	if (login)
	{
		result = 1;
		login->lDumpLoad = b_value != 1;
	}
	else
	{
		GeneralError(0, SQLENLOG);
		return 0;
	}
	return result;
}
int __stdcall bcpVerifyBind(
	PDBPROCESS dbproc,
	char usertype,
	int varlen,
	int prefixlen,
	int termlen,
	BYTE* terminator)
{
	int bSucc = 0; 
	int result = 0; 

	switch (usertype)
	{
	case SQLIMAGE:
	case SQLTEXT:
		bSucc = 0;
		break;
	case SQLVARBINARY:
	case SQLVARCHAR:
	case SQLBINARY:
	case SQLCHAR:
		if (varlen > 255)
			return 0;
		bSucc = 0;
		break;
	case SQLINTN:
		if (varlen > 0 && varlen != 4)
			return 0;
		bSucc = 0;
		break;
	case SQLINT1:
	case SQLBIT:
	case SQLINT2:
	case 0x37:
	case SQLINT4:
	case SQLDATETIM4:
	case SQLFLT4:
	case SQLMONEY:
	case SQLDATETIME:
	case SQLFLT8:
	case 0x3F:
	case SQLDECIMAL:
	case SQLNUMERIC:
	case SQLMONEY4:
		if (varlen > 0)
			return 0;
		bSucc = 1;
		break;
	case SQLFLTN:
	case SQLMONEYN:
	case SQLDATETIMN:
		if (varlen > 0 && varlen != 8)
			return 0;
		bSucc = 0;
		break;
	default:
		return 0;
	}
	if (varlen < -1)
		return 0;
	switch (usertype)
	{
	case SQLIMAGE:
	case SQLTEXT:
	case SQLVARBINARY:
	case SQLVARCHAR:
	case SQLBINARY:
	case SQLCHAR:
		if (bSucc || varlen >= 0)
			goto LABEL_20;

		if (prefixlen)
			goto LABEL_21;

		if (termlen)
			goto LABEL_27;
		GeneralError(dbproc, 10058);
		return 0;
	default:
	LABEL_20:

	LABEL_21:
		if (prefixlen <= 0 || prefixlen == 1 || prefixlen == 2 || prefixlen == 4)
		{

		LABEL_27:
			if (termlen <= 0 || terminator)
			{
				result = 1;
			}
			else
			{
				GeneralError(dbproc, 10069);
				result = 0;
			}
		}
		else
		{
			GeneralError(dbproc, 10058);
			result = 0;
		}
		break;
	}
	return result;
}


int __stdcall bcpDefineDefaultFields(PDBPROCESS dbproc)
{
	bcp_info_t* bi = 0; 
	int result = 0; 
	int ncol = 0;


	bi = dbproc->bcpinfo;
	result = bcp_columns(dbproc, bi->num_cols);
	if (!result)
		return 0;
	if (bi->num_cols)
	{
		ncol = 1;
		while (1)
		{
			result = bcp_colfmt(dbproc, ncol, 0, -1, -1, 0, -1, ncol);
			if (!result)
				break;
			if (ncol++ >= bi->num_cols)
				return SUCCEED;
		}
		return 0;
	}
	return SUCCEED;
}

int __cdecl bcp_bind(
	PDBPROCESS dbproc,
	LPCBYTE varaddr,
	INT prefixlen,
	DBINT varlen,
	LPCBYTE terminator,
	INT termlen,
	INT vartype,
	INT table_column)
{
	bcp_info_t* bcpinfo = 0; 
	bcp_bindinfo_t* bindinfo = 0;

	BYTE usertype = 0;
	bcp_column_t* column = 0; 
	BYTE token = 0; 
	bcp_column_t* col = 0; 


	if (bcpCheckEntry(dbproc))
	{
		bcpinfo = dbproc->bcpinfo;
		if (table_column < 1 || table_column > bcpinfo->num_cols)
		{
			GeneralError(dbproc, SQLECNOR);
		}
		else
		{
			bindinfo = &bcpinfo->bindinfo[table_column - 1];


			if (!varlen && (bindinfo->status & 8) == 0 && (!bindinfo->datsize || !bindinfo->vardata))
			{
				GeneralError(dbproc, 10053);
				return 0;
			}
			usertype = vartype;
			if (!vartype)
				usertype = (unsigned __int8)bindinfo->usertype;
			if (usertype == SQLVARCHAR)
			{
				usertype = SQLCHAR;
			}
			else if (usertype == SQLVARBINARY)
			{
				usertype = SQLBINARY;
			}
			if (bcpVerifyBind(dbproc, usertype, varlen, prefixlen, termlen, terminator) && termlen >= 0)
			{
				if (bcpinfo->b_loaded == 0)
				{
					GeneralError(dbproc, 10057);
					return 0;
				}
				if (bcpinfo->direction != DB_IN)
				{
					GeneralError(dbproc, 10056);
					return 0;
				}
				if (!dbwillconvert(usertype, (unsigned __int8)bindinfo->usertype))
				{
					GeneralError(dbproc, 10016);
					return 0;
				}
				if (bcpinfo->columns
					|| (column = (bcp_column_t*)AllocateHeapMemory(4, dbproc, 44 * bcpinfo->num_cols, 1),
						(bcpinfo->columns = column) != 0))
				{
					if (varaddr || (token = bindinfo->usertype, token == SQLTEXT) || token == SQLIMAGE)
					{
						if (prefixlen >= 0)
						{
							if (varlen < 0)
								varlen = bcpDefaultLength(dbproc, usertype, table_column);
							col = &bcpinfo->columns[table_column - 1];
							col->collen = varlen;
							col->usertype = usertype;
							col->varaddr = varaddr;
							col->prefixlen = prefixlen;
							col->termlen = termlen;
							col->bindinfo = bindinfo;
							bindinfo->columnsinfo = col;
							if (termlen <= 0)
								return SUCCEED;
							if (col->terminator)
								FreeMemory(dbproc, (LPVOID)col->terminator);
							col->terminator = (char*)AllocateHeapMemory(4, dbproc, termlen, 0);
							if (col->terminator)
							{
								memmove(col->terminator, terminator, termlen);
								return SUCCEED;
							}
						}
					}
				}
			}
		}
	}
	return 0;
}
DBINT __cdecl bcp_done(PDBPROCESS dbproc)
{
	bcp_info_t* bcpinfo = 0;
	BYTE* buffer1 = 0;
	int result = 0; 
	int i = 0;

	if (!bcpCheckEntry(dbproc))
		return -1;
	bcpinfo = dbproc->bcpinfo;
	buffer1 = dbproc->CommLayer->buffer1;
	if (bcpinfo->direction == DB_IN)
	{
		result = bcpinfo->result;
		bcpinfo->result = 0;
		if (!sendflush(dbproc) || !dbsqlok(dbproc) || dbresults(dbproc) == FAIL)
			result = -1;
	}
	else
	{
		result = 0;
	}
	for (i = dbresults(dbproc); i != NO_MORE_RESULTS; i = dbresults(dbproc))
	{
		if (!i)
			break;
		while (dbnextrow(dbproc) != NO_MORE_ROWS)
			;
	}
	if (!bcpClose(dbproc, bcpinfo->bcpdata) && bcpinfo->direction == DB_OUT)
	{
		GeneralError(dbproc, 10052);
		result = -1;
	}
	if (!bcpClose(dbproc, bcpinfo->bcplog))
		GeneralError(dbproc, 10065);
	bcpError(dbproc, 0);
	if (dbproc->ver >= 0x40u)
	{
		*buffer1 = PT_SQLBATCH;
		*dbproc->CommLayer->buffer0 = PT_SQLBATCH;
	}
	return result;
}
void __stdcall bcpSetUpOutMode(PDBPROCESS dbproc)
{
	bcp_bindinfo_t* bindinfo = 0; 
	int i, i1;
	bcp_info_t* bcpinfo = 0; 
	__int16 typ = 0;
	__int16 B1 = 0;
	__int16 usertype = 0;

	i1 = i = 0;
	bcpinfo = dbproc->bcpinfo;

	if (bcpinfo->ncols)
	{
		while (1)
		{
			bindinfo = bcpinfo->columns[i].bindinfo;
			if (bindinfo)
			{
				typ = bindinfo->usertype;
				B1 = 0;
				bindinfo->data_len = 0;
				usertype = bcpinfo->columns[i].usertype;
				if (typ == SQLVARCHAR)
				{
					typ = SQLCHAR;
				}
				else
				{
					if (typ != SQLVARBINARY)
					{
					LABEL_8:
						if (bcpinfo->columns[i].collen && bcpinfo->columns[i].varlen)
						{
							bindinfo->have_data = 1;
							bindinfo->data_len = bcpinfo->columns[i].collen;
							goto LABEL_31;
						}
						if (typ == SQLTEXT)
						{
							if (usertype == SQLCHAR || usertype == SQLTEXT)
							{
								usertype = SQLTEXT;
								bindinfo->have_data = 0;
								goto LABEL_32;
							}
						}
						else
						{
							if (usertype == SQLBINARY || usertype == SQLIMAGE)
							{
								usertype = typ;
								goto LABEL_32;
							}
							if (usertype == SQLCHAR || usertype == SQLVARCHAR)
							{
								switch (typ)
								{
								case SQLINTN:
								case SQLINT1:
								case SQLINT2:
								case SQLINT4:
									bindinfo->have_data = 1;
									bindinfo->data_len = 11;
									break;
								case SQLBIT:
									bindinfo->have_data = 1;
									bindinfo->data_len = 3;
									break;
								case SQLDATETIM4:
								case SQLDATETIME:
								case SQLDATETIMN:
									if (dbproc && (dbproc->ret_status & 0x400) != 0)
									{
										bindinfo->data_len = 30;
										bindinfo->have_data = 1;
									}
									else
									{
										bindinfo->data_len = 27;
										bindinfo->have_data = 1;
									}
									break;
								case SQLFLT4:
								case SQLFLT8:
								case SQLFLTN:
									bindinfo->have_data = 1;
									bindinfo->data_len = 32;
									break;
								case SQLMONEY:
								case SQLMONEYN:
								case SQLMONEY4:
									bindinfo->have_data = 1;
									bindinfo->data_len = 26;
									break;
								case SQLDECIMAL:
								case SQLNUMERIC:
									bindinfo->have_data = 1;
									bindinfo->data_len = 40;
									break;
								default:
									goto LABEL_30;
								}
							LABEL_31:

								if (usertype != typ)
								{
								LABEL_35:
									bindinfo->from_type = typ;
									i = i1;
									bindinfo->to_type = usertype;
									goto LABEL_36;
								}
							LABEL_32:
								if (B1 == 1 || !bindinfo->data_len)
									bindinfo->have_data = 0;
								goto LABEL_35;
							}
						}
					LABEL_30:
						bindinfo->have_data = 0;
						goto LABEL_31;
					}
					typ = SQLBINARY;
				}
				B1 = 1;
				goto LABEL_8;

			}
		LABEL_36:
			i1 = ++i;
			if (i >= bcpinfo->ncols)
				return ;
		}

	}
	return ;
}
char null32[32] = { 0 };
int __stdcall bcpWriteRecord(PDBPROCESS dbproc)
{
	bcp_info_t* bcpinfo = 0;
	bcp_t* bcpdata = 0;
	int i = 0;
	bcp_column_t* columns = 0;
	bcp_bindinfo_t* bindinfo = 0;
	int len = 0;
	int i0 = 0;
	int fTyp, tTyp;
	BYTE*vardata = 0;
	DWORD l2 = 0;

	char* p1 = 0,* p2 = 0;
	BOOL result, bSucc;

	unsigned __int64 SiZ = 0;

	const char* pspace = 0;
	size_t l1 = 0;
	char* Destination = 0;
	int L = 0;
	int bAlloc = 0;

	char Source[52] = { 0 };
	char localstr[256] = {0};

	bcpinfo = dbproc->bcpinfo;
	Destination = 0;
	bAlloc = 0;

	bcpdata = bcpinfo->bcpdata;

	if (bcpinfo->ncols == 0)
		return SUCCEED;

	i = 0;
	while (1)
	{
		columns = bcpinfo->columns;
		bindinfo = columns[i].bindinfo;

		if (bindinfo)
		{
			*_errno() = 0;
			len = 0;
			i0 = ((int)bcpinfo->columns[i].bindinfo - (int)bcpinfo->bindinfo) / SQLINT2 + 1;
			fTyp = bindinfo->from_type;
			tTyp = bindinfo->to_type;

			if (bindinfo->have_data)
			{
				if (dbproc->columns_info[i0 - 1]->coltype == SQLTEXT 
					|| dbproc->columns_info[i0 - 1]->coltype == SQLIMAGE)
				{
					blob_t* pblob = (blob_t*)dbproc->columns_data[i0 - 1]->data;
					len = pblob->len;
				}
				else
					len = dbproc->columns_data[i0 - 1]->len;

				if (len > 0)
				{
					len = bindinfo->data_len;
				}
			}
			else
			{
				if (fTyp == SQLTEXT)
				{
					if (tTyp == SQLCHAR || tTyp == SQLTEXT)
					{
					LABEL_26:
						if (dbproc->columns_info[i0 - 1]->coltype == SQLTEXT 
							|| dbproc->columns_info[i0 - 1]->coltype == SQLIMAGE)
						{
							blob_t* pblob = (blob_t*)dbproc->columns_data[i0 - 1]->data;
							len = pblob->len;
						}
						else
							len = dbproc->columns_data[i0 - 1]->len;
					}
					else
					{
						if (dbproc->columns_info[i0 - 1]->coltype == SQLTEXT 
							|| dbproc->columns_info[i0 - 1]->coltype == SQLIMAGE)
						{
							blob_t* pblob = (blob_t*)dbproc->columns_data[i0 - 1]->data;
							len = pblob->len / 2 + 1;
						}
						else
						{
							len = dbproc->columns_data[i0 - 1]->len;
							len = len / 2 + 1;
						}
					}

				}
				else 
				{
					if (tTyp == SQLBINARY || tTyp == SQLIMAGE)
					{
						tTyp = fTyp;
						goto LABEL_47;
					}
					if (tTyp == SQLCHAR || tTyp == SQLVARCHAR)
					{
						if (fTyp != SQLIMAGE && fTyp != SQLBINARY)
							goto LABEL_26;

						if (dbproc->columns_info[i0 - 1]->coltype == SQLTEXT || dbproc->columns_info[i0 - 1]->coltype == SQLIMAGE)
						{
							blob_t* pblob = (blob_t*)dbproc->columns_data[i0 - 1]->data;
							len = pblob->len * 1 + 1;
						}
						else
							len = 2 * dbproc->columns_data[i0 - 1]->len + 1;

						goto LABEL_42;
					}


					if (dbproc->columns_info[i0 - 1]->coltype == SQLTEXT || dbproc->columns_info[i0 - 1]->coltype == SQLIMAGE)
					{
						blob_t* pblob = (blob_t*)dbproc->columns_data[i0 - 1]->data;
						len = pblob->len;
					}
					else
						len = dbproc->columns_data[i0 - 1]->len;

					if (len > 0 && (fTyp == SQLIMAGE || fTyp == SQLBINARY))
					{
						len = 2 * len + 1;
						goto LABEL_42;
					}
				}

			}
		LABEL_42:
			if (tTyp != fTyp)
			{
				if (len <= 255)
				{
					Destination = localstr;
				}
				else
				{
					Destination = (char*)AllocateHeapMemory(4, dbproc, len, 0);
					bAlloc = 1;
					if (!Destination)
						return bcpLog(dbproc, -10000, i0);

				}
			}
		LABEL_47:

			if (tTyp != bindinfo->commontype)
			{

				if (len > 0)
				{
					if (dbproc->columns_data[i0 - 1]->data == 0)
					{
						vardata = columns[i].vardata;
					}
					else if (dbproc->columns_info[i0 - 1]->coltype == SQLTEXT || dbproc->columns_info[i0 - 1]->coltype == SQLIMAGE)
					{
						blob_t* pblob = (blob_t*)dbproc->columns_data[i0 - 1]->data;
						vardata = pblob->data;
					}
					else
						vardata = dbproc->columns_data[i0 - 1]->data;

					if (dbproc->columns_info[i0 - 1]->coltype == SQLTEXT || dbproc->columns_info[i0 - 1]->coltype == SQLIMAGE)
					{
						blob_t* pblob = (blob_t*)dbproc->columns_data[i0 - 1]->data;
						l2 = pblob->len;
					}
					else
						l2 = dbproc->columns_data[i0 - 1]->len;
					len = ((CONVERTFUNC)bindinfo->convfunc)(
						dbproc,
						bindinfo->commontype,
						vardata,
						l2,
						tTyp,
						Destination,
						len);
				}

				if (len >= 0)
					goto LABEL_76;
			}

			if (bindinfo->usertype == SQLVARCHAR || bindinfo->usertype == SQLVARBINARY || !len)
			{
				if (dbproc->columns_info[i0 - 1]->coltype == SQLTEXT || dbproc->columns_info[i0 - 1]->coltype == SQLIMAGE)
				{
					blob_t* pblob = (blob_t*)dbproc->columns_data[i0 - 1]->data;
					len = pblob->len;
				}
				else
					len = dbproc->columns_data[i0 - 1]->len;

			}

			if (dbproc->columns_data[i0 - 1]->data)
			{
				if (dbproc->columns_info[i0 - 1]->coltype == SQLTEXT || dbproc->columns_info[i0 - 1]->coltype == SQLIMAGE)
				{
					blob_t* pblob = (blob_t*)dbproc->columns_data[i0 - 1]->data;
					Destination = (char*)pblob->data;
				}
				else
					Destination = (char*)dbproc->columns_data[i0 - 1]->data;
			}
			else
			{
				Destination = (char*)columns[i].vardata;
			}
		LABEL_76:
			if ((fTyp == SQLCHAR || fTyp == SQLVARCHAR || fTyp == SQLTEXT) && len > 0)
			{
				if (bcpinfo->charset)
				{
					LocalCharSetConvert(dbproc, Destination, len, 2);
				}
				switch (fTyp)
				{
				case SQLDATETIM4:
				case SQLDATETIME:
				case SQLDATETIMN:
					if (columns[i].collen < len)
					{
						len = columns[i].collen;
					}
					break;
				case SQLMONEY:
				case SQLMONEYN:
				case SQLMONEY4:
					p1 = Destination;
					p2 = Source;
					if (len > 0)
					{
						L = len;
						do
						{
							if (*p1 != ThouSep[0])
								*p2++ = *p1;
							++p1;
							--L;
						} while (L);
					}
					*p2 = 0;
					len = strlen(Source);
					strncpy(Destination, Source, len);
					break;
				default:
					break;
				}
			}
			if ((tTyp == SQLNUMERIC || tTyp == SQLDECIMAL) && len)
			{
				len = (unsigned __int8)GetMaxNumericBytes(*Destination) + 2;
			}
			switch (columns[i].prefixlen)
			{
			case 1:
				if (!bcpdata->m_bMaped || (bcpdata->m_nToWriteSize + 1 > 0x1000))
				{
					result = bcpWrite(dbproc, bcpdata, 1u, &len);
				LABEL_112:
					bSucc = result;
					if (!result)
						goto LABEL_151;
					break;
				}
				memmove((char*)bcpdata->m_pBuffer + LODWORD(bcpdata->m_nToWriteSize), &len, 1u);
				bcpdata->m_nToWriteSize += 1;
				break;
			case 2:
				if (!bcpdata->m_bMaped || (bcpdata->m_nToWriteSize + 2 > 0x1000))
				{
					result = bcpWrite(dbproc, bcpdata, 2u, &len);
					goto LABEL_112;
				}
				memmove((char*)bcpdata->m_pBuffer + LODWORD(bcpdata->m_nToWriteSize), &len, 2u);
				bcpdata->m_nToWriteSize += 2;
				break;
			case 4:
				if (!bcpdata->m_bMaped || (bcpdata->m_nToWriteSize + 4 > 0x1000))
				{
					result = bcpWrite(dbproc, bcpdata, 4u, &len);
					goto LABEL_112;
				}
				memmove((char*)bcpdata->m_pBuffer + LODWORD(bcpdata->m_nToWriteSize), &len, 4u);
				bcpdata->m_nToWriteSize += 4;
				break;
			default:
				goto LABEL_114;
			}

		LABEL_114:
			if (len)
			{
				if (bcpdata->m_bMaped
					&& (SiZ = bcpdata->m_nToWriteSize + (unsigned int)len,
						SiZ <= 0x1000))
				{
					memmove((char*)bcpdata->m_pBuffer + SiZ, Destination, len);
					bSucc = 1;
					bcpdata->m_nToWriteSize += len;
				}
				else
				{
					bSucc = bcpWrite(dbproc, bcpdata, len, Destination);
					if (!bSucc)
						goto LABEL_151;
				}

			}
			else
			{
				bSucc = 1;
			}

			if (columns[i].usertype == SQLCHAR || columns[i].usertype == SQLVARCHAR || (pspace = (char*)null32, columns[i].usertype == SQLTEXT))
				pspace = "                              ";

			if (!columns[i].prefixlen && !columns[i].termlen)
			{
				if (len < columns[i].collen || !len)
				{
					l1 = columns[i].collen - len;
					if (l1 > 30)
					{
						L = (l1 - 1) / 30;
						do
						{
							if (bcpdata->m_bMaped && (bcpdata->m_nToWriteSize + 30 <= 0x1000))
							{
								memmove((char*)bcpdata->m_pBuffer + LODWORD(bcpdata->m_nToWriteSize), pspace, 0x1Eu);
								bSucc = 1;
								bcpdata->m_nToWriteSize += 30;
							}
							else
							{
								bSucc = bcpWrite(dbproc, bcpdata, 30u, pspace);
							}

							l1 -= 30;
							--L;
						} while (!L);
					}
					if (l1)
					{
						if (bcpdata->m_bMaped)
						{

							if (l1 + bcpdata->m_nToWriteSize <= 0x1000)
							{
								memmove((char*)bcpdata->m_pBuffer + LODWORD(bcpdata->m_nToWriteSize), pspace, l1);
								bcpdata->m_nToWriteSize += l1;
								bSucc = 1;
							LABEL_143:

								goto LABEL_144;
							}
						}
						bSucc = bcpWrite(dbproc, bcpdata, l1, pspace);
					}
					if (!bSucc)
						goto LABEL_151;
					goto LABEL_143;
				}
			}
		LABEL_144:

			if (columns[i].termlen <= 0)
				goto LABEL_151;
			if (bcpdata->m_bMaped)
			{

				if (bcpdata->m_nToWriteSize + columns[i].termlen <= 0x1000)
				{

					memmove((char*)bcpdata->m_pBuffer + bcpdata->m_nToWriteSize, columns[i].terminator, columns[i].termlen);

					bSucc = 1;
					bcpdata->m_nToWriteSize = columns[i].termlen + bcpdata->m_nToWriteSize;
					goto LABEL_151;
				}
				bSucc = bcpWrite(dbproc, bcpdata, columns[i].termlen, columns[i].terminator);
			}
			else
			{
				bSucc = bcpWrite(dbproc, bcpdata, columns[i].termlen, columns[i].terminator);
			}

		LABEL_151:
			if (bAlloc)
			{
				FreeMemory(dbproc, Destination);
				bAlloc = 0;
			}
			if (!bSucc)
				return bcpLog(dbproc, 10052, i);
		}

		i++;

		if (i>= bcpinfo->ncols)
			return SUCCEED;
	}

	if (bAlloc)
		FreeMemory(dbproc, Destination);
	return bcpLog(dbproc, -10039, i);
}

int __stdcall bcpReceive(PDBPROCESS dbproc)
{
	int i = 0; 
	bcp_info_t* bcpinfo = 0; 
	int Count = 0;
	int result = 0;

	int last = 0; 
	int ie = 0; 


	i = 1;
	bcpinfo = dbproc->bcpinfo;
	Count = 0;
	ie = 0;
	PrepareFullName(dbproc, bcpinfo, 1);
	if (!bcpCmd(dbproc, "select * from %s ", bcpinfo->object_id) || !dbsqlexec(dbproc) || dbresults(dbproc) == FAIL)
		return 0;
	if (bcpinfo->direction == 2)
		bcpSetUpOutMode(dbproc);
	bcpinfo->charset = dbisopt(dbproc, 14, 0) || !dbisopt(dbproc, 15, 0) && dbproc->ansi;

	if (bcpinfo->first > 1)
	{
		while ((dbproc->ret_status & 0x100) == 0)
		{
			result = dbnextrow(dbproc);
			if (result == NO_MORE_ROWS)
			{
				bcpErrorHandle(dbproc, 10100, bcpinfo->tabname1, i - 1, 0);
				return 0;
			}
			if (!result)
				return 0;
			if (++i >= bcpinfo->first)
				break;
		}
	}
	if (dbnextrow(dbproc) == MORE_ROWS)
	{
		while (i <= bcpinfo->last && (dbproc->ret_status & 0x100) == 0)
		{
			if (bcpWriteRecord(dbproc))
			{

				++Count;
				if (Count == 1000)
				{
					Count = 0;
					bcpErrorHandle(dbproc, 10049, 0, Count, 0);
				}
				++i;
				++bcpinfo->dcol;
			}
			else if (++ie >= bcpinfo->maxerrs)
			{
				dbcancel(dbproc);
				return 0;
			}
			if (dbnextrow(dbproc) != MORE_ROWS)
				break;
		}
	}
	dbcancel(dbproc);
	last = bcpinfo->last;
	if (last == 0x7FFFFFFF || i - 1 == last)
		return SUCCEED;
	bcpErrorHandle(dbproc, 10099, bcpinfo->tabname1, bcpinfo->dcol, bcpinfo->last);
	return 0;
}

int __cdecl bcp_exec(PDBPROCESS dbproc, LPDBINT lpReturn )
{
	int result = 0; 
	bcp_info_t* bcpinfo = 0; 

	result = bcpCheckEntry(dbproc);
	if (!result)
		return result;
	bcpinfo = dbproc->bcpinfo;
	dbproc->ret_status &= ~0x100u;
	bcpinfo->dbproc = dbproc;

	if (!bcpinfo->bcpdata)
	{
		GeneralError(dbproc, 10062);
		return 0;
	}
	if (bcpinfo->bcpdata->m_bMaped && bcpinfo->bcpdata->m_pMap)
	{
		if (bcpinfo->direction == DB_IN)
		{
			GeneralError(dbproc, 10067);
			return SUCCEED;
		}

	}
	else if (bcpinfo->bcpdata->m_hFile == 0)
	{
		if (bcpinfo->direction == DB_IN)
		{
			GeneralError(dbproc, 10067);
			return SUCCEED;
		}
	}

	if (bcpinfo->columns || (result = bcpDefineDefaultFields(dbproc)) != 0)
	{
		if (bcpinfo->direction == 1)
		{
			bcpinfo->read_fail = 0;
			bcpinfo->blkbuffer = (BYTE*)AllocateHeapMemory(4, dbproc, 0x2000u, 1);
			bcpinfo->read_pos = 0;
			bcpinfo->total_size = 0;
			bcpinfo->read_size = -1;
			
			result = bcpSend(dbproc);
			if (bcpinfo->blkbuffer)
			{
				FreeMemory(dbproc, (LPVOID)bcpinfo->blkbuffer);
				bcpinfo->blkbuffer = 0;
			}
		}
		else
		{
			result = bcpReceive(dbproc);
		}
		if (dbproc && dbproc->bcpinfo)
			*lpReturn = bcpinfo->dcol;
		if (result)
		{
			if (bcp_done(dbproc) == -1)
				result = 0;
			else
				result = ((dbproc->ret_status & 0x100) != 0) + 1;
		}
		else
		{
			if (dbproc->bcpinfo)
			{
				bcpClose(dbproc, bcpinfo->bcpdata);
				bcpClose(dbproc, bcpinfo->bcplog);
			}
			result = 0;
		}
	}
	return result;
}

int __cdecl bcp_columns(PDBPROCESS dbproc, INT ncols)
{
	int result = 0;
	bcp_info_t* bcpinfo = 0; 

	result = bcpCheckEntry(dbproc);
	if (result)
	{
		bcpinfo = dbproc->bcpinfo;
		if (bcpinfo->b_loaded)
		{
			GeneralError(dbproc, 10059);
			result = 0;
		}
		else if (ncols >= 1)
		{
			if (bcpinfo->ncols)
			{
				result = 0;
			}
			else
			{
				bcpinfo->columns = (bcp_column_t*)AllocateHeapMemory(4, dbproc, 44 * ncols, 1);
				if (bcpinfo->columns)
				{
					bcpinfo->ncols = ncols;
					result = 1;
				}
				else
				{
					result = bcpError(dbproc, 0);
				}
			}
		}
		else
		{
			GeneralError(dbproc, 10061);
			result = 0;
		}
	}
	return result;
}
int __cdecl bcpDefaultPrefix(PDBPROCESS dbproc, BYTE dType)
{
	int result = 0; 

	if ((dType & SQLINT1) != 0x20)
		return 0;
	switch (dType)
	{
	case SQLIMAGE:
	case SQLTEXT:
		result = 4;
		break;
	case SQLVARBINARY:
	case SQLBINARY:
		result = 2;
		break;
	case SQLCHAR:
		return 0;
	default:
		result = 1;
		break;
	}
	return result;
}
int __cdecl bcp_colfmt(
	PDBPROCESS dbproc,
	INT column,
	BYTE usertype,
	INT prefixlen,
	DBINT varlen,
	LPCBYTE terminator,
	INT termlen,
	INT cdefault)
{
	bcp_info_t* bcpinfo = 0; 
	int result = 0; 
	BYTE uTy, uTy1;
	bcp_column_t* col = 0; 
	char* term = 0; 
	unsigned __int8 Typ; 

	if (!bcpCheckEntry(dbproc))
		return 0;
	bcpinfo = dbproc->bcpinfo;
	if (cdefault < 0 || cdefault > bcpinfo->num_cols)
	{
		GeneralError(dbproc, SQLECNOR);
		return 0;
	}
	if (bcpinfo->direction == DB_OUT && !cdefault)
	{
		GeneralError(dbproc, 10068);
		return 0;
	}
	if (!bcpinfo->ncols)
	{
		GeneralError(dbproc, 10060);
		return 0;
	}
	if (column < 1 || column > bcpinfo->ncols)
	{
		GeneralError(dbproc, SQLECNOR);
		return 0;
	}
	if (!usertype && cdefault)
		usertype = bcpinfo->bindinfo[cdefault - 1].usertype;

	Typ = dbconvert_getcommontype(usertype, (unsigned __int8)bcpinfo->bindinfo[cdefault - 1].length);
	if (!bcpVerifyBind(dbproc, Typ, varlen, prefixlen, termlen, terminator))
		return 0;
	if (cdefault)
	{
		if (!(bcpinfo->direction == DB_IN
			? dbwillconvert(Typ, (unsigned __int8)bcpinfo->bindinfo[cdefault - 1].usertype)
			: dbwillconvert((unsigned __int8)bcpinfo->bindinfo[cdefault - 1].usertype, Typ)))
		{
			GeneralError(dbproc, 10016);
			return 0;
		}
	}
	if (termlen < -1)
		return 0;
	if (prefixlen < 0)
	{
		uTy = bcpinfo->bindinfo[cdefault - 1].usertype;
		prefixlen = bcpDefaultPrefix(dbproc, uTy);
	}
	if (varlen < 0)
	{
		if (Typ)
			uTy1 = Typ;
		else
			uTy1 = (unsigned __int8)bcpinfo->bindinfo[cdefault - 1].usertype;
		varlen = bcpDefaultLength(dbproc, uTy1, cdefault);
	}
	col = &bcpinfo->columns[column - 1];

	col->usertype = Typ;
	col->collen = varlen;
	col->prefixlen = prefixlen;
	col->termlen = termlen;
	if (termlen <= 0)
	{
		col->termlen = 0;
	}
	else
	{
		term = (char*)AllocateHeapMemory(4, dbproc, termlen, 0);
		col->terminator = term;
		if (!term)
			return bcpError(dbproc, 0);
		dbmove((void*)terminator, term, termlen);
	}
	if (!bcpinfo->b_loaded && varlen > 0 && col->collen <= 0xFFF2u)
	{
		col->vardata = (BYTE*)AllocateHeapMemory(4, dbproc, varlen, 1);
		if (!col->vardata)
			return bcpError(dbproc, 0);
		col->balloced = 1;
	}
	if (cdefault)
	{
		result = 1;
		col->bindinfo = &bcpinfo->bindinfo[cdefault - 1];
		bcpinfo->bindinfo[cdefault - 1].columnsinfo = col;
	}
	else
	{
		col->bindinfo = 0;
		return SUCCEED;
	}
	return result;
}

int __cdecl bcp_collen(PDBPROCESS dbproc, DBINT Length, INT column)
{
	BYTE uType = 0;
	bcp_info_t* bcpinfo = 0;
	DBINT l0 = 0;
	bcp_column_t* columns = 0; 
	bcp_column_t* col = 0; 

	if (bcpCheckEntry(dbproc))
	{
		uType = column;
		bcpinfo = dbproc->bcpinfo;
		if (column < 1 || column > bcpinfo->num_cols)
		{
			GeneralError(dbproc, SQLECNOR);
		}
		else
		{
			l0 = Length;
			if (Length >= -1)
			{
				columns = bcpinfo->columns;
				if (columns)
				{
					col = &columns[column - 1];
					if (Length >= 0
						|| (uType = col->usertype, (l0 = bcpDefaultLength(dbproc, uType, column)) != 0)
						|| col->prefixlen
						|| col->termlen)
					{
						col->collen = l0;
						return SUCCEED;
					}
				}
			}
		}
	}
	return 0;
}

int __cdecl bcp_colptr(PDBPROCESS dbproc, LPCBYTE ptr, INT column)
{
	bcp_info_t* bcpinfo = 0;
	bcp_column_t* columns = 0; 

	if (bcpCheckEntry(dbproc))
	{
		bcpinfo = dbproc->bcpinfo;
		if (column < 1 || column > bcpinfo->num_cols)
		{
			GeneralError(dbproc, SQLECNOR);
		}
		else
		{
			if (!ptr)
			{
				GeneralError(dbproc, 10069);
				return 0;
			}
			columns = bcpinfo->columns;
			if (columns)
			{
				columns[column - 1].varaddr = ptr;
				return SUCCEED;
			}
		}
	}
	return 0;
}

int __cdecl bcp_control(PDBPROCESS dbpro, INT npar, DBINT value)
{
	bcp_info_t* bcpinfo = 0; 
	int result = 0; 

	if (!bcpCheckEntry(dbpro))
		return 0;
	bcpinfo = dbpro->bcpinfo;
	result = 1;
	switch (npar)
	{
	case BCPMAXERRS:
		if (value < 1 || value > 0xFFFF)
			bcpinfo->maxerrs = -1;
		else
			bcpinfo->maxerrs = value;
		break;
	case BCPFIRST:
		if (value >= 1)
			bcpinfo->first = value;
		else
			bcpinfo->first = 1;
		break;
	case BCPLAST:
		if (value >= 1)
			bcpinfo->last = value;
		else
			bcpinfo->last = 0x7FFFFFFF;
		break;
	case BCPBATCH:
		if (value >= 0)
			bcpinfo->batch = value;
		else
			bcpinfo->batch = 1;
		break;
	case BCPKEEPNULLS:
		bcpinfo->keepnul = 1;
		break;
	case BCPABORT:
		dbpro->ret_status |= 0x100;
		break;
	default:
		GeneralError(dbpro, 10048);
		return 0;
	}
	return result;
}

int __cdecl bcp_writefmt(PDBPROCESS dbproc, LPCSTR lpFileName)
{
	char* pbuf = 0; 
	bcp_t* bcp = 0; 

	bcp_info_t* bcpinfo = 0; 
	bcp_bindinfo_t* bindinfo = 0;
	bcp_column_t* columns = 0;
	int l0 = 0; 
	int i = 0; 
	int l1 = 0; 
	int result = 0; 
	

	result = 1;
	if (!CheckEntry(dbproc))
		return 0;
	if (!dbproc->bcpinfo)
		return 0;
	if (!lpFileName)
		return 0;
	if (!*lpFileName)
		return 0;
	pbuf = (char*)AllocateHeapMemory(4, dbproc, 0x61u, 0);
	if (!pbuf)
		return 0;
	bcp = bcpOpen(dbproc, lpFileName, 2);

	if (!bcp)
	{
		GeneralError(dbproc, 10063);
		FreeMemory(dbproc, pbuf);
		return 0;
	}
	// "6.0 \r\n ncols \r\n"
	pbuf[0] = ver60[0] + 48; // "6"
	pbuf[1] = 46;
	pbuf[2] = ver60[1] + 48;
	pbuf[3] = 13;
	pbuf[4] = 10;
	bcpinfo = dbproc->bcpinfo;

	columns = bcpinfo->columns;
	if (!columns || !bcpinfo->ncols)
	{
		bcpClose(dbproc, bcp);
		FreeMemory(dbproc, pbuf);
		return 0;
	}
	_itoa(bcpinfo->ncols, pbuf + 5, 10);
	l0 = strlen(pbuf);
	pbuf[l0] = 13;
	pbuf[l0 + 1] = 10;
	if (!bcpWrite(dbproc, bcp, l0 + 2, pbuf))
	{
		GeneralError(dbproc, 10052);
		bcpClose(dbproc, bcp);
		FreeMemory(dbproc, pbuf);
		return 0;
	}
	i = 0;

	while (1)
	{
		_itoa(i + 1, pbuf, 10);
		l0 = strlen(pbuf) + 1;
		memset(&pbuf[l0 - 1], ' ', 8 - (l0 - 1));
		if (!bcpDataTokenToName(columns[i].usertype, pbuf + 8))
		{
			bcpClose(dbproc, bcp);
			FreeMemory(dbproc, pbuf);
			return 0;
		}
		l0 = strlen(pbuf) + 1;
		if ((int)(l0 - 1) < 22)
			memset(&pbuf[l0 - 1], ' ', 22 - (l0 - 1));
		_itoa(columns[i].prefixlen, pbuf + 22, 10);
		l0 = strlen(pbuf) + 1;
		if ((int)(l0 - 1) < 30)
			memset(&pbuf[l0 - 1], ' ', 30 - (l0 - 1));
		_ltoa(columns[i].collen, pbuf + 30, 10);
		l0 = strlen(pbuf) + 1;
		if ((int)(l0 - 1) < 38)
			memset(&pbuf[l0 - 1], ' ', 38 - (l0 - 1));
		pbuf[38] = '"';
		bcpConvertBinaryToLiteral((BYTE*)columns[i].terminator, pbuf + 39, columns[i].termlen);
		l0 = strlen(pbuf) + 1;
		pbuf[l0 - 1] = '"';
		if (l0 < 48)
			memset(&pbuf[l0], ' ', 48 - l0);
		bindinfo = columns[i].bindinfo;
		if (bindinfo)
		{
			_itoa((unsigned int)(bindinfo - (unsigned int)bcpinfo->bindinfo) / 52 + 1, pbuf + 48, 10);
			l0 = strlen(pbuf) + 1;
			if ((int)(l0 - 1) < 56)
				memset(&pbuf[l0 - 1], ' ', 56 - (l0 - 1));
			l1 = strlen(bindinfo->name);
			dbmove(bindinfo->name, pbuf + 56, l1);
		}
		else
		{
			_itoa(0, pbuf + 48, 10);
			l0 = strlen(pbuf);
			if (!GetConsoleCP())
				LocalCharSetConvert(dbproc, pbuf, l0, 2);
			if (l0 < 56)
				memset(&pbuf[l0], ' ', 56 - l0);
			l1 = strlen(*(const char**)szSkip); // "skipped"
			dbmove(*(void**)szSkip, pbuf + 56, l1);
		}
		l0 = l1 + 56;
		pbuf[l0] = 13;
		pbuf[l0 + 1] = 10;
		if (!bcpWrite(dbproc, bcp, l0 + 2, pbuf))
			break;
		i++;

		if (i >= bcpinfo->ncols)
		{
			bcpClose(dbproc, bcp);
			FreeMemory(dbproc, pbuf);
			return 0;
		}
	}
	GeneralError(dbproc, 10052);
	bcpClose(dbproc, bcp);
	FreeMemory(dbproc, pbuf);
	return 0;
}
int __cdecl bcp_readfmt(PDBPROCESS dbproc, LPCSTR lpFileName)
{
	char* pbuf = 0; 
	bcp_t* bcp = 0; 

	int retcode = 0; 
	char* p1 = 0; 
	char C = 0; 
	int l1 = 0; 
	char* p2 = 0; 
	int ncoli = 0; 

	int bfailed = 0; 
	BYTE token = 0; 
	int varlen = 0; 
	INT ncol = 0; 
	int ncols = 0; 

	int prefixlen = 0; 

	bfailed = 1;
	if (!CheckEntry(dbproc))
		return 0;
	if (!dbproc->bcpinfo)
		return 0;
	if (!lpFileName)
		return 0;
	if (!*lpFileName)
		return 0;
	pbuf = (char*)AllocateHeapMemory(4, dbproc, 0x51u, 0);
	if (!pbuf)
		return 0;
	bcp = bcpOpen(dbproc, lpFileName, 1);

	if (!bcp)
	{
		GeneralError(dbproc, 10063);
		FreeMemory(dbproc, pbuf);
		return 0;
	}
	if (bcpRead(dbproc, bcp, 3u, pbuf) != 1
		|| pbuf[1] != '.'
		|| (*pbuf != '4' || pbuf[2] != '2') && (*pbuf - '0' != ver60[0] || pbuf[2] - '0' != ver60[1]))
	{
		bcpClose(dbproc, bcp);
		FreeMemory(dbproc, pbuf);
		GeneralError(dbproc, 10101);
		return 0;
	}
	if (!bcpSkipWhiteSp(bcp, 1u) || !bcpReadNumber(bcp, pbuf))
	{
		bcpClose(dbproc, bcp);
		FreeMemory(dbproc, pbuf);
		GeneralError(dbproc, 10102);
		return 0;
	}

	ncols = atoi(pbuf);
	retcode = bcp_columns(dbproc, ncols);
	if (retcode == 0)
	{
		bcpClose(dbproc, bcp);
		FreeMemory(dbproc, pbuf);
		return 0;
	}
	if (ncols)
	{
		ncol = 1;
		while (1)
		{
			if (!bcpSkipWhiteSp(bcp, 1u) || !bcpReadNumber(bcp, pbuf) || atoi(pbuf) != ncol)
			{
				bfailed = 0;
				GeneralError(dbproc, 10102);
				break;
			}
			if (!bcpSkipWhiteSp(bcp, 0) || !bcpReadChars(bcp, pbuf) || (token = bcpDataNameToToken(pbuf)) == 0)
			{
				GeneralError(dbproc, 10101);
				bfailed = 0;
				break;
			}
			if (!bcpSkipWhiteSp(bcp, 0) || !bcpReadNumber(bcp, pbuf))
			{
				GeneralError(dbproc, 10103);
				bfailed = 0;
				break;
			}
			if (pbuf[0] != '0' || pbuf[1])
			{
				prefixlen = atoi(pbuf);
				if (!prefixlen)
				{
					bfailed = 0;
					GeneralError(dbproc, SQLECNOR);
					break;
				}
			}
			else
			{
				prefixlen = 0;
			}
			if (!bcpSkipWhiteSp(bcp, 0) || !bcpReadNumber(bcp, pbuf))
			{
				GeneralError(dbproc, 10103);
				bfailed = 0;
				break;
			}
			if (pbuf[0] != '0' || pbuf[1])
			{
				varlen = atol(pbuf);
				if (!varlen)
				{
					bfailed = 0;
					GeneralError(dbproc, SQLECNOR);
					break;
				}
				switch (token)
				{
				case SQLIMAGE:
				case SQLTEXT:
				case 0x24:
				case SQLVARBINARY:
				case SQLINTN:
				case SQLVARCHAR:
				case SQLBINARY:
				case SQLCHAR:
				case SQLFLTN:
				case SQLMONEYN:
				case SQLDATETIMN:
					break;
				default:
					varlen = -1;
					break;
				}
			}
			else
			{
				varlen = 0;
			}
			if (!bcpSkipWhiteSp(bcp, 0))
			{
				bfailed = 0;
				GeneralError(dbproc, 10103);
				break;
			}
			if (!bcpRead(dbproc, bcp, 1u, pbuf) || *pbuf != SQLIMAGE)
			{
				bfailed = 0;
				GeneralError(dbproc, 10067);
				break;
			}
			p1 = pbuf;
			if (bcpRead(dbproc, bcp, 1u, pbuf) == 1)
			{
				do
					C = *p1++;
				while ((C != SQLIMAGE || p1 - 2 >= pbuf && *(p1 - 2) == 0x5C && (p1 - 2 <= pbuf || *(p1 - 3) != 0x5C))
					&& bcpRead(dbproc, bcp, 1u, p1) == 1);
			}
			if (*(p1 - 1) != SQLIMAGE)
			{
				bfailed = 0;
				GeneralError(dbproc, 10067);
				break;
			}
			*(p1 - 1) = 0;
			if (!bcpConvertLiteralToBinary(pbuf, pbuf))
			{
				bfailed = 0;
				break;
			}
			l1 = strlen(pbuf) + 1;
			p2 = &pbuf[l1 + 1];
			if (!bcpSkipWhiteSp(bcp, 0) || !bcpReadNumber(bcp, p2))
			{
				bfailed = 0;
				GeneralError(dbproc, 10103);
				break;
			}
			if (*p2 != SQLINT1 || p2[1])
			{
				ncoli = atoi(p2);
				if (!ncoli)
				{
					bfailed = 0;
					GeneralError(dbproc, SQLECNOR);
					break;
				}
			}
			else
			{
				ncoli = 0;
			}
			if (!bcpSkipWhiteSp(bcp, 0) || !bcpReadChars(bcp, p2))
			{
				bfailed = 0;
				GeneralError(dbproc, 10103);
				break;
			}
			if (prefixlen == 0)
			{
				if (token == SQLVARCHAR)
				{
					token = SQLCHAR;
				}
				else if (token == SQLVARBINARY)
				{
					token = SQLBINARY;
				}
				else
					prefixlen = 2;
			}

			retcode = bcp_colfmt(dbproc, ncol, token, prefixlen, varlen, (LPCBYTE)pbuf, l1 - 1, ncoli);
			if (retcode == 0)
			{
				bfailed = 0;
				break;
			}
			++ncol;
			if (ncol > ncols)
				break;
		}
	}

	bcpClose(dbproc, bcp);
	FreeMemory(dbproc, pbuf);
	return bfailed;
}

int __cdecl bcp_init(PDBPROCESS dbproc, LPCSTR tblname, LPCSTR hfile, LPCSTR errfile, INT direction)
{
	int result = 0; 
	bcp_t* bcp_data,*bcp_log = 0; 

	bcp_info_t* bcpinfo = 0; 
	BYTE* buffer1 = 0; 
	char tablename[96] = { 0 };


	result = CheckEntry(dbproc);
	if (result)
	{
		buffer1 = dbproc->CommLayer->buffer1;
		if (dbproc->bcpinfo)
			return 0;
		result = bcpParse(dbproc, tblname, tablename);
		if (result)
		{
			if (direction != DB_IN && direction != DB_OUT)
			{
				GeneralError(dbproc, 10071);
				return 0;
			}
			if (hfile && *hfile)
			{
				if (direction == 1)
					bcp_data = bcpOpen(dbproc, hfile, 1);
				else
					bcp_data = bcpOpen(dbproc, hfile, 2);
				if (!bcp_data)
				{
					GeneralError(dbproc, 10063);
					return 0;
				}
			}
			else
			{
				if (direction != 1)
					return 0;
				bcp_data = 0;
			}
			if (errfile && *errfile)
			{
				bcp_log = bcpOpen(dbproc, errfile, 2);

				if (!bcp_log)
				{
					bcpClose(dbproc, bcp_data);
					GeneralError(dbproc, 10064);
					return 0;
				}
			}
			else
			{
				bcp_log = 0;
			}
			bcpinfo = (bcp_info_t*)AllocateHeapMemory(4, dbproc, 0x158u, 1);
			if (bcpinfo)
			{
				dbproc->bcpinfo = bcpinfo;
				bcpinfo->b_loaded = bcp_data == 0;
				bcpinfo->bcplog = bcp_log;
				bcpinfo->direction = direction;
				bcpinfo->maxerrs = 10;
				bcpinfo->bcpdata = bcp_data;
				bcpinfo->first = 1;
				bcpinfo->last = 0x7FFFFFFF;
				qmemcpy(bcpinfo->tablename, tablename, 92u);
				bcpinfo->tabname1[30] = tablename[92];
				bcpinfo->blkbuffer = 0;
				bcpinfo->keepnul = 0;
				bcpinfo->dbproc = 0;
				if (bcpSetUp(dbproc))
				{
					result = 1;
					if (direction == 1 && dbproc->ver >= 0x40u)
					{
						*buffer1 = PT_BULKLOAD;
						*dbproc->CommLayer->buffer0 = PT_BULKLOAD;
					}
				}
				else
				{
					bcpClose(dbproc, bcp_data);
					bcpClose(dbproc, bcp_log);
					return 0;
				}
			}
			else
			{
				bcpClose(dbproc, bcp_data);
				bcpClose(dbproc, bcp_log);
				return 0;
			}
		}
	}
	return result;
}

int __cdecl bcp_moretext(PDBPROCESS dbproc, DBINT Length, LPCBYTE p_data)
{
	bcp_info_t* bcpinfo = 0;
	bcp_blob_t* textdata = 0;
	int datsize = 0;


	if (!bcpCheckEntry(dbproc))
		return 0;
	bcpinfo = dbproc->bcpinfo;
	if (Length < 0)
		return 0;
	if (!p_data)
		return 0;
	if (bcpinfo->direction != 1)
		return 0;

	if (!bcpinfo->textcount)
		return 0;
	if (bcpinfo->maxcount != bcpinfo->textcount)
		return 0;
	textdata = &bcpinfo->textdata[bcpinfo->textindex];
	if (!textdata->textsize && !queuepacket(dbproc, (BYTE*)&textdata->field_C, 0xAu))
		return 0;
	if ((Length + textdata->textsize) > textdata->datsize)
	{
		GeneralError(dbproc, 10066);
		return 0;
	}
	if (Length && !queuepacket(dbproc, (BYTE*)p_data, Length))
		return 0;
	datsize = textdata->datsize;
	textdata->textsize += Length;
	if (textdata->textsize >= datsize && ++bcpinfo->textindex >= bcpinfo->maxcount)
		bcpinfo->maxcount = 0;
	return SUCCEED;
}

int __cdecl bcp_sendrow(PDBPROCESS dbproc)
{
	bcp_info_t* bcpinfo = 0; 
	bcp_column_t* column = 0; 
	int i ,i1, j; 
	BYTE* p1 = 0; 

	if (!bcpCheckEntry(dbproc))
		return 0;
	bcpinfo = dbproc->bcpinfo;

	if (bcpinfo->direction != 1)
		return 0;
	if (bcpinfo->b_loaded != 1)
		return 0;
	column = bcpinfo->columns;
	if (!bcpinfo->columns)
		return 0;
	i = 0;
	if (bcpinfo->num_cols)
	{
		do
		{
			column->vardata = (BYTE*)column->varaddr;
			column->varlen = column->collen;
			if (column->bindinfo)
			{
				if (column->varaddr)
				{
					if (column->collen 
						|| column->bindinfo->usertype == SQLTEXT 
						|| column->bindinfo->usertype == SQLIMAGE)
					{
						column->varlen = 0;
						if (column->prefixlen != 0)
						{
							memmove(&column->varlen, column->varaddr, column->prefixlen);
							column->vardata = (BYTE*)&column->varaddr[column->prefixlen];
						}
						if (column->termlen > 0)
						{
							for (i1 = 0; ; ++i1)
							{
								if (column->vardata[i1] == *column->terminator)
								{
									j = 1;
									if (column->termlen > 1)
									{
										p1 = &column->vardata[i1 + 1];
										do
										{
											if (*p1 != column->terminator[j])
												break;
											++j;
											++p1;
										} while (j < column->termlen);

									}
									if (j >= column->termlen)
										break;
								}
							}

							if (column->varlen == 0 || i1 < column->varlen)
								column->varlen = i1;
						}
						if (!column->varlen || column->collen < column->varlen)
						{
							if (column->collen)
								column->varlen = column->collen;
						}
					}
				}
			}
			if (column->usertype == SQLINTN)
			{
				if (column->bindinfo->usertype == SQLINTN && column->varlen > column->bindinfo->length)
					column->varlen = column->bindinfo->length;
			}
			column->column_datsize = column->varlen;
			++column;
			++i;
		} while (i < bcpinfo->num_cols);

	}
	UINT codepage = GetConsoleCP();
	return bcpSendRow(dbproc, codepage != 0);
}
int __stdcall AppendAsciiLong(char* Src, int Value)
{
	int result = 0; 
	char Buffer[12] = { 0 };

	_ltoa(Value, Buffer, 10);
	result = 0;
	strcat(Src, Buffer);
	return result;
}
int __stdcall DoTransaction(PDBPROCESS dbproc, char* Src)
{
	int result = 0;
	int retcode = 0;

	retcode = 1;
	if (dbcmd(dbproc, Src) == 1)
	{
		if (dbsqlexec(dbproc) == 1)
		{
			if (dbresults(dbproc))
			{
				while (1)
				{
					result = dbnextrow(dbproc);
					if (result == NO_MORE_ROWS || !result)
						break;
					if (result == BUF_FULL)
						dbclrbuf(dbproc, 1);
				}
				if (!result)
					retcode = 0;
			}
			else
			{
				retcode = 0;
			}
		}
		else
		{
			retcode = 0;
		}
	}
	else
	{
		retcode = 0;
	}
	dbfreebuf(dbproc);
	return retcode;
}
int __cdecl abort_xact(PDBPROCESS dbproc, int commid)
{
	char buffer[48] = { 0 };

	if (!CheckEntry(dbproc))
		return 0;
	strcpy(buffer, "EXECUTE sp_abort_xact ");
	AppendAsciiLong(buffer, commid);
	return DoTransaction(dbproc, buffer);
}
int __cdecl build_xact_string(const char* xact_name, const char* service_name, int commid, char* lpResult)
{
	int result = 0;
	const char* p1 = 0; 
	int l1 = 0; 
	char* p = 0; 

	if (!lpResult || !service_name)
		return GeneralError(0, 10069);
	*lpResult = 0;
	AppendAsciiLong(lpResult, commid);
	strcat(lpResult, ":");
	strcat(lpResult, service_name);
	strcat(lpResult, ".");
	if (xact_name)
	{
		p1 = (const char*)xact_name;
		l1 = strlen(xact_name) + 1;
		result = 0;
		p = &lpResult[strlen(lpResult) + 1];
	}
	else
	{
		p1 = "XACT_NAME";
		l1 = strlen(p1) + 1;
		result = 0;
		p = &lpResult[strlen(lpResult) + 1];
	}
	qmemcpy(p - 1, p1, l1);
	return result;
}
int __cdecl close_commit(PDBPROCESS dbproc)
{
	return dbclose(dbproc);
}
BOOL __cdecl commit_xact(PDBPROCESS dbproc, int commid)
{
	BYTE* pbyt = 0;
	int result = 0; 
	// xact_state == 0  - There is no active user transaction for the current request.
	int xact_state = 0;
	
	if (!CheckEntry(dbproc))
		return 0;
	if (dbfcmd(dbproc, "EXECUTE sp_commit_xact %ld", commid)
		&& dbsqlexec(dbproc)
		&& dbresults(dbproc) == SUCCEED
		&& dbnextrow(dbproc) == -1
		&& (pbyt = dbdata(dbproc, 1)) != 0)
	{
		xact_state = *(_DWORD*)pbyt;
		do
			result = dbnextrow(dbproc);
		while (result != NO_MORE_ROWS && result);
		while (dbresults(dbproc) != NO_MORE_RESULTS)
			;
		return xact_state == 0;
	}
	else
	{
		dbfreebuf(dbproc);
		return 0;
	}
}
PDBPROCESS __cdecl open_commit(LOGINREC* login, const char* servername)
{
	if (servername)
	{
		dbsetlname(login, "Commit", 4);
		return dbopen(login, servername);
	}
	else
	{
		GeneralError(0, 10069);
		return 0;
	}
}
int __cdecl remove_xact(PDBPROCESS dbproc, DBINT commid, int n)
{
	char buffer[128] = { 0 };

	if (!CheckEntry(dbproc))
		return 0;
	if (n >= 0)
	{
		strcpy(buffer, "EXECUTE sp_remove_xact ");
		AppendAsciiLong(buffer, commid);
		strcat(buffer, ", ");
		AppendAsciiLong(buffer, n);
		return DoTransaction(dbproc, buffer);
	}
	else
	{
		GeneralError(dbproc, SQLEPARM);
		return 0;
	}
}
/*
* Returns 
* commid
* This number is used to identify the transaction in subsequent calls to the commit service. 
* In case of error, this routine will return 0.
*/
int __cdecl start_xact(PDBPROCESS connect, const char* application_name, const char* xact_name, int site_count)
{
	const char* p1 = 0 ; 
	const char* p2 = 0 ; 
	char Src[128] = { 0 };
	int commid = 0; 
	int result = 0; 

	commid = 0;
	if (!CheckEntry(connect))
		return 0;
	if (site_count < 1)
		return 0;
	strcpy(Src, "EXECUTE sp_start_xact ");
	if (application_name)
		p2 = application_name;
	else
		p2 = "Commit";
	strcat(Src, p2);
	strcat(Src, ", ");
	if (xact_name)
		p1 = xact_name;
	else
		p1 = "XACT_NAME";
	strcat(Src, p1);
	strcat(Src, ", ");
	AppendAsciiLong(Src, site_count);
	if (dbcmd(connect, Src) && dbsqlexec(connect) == 1 && dbresults(connect) == SUCCEED)
	{
		result = dbnextrow(connect);
		if (result == NO_MORE_ROWS || !result)
		{
			if (result == NO_MORE_ROWS)
				GeneralError(connect, 10047);
		}
		else
		{
			commid = *(_DWORD*)dbdata(connect, 1);
			while (1)
			{
				result = dbnextrow(connect);
				if (result == NO_MORE_ROWS || !result)
					break;
				if (result == BUF_FULL)
					dbclrbuf(connect, 1);
			}
		}
	}
	dbfreebuf(connect);
	return commid;
}
/*
* Returns
* A character code: “a” (abort), “b” (begin), “c” (commit), “u” (unknown), or -1 (request failed).
*/
int __cdecl stat_xact(PDBPROCESS connect, int commid)
{
	char Src[48] = { 0 };
	int result1 = 0; 
	char C = 0;
	int result = 0; 

	result = 1;
	if (!CheckEntry(connect))
		return 0;
	strcpy(Src, "EXECUTE sp_stat_xact ");
	AppendAsciiLong(Src, commid);
	result1 = dbcmd(connect, Src);
	if (result1 == 1)
	{
		result1 = dbsqlexec(connect);
		if (result1 == 1)
		{
			result1 = dbresults(connect);
			if (result1 == SUCCEED)
			{
				result1 = dbnextrow(connect);
				if (result1 && result1 != NO_MORE_ROWS)
					C = *dbdata(connect, 1);
				while (1)
				{
					result = dbnextrow(connect);
					if (result == NO_MORE_ROWS || !result)
						break;
					if (result == BUF_FULL)
						dbclrbuf(connect, 1);
				}
			}
		}
	}
	dbfreebuf(connect);
	if (result1 && result1 != NO_MORE_ROWS && result)
		return (char)C;
	else
		return -1;
}

int __cdecl dbcolntype(PDBPROCESS connect, int column)
{
	if (CheckColumn(connect, column))
		return connect->columns_info[column - 1]->coltype;
	else
		return -1;
}
BOOL __cdecl dbiscount(PDBPROCESS dbproc)
{
	return CheckEntry(dbproc) && (dbproc->opmask & 1) != 0;
}
/*
* Return the user-defined datatype for a regular result column.
*/
int __cdecl dbcolutype(PDBPROCESS dbproc, int column)
{
	if (!CheckColumn(dbproc, column))
		return -1;
	if (dbproc->columns_info[column - 1]->usertype <= 0x64u)
		return -1;
	else
		return dbproc->columns_info[column - 1]->usertype;
}
BOOL __cdecl dbhasretstat(PDBPROCESS dbproc)
{
	if (!CheckEntry(dbproc))
		return 0;
	return dbproc->ver >= 0x40u && (dbproc->opmask & 2) != 0;
}
int __cdecl dbnumrets(PDBPROCESS dbproc)
{
	if (CheckEntry(dbproc))
		return dbproc->numrets;
	else
		return -1;
}

LPCSTR __cdecl dbretname(PDBPROCESS dbproc, int retnum)
{
	retval_t* rval = 0;

	if (!CheckEntry(dbproc))
		return 0;
	if (retnum > dbproc->numrets || retnum < 1)
		return 0;
	rval = ReturnRequestedRetval(dbproc, retnum);
	if (rval)
		return rval->name;
	else
		return 0;
}
/*
* Determine the datatype of a return parameter value generated by a stored procedure.
*/
int __cdecl dbrettype(PDBPROCESS dbproc, int retnum)
{
	retval_t* rval = 0; 

	if (!CheckEntry(dbproc))
		return -1;
	if (retnum < 1 || retnum > dbproc->numrets)
		return -1;
	rval = ReturnRequestedRetval(dbproc, retnum);
	if (rval)
		return GetColumnType(dbproc, rval->type, rval->retlen);
	else
		return -1;
}

void __cdecl dbrpwclr(db_login_t* login)
{

	if (login)
	{
		dbzero(login->RemotePassword, 0xFFu);
		login->cbRemotePassword = 0;
	}

}
/*
* len + srvname +  len + password
*/
int __cdecl dbrpwset(db_login_t*login, LPCSTR srvname, LPCSTR password, int pwlen)
{
	char* p1 = 0;
	char* p2 = 0; 
	int l0 = 0; 
	int l1 = 0; 

	if (!login)
		return 0;
	l0 = 0;
	if (srvname)
		l0 = strlen(srvname);
	if (!strlen(password) && pwlen)
		return 0;
	l1 = l0 + pwlen + 2;
	if (l1 + login->cbRemotePassword > 0xFF)
		return 0;
	p1 = &login->RemotePassword[login->cbRemotePassword];
	*p1++ = (char)l0;
	dbmove((void*)srvname, p1, l0);
	p2 = (char*)&p1[l0];
	*p2 = (char)pwlen;
	dbmove((void*)password, p2 + 1, pwlen);
	login->cbRemotePassword += l1;
	return SUCCEED;
}
/*
* utype
* user-defined datatype
*/
int __cdecl dbaltutype(PDBPROCESS dbproc, int computeid, int column)
{
	altcol_link_t* link = 0; 

	link = CheckAltColumn(dbproc, computeid, column);
	if (!link)
		return -1;
	if (link->altcols[column - 1]->UserType <= 0x64)
		return -1;
	else
		return link->altcols[column - 1]->UserType;
}
/*
* Convert a machine-readable DBDATETIME value into user-accessible format. 
* Return value SUCCEED or FAIL.
*/
int __cdecl dbdatecrack(PDBPROCESS dbproc, DBDATEREC* dateinfo, DBDATETIME* datetime)
{

	int d = 0; 
	int yrDay = 0;
	int d1 = 0;
	ULONG dttime = 0; 
	int h = 0; 
	int result = FAIL;
	int year = 0;

	if (dbproc && !CheckEntry(dbproc))
		return FAIL;
	if (!dateinfo)
		return FAIL;
	if (!datetime)
		return FAIL;

	d = datetime->dtdays + 53690;
	if (!DtdaysToYearDay(datetime->dtdays, &dateinfo->year, &dateinfo->dayofyear))
		return FAIL;
	yrDay = dateinfo->dayofyear;
	d1 = d - dateinfo->dayofyear;
	dateinfo->weekday = d % 7 + 1;
	year = dateinfo->year;
	dateinfo->week = ((d1 + 1) % 7 + yrDay - 1) / 7 + 1;
	YearDayToYrMoDay(year, yrDay, &dateinfo->month, &dateinfo->day);
	dateinfo->quarter = (dateinfo->month - 1) / 3 + 1;
	dttime = datetime->dttime;
	if (dttime > 25919999)
		return FAIL;
	dateinfo->millisecond = (int)(10 * dttime / 3) % 1000;
	dateinfo->second = (int)(10 * dttime / 3) / 1000 % 60;
	dateinfo->minute = (int)(10 * dttime / 3) / 1000 / 60 % 60;
	h = (int)(10 * dttime / 3) / 1000 / 60 / 60;
	result = SUCCEED;
	dateinfo->hour = h;
	return result;
}

int __cdecl dbcolinfo_regular(PDBPROCESS dbproc, int column, DBCOL* dbcol)
{
	BOOL falg = 0;
	column_info_t* pcolumn = 0; 

	if (!CheckEntry(dbproc))
		return 0;
	if (CheckColumn(dbproc, column))
	{
		falg = dbproc->bServerType == 1 && dbproc->ServerMajor >= 5u;
		pcolumn = dbproc->columns_info[column - 1];
		if (dbcol)
		{
			if (dbcolname(dbproc, column))
			{
				strcpy(dbcol->Name, (char*)dbcolname(dbproc, column));
				if (pcolumn->actualname)
					strcpy(dbcol->ActualName, (const char*)pcolumn->actualname);
				else
					dbcol->ActualName[0] = 0;
				if (dbproc->ntab && dbproc->tabnames[pcolumn->ntab - 1])
					strcpy(dbcol->TableName, dbproc->tabnames[pcolumn->ntab - 1]);
				else
					dbcol->TableName[0] = 0;
				dbcol->Type = dbcoltype(dbproc, column);
				if (dbcol->Type == -1)
				{
					return 0;
				}
				else
				{
					dbcol->UserType = dbproc->columns_info[column - 1]->usertype;
					dbcol->MaxLength = dbcollen(dbproc, column);
					if (dbcol->MaxLength == -1)
					{
						return 0;
					}
					else
					{
						if (dbcol->Type == SQLDECIMAL || dbcol->Type == SQLNUMERIC)
						{
							dbcol->Precision = pcolumn->precision;
							dbcol->Scale = pcolumn->scale;
						}
						else
						{
							dbcol->Precision = -1;
							dbcol->Scale = -1;
						}
						if (falg)
						{
							dbcol->VarLength = pcolumn->flags & 1;
						}
						else if (pcolumn && pcolumn->varlength)
						{
							dbcol->VarLength = pcolumn->varlength;
						}
						else
						{
							dbcol->VarLength = DBUNKNOWN;
						}
						dbcol->B1 = pcolumn
							&& (pcolumn->coltype == SQLVARCHAR
								|| pcolumn->coltype == SQLVARBINARY
								|| pcolumn->coltype == SQLIMAGE
								|| pcolumn->coltype == SQLTEXT);
						if (falg)
							dbcol->Null1 = (pcolumn->flags & 2) != 0;
						else
							dbcol->Null1 = DBUNKNOWN;
						if (falg)
							dbcol->Null = (pcolumn->flags >> 2) & 3;
						else
							dbcol->Null = DBUNKNOWN;
						if (falg)
							dbcol->Updatable = (pcolumn->flags >> 4) & 1;
						else
							dbcol->Updatable = DBUNKNOWN;
						return SUCCEED;
					}
				}
			}
			else
			{
				return 0;
			}
		}
		else
		{
			return 0;
		}
	}
	else
	{
		GeneralError(dbproc, SQLEPARM);
		return 0;
	}
}
int __cdecl dbcolinfo_alternate(PDBPROCESS dbproc, int column, int compid, DBCOL* dbcol)
{
	altcol_link_t* p_link = 0;
	altcol_t* p_col = 0; 

	p_link = CheckAltColumn(dbproc, compid, column);
	if (!p_link)
		return 0;
	p_col = p_link->altcols[column - 1];
	dbcol->Name[0] = 0;
	dbcol->ActualName[0] = 0;
	dbcol->TableName[0] = 0;
	dbcol->Type = (SHORT)dbalttype(dbproc, compid, column);
	if (dbcol->Type == -1)
		return 0;
	dbcol->UserType = dbaltutype(dbproc, compid, column);
	dbcol->MaxLength = dbaltlen(dbproc, compid, column);
	if (dbcol->MaxLength == -1)
		return 0;
	if (dbcol->Type == SQLDECIMAL || dbcol->Type == SQLNUMERIC)
	{
		dbcol->Precision = p_col->precision;
		dbcol->Scale = p_col->scale;
	}
	else
	{
		dbcol->Precision = -1;
		dbcol->Scale = -1;
	}
	dbcol->B1 = p_col->token == SQLVARCHAR || p_col->token == SQLVARBINARY || p_col->token == SQLIMAGE || p_col->token == SQLTEXT;
	dbcol->VarLength = DBUNKNOWN;
	dbcol->Null1 = DBUNKNOWN;
	dbcol->Null = DBUNKNOWN;
	dbcol->Updatable = DBUNKNOWN;
	return SUCCEED;
}
int __cdecl dbcolinfo_cursor(PDBPROCESS dbproc, int column, DBCOL* dbcol)
{
	int l1 = 0;
	char* p1 = 0; 
	DBINT utype = 0; 
	BOOL flag = 0;
	column_info_t* p_col = 0; 

	DBCURSOR* hcursor = (DBCURSOR*)dbproc;

	if (!hcursor || hcursor == (DBCURSOR*)-1 || column <= 0 || column > hcursor->ncols)
		return 0;
	if (!CursorVerify(hcursor, hcursor->dbproc))
		return 0;
	p_col = hcursor->columnsinfo[column - 1];
	flag = hcursor->dbproc->bServerType == 1 && hcursor->dbproc->ServerMajor >= 5u;
	if (p_col->namlen && p_col)
		strcpy(dbcol->Name, p_col->name);
	else
		dbcol->Name[0] = 0;
	if (p_col->actualname)
	{
		l1 = strlen(p_col->actualname) + 1;
		p1 = p_col->actualname;
	}
	else
	{
		l1 = strlen(dbcol->Name) + 1;
		p1 = dbcol->Name;
	}
	qmemcpy(dbcol->ActualName, p1, l1);
	if (p_col->ntab && hcursor->n_tabs && hcursor->tabname_array)
		strcpy(dbcol->TableName, *((const char**)hcursor->tabname_array + p_col->ntab - 1));
	else
		dbcol->TableName[0] = 0;
	dbcol->Type = GetColumnType(hcursor->dbproc, p_col->coltype, p_col->collen);
	if (p_col->usertype <= 0x64u)
		utype = -1;
	else
		utype = p_col->usertype;
	dbcol->UserType = utype;
	dbcol->MaxLength = p_col->collen;
	if (dbcol->Type == SQLDECIMAL || dbcol->Type == SQLNUMERIC)
	{
		dbcol->Precision = p_col->precision;
		dbcol->Scale = p_col->scale;
	}
	else
	{
		dbcol->Precision = -1;
		dbcol->Scale = -1;
	}
	if (flag)
	{
		dbcol->VarLength = p_col->flags & 1;
	}
	else if (p_col && p_col->varlength)
	{
		dbcol->VarLength = p_col->varlength;
	}
	else
	{
		dbcol->VarLength = 2;
	}
	dbcol->B1 = p_col && (p_col->coltype == SQLVARCHAR || p_col->coltype == SQLVARBINARY || p_col->coltype == SQLIMAGE || p_col->coltype == SQLTEXT);
	if (flag)
		dbcol->Null1 = (p_col->flags & 2) != 0;
	else
		dbcol->Null1 = 2;
	if (flag)
		dbcol->Null = (p_col->flags >> 2) & 3;
	else
		dbcol->Null = 2;
	if (flag)
		dbcol->Updatable = (p_col->flags >> 4) & 1;
	else
		dbcol->Updatable = 2;
	return SUCCEED;
}
int __cdecl dbcolinfo(PDBPROCESS dbproc, int ci_type, int column, int a4, DBCOL* dbcol)
{
	if ((ci_type == CI_REGULAR || ci_type == CI_ALTERNATE || ci_type == CI_CURSOR) && dbcol)
	{
		if (dbcol->SizeOfStruct == 122)
		{
			if (ci_type == CI_REGULAR)
			{
				return dbcolinfo_regular(dbproc, column, dbcol);
			}
			else if (ci_type == CI_ALTERNATE)
			{
				return dbcolinfo_alternate(dbproc, column, a4, dbcol);
			}
			else
			{
				return dbcolinfo_cursor(dbproc, column, dbcol);
			}
		}
		else
		{
			return 0;
		}
	}
	else
	{
		GeneralError(dbproc, SQLEPARM);
		return 0;
	}
}

BOOL __cdecl dbvarylen(PDBPROCESS dbproc, int column)
{
	char result = 0;
	DBCOL dbcol ;
	int ntype = 0;

	if (!CheckColumn(dbproc, column))
		return 0;
	ntype = dbproc->columns_info[column - 1]->coltype;
	switch (ntype)
	{
	case SQLIMAGE:
	case SQLTEXT:
	case 0x24:
	case SQLVARBINARY:
	case SQLINTN:
	case SQLVARCHAR:
	case SQLFLTN:
	case SQLMONEYN:
	case SQLDATETIMN:
		result = 1;
		break;
	case SQLDECIMAL:
	case SQLNUMERIC:
		if (dbcolinfo(dbproc, CI_REGULAR, column, 0, &dbcol))
			result = dbcol.VarLength;
		else
			result = 0;
		break;
	default:
		result = 0;
		break;
	}
	return result;
}

int __cdecl dbnullbind(PDBPROCESS dbproc, int column, int* indicator)
{
	int col_ = 0; 

	if (!CheckEntry(dbproc))
		return 0;
	if (column <= dbproc->numcols && column >= 1)
	{
		col_ = column - 1;
		if (dbproc->binds && indicator && dbproc->binds[col_])
		{
			dbproc->binds[col_]->indicator = indicator;
			return SUCCEED;
		}
		else
		{
			GeneralError(dbproc, 10044);
			return 0;
		}
	}
	else
	{
		GeneralError(dbproc, 10042);
		return 0;
	}
}
int __cdecl dbanullbind(PDBPROCESS dbproc, int compid, int column, int* indicator)
{
	altcol_link_t* link = 0; 

	link = CheckAltColumn(dbproc, compid, column);
	if (!link)
		return 0;

	if (link->altbinds && indicator && link->altbinds[column - 1])
	{
		link->altbinds[column - 1]->indicator = indicator;
		return SUCCEED;
	}
	else
	{
		GeneralError(dbproc, 10044);
		return 0;
	}
}
/*
* Read part of a text or image value from the server.
*/
int __cdecl dbreadtext(PDBPROCESS dbproc, void* buf, int bufsize)
{
	int result = 0; 

	int Size = 0, SiZ = 0; 
	column_info_t** columns = 0; 
	int l1 = 0; 
	blob_t* blob = 0;
	BYTE Byt1 = 0;

	column_data_t** column_data = 0; 

	SiZ = 0;
	if (!CheckEntry(dbproc))
		return -1;
	dbproc->ret_status &= ~1u;
	if (bufsize <= 0 || bufsize > 0x10000)
		return -1;
	if (dbproc->nbufrow > 1u
		|| dbproc->ncols != 1
		|| dbproc->n_compute_row
		|| (*dbproc->columns_info)->coltype != SQLTEXT && (*dbproc->columns_info)->coltype != SQLIMAGE)
	{
		return -1;
	}
	if (dbproc->severity_level == 3
		|| (!dbproc->severity_level || dbproc->severity_level == 2) && (dbproc->cmd_flag & 2) == 0)
	{
		return -1;
	}
	if (dbproc->token == SQLROW && dbproc->packet_size == -1)
	{
		dbproc->token = 0;
		dbproc->packet_size = 0;
		return 0;
	}
	while (2)
	{

		if (!dbproc->token)
		{
			dbproc->token = getbyte(dbproc, (BYTE*)&Byt1);
			if (!Byt1)
			{
				dbproc->token = 0;
				return FAIL;
			}
		}
		switch (dbproc->token)
		{
		case SQLERROR:
		case SQLINFO:
		case SQLDONE:
		case SQLDONEPROC:
		case SQLDONEINPROC:
			if (!gettokenlen(dbproc, dbproc->token, (BYTE*)&SiZ))
				return -1;
			break;
		case SQLROW:
			if (dbproc->packet_size)
				break;
			if (!gettokenlen(dbproc, dbproc->token, (BYTE*)&SiZ))
				return -1;
			break;
		default:
			break;
		}
		switch (dbproc->token)
		{
		case OLD_SQLCOLFMT:
		case SQLOFFSET:
		case SQLRETURNSTATUS:
		case SQLPROCID:
		case SQLCOLNAME:
		case SQLCOLFMT:
		case SQLTABNAME:
		case SQLCOLINFO:
		case SQLALTNAME:
		case SQLALTFMT:
		case SQLORDER:
		case SQLRETURNVALUE:
		case SQLCONTROL:
		case SQLALTCONTROL:
		case SQLRETURN:
			dbproc->rowtype = -2;
			dbproc->firstrow = 0;
			dbproc->lastrow = 0;
			dbproc->currow = 0;
			return -2;
		case SQLERROR:
		case SQLINFO:
			if (HandleInfoToken(dbproc, SiZ) == 1)
				goto LABEL_84;
			FreeOnError(0, dbproc);
			return -1;
		case SQLROW:
			column_data = dbproc->columns_data;
			columns = dbproc->columns_info;
			if (dbproc->packet_size)
			{
				Size = dbproc->packet_size;
			}
			else
			{
				free_rowdata(dbproc, 0);
				++dbproc->firstrow;
				++dbproc->currow;
				++dbproc->lastrow;
				dbproc->severity_level = 1;
				dbproc->rowtype = -1;
				l1 = (BYTE)getbyte(dbproc, (BYTE*)&Byt1);
				if (!Byt1)
					return -1;
				blob = (blob_t*)AllocateHeapMemory(4, dbproc, 0x16u, 1);
				if (!blob)
				{
					FreeOnError(0, dbproc);
					return -1;
				}
				(*column_data)->data = (BYTE*)blob;
				if (l1 == 0)
				{
					(*column_data)->len = 0;
					dbproc->token = 0;
					++dbproc->nrows;
					return 0;
				}
				blob->size = l1;
				blob->txptr = (BYTE*)AllocateHeapMemory(4, dbproc, (unsigned __int8)l1, 0);
				if (!blob->txptr)
				{
					FreeOnError(0, dbproc);
					return -1;
				}
				if (dbproc->CommLayer->rbytes
					&& l1 <= dbproc->CommLayer->wbytes
					&& l1 <= dbproc->CommLayer->length - dbproc->CommLayer->rbytes)
				{
					memmove(blob->txptr,
						&dbproc->CommLayer->buffer0[dbproc->CommLayer->rbytes],
						(unsigned __int8)l1);
					dbproc->CommLayer->rbytes += (unsigned __int8)l1;
					dbproc->CommLayer->wbytes -= (unsigned __int8)l1;
					result = 1;
				}
				else
				{
					result = getbytes_internal(dbproc, blob->txptr, (unsigned __int8)l1);
				}
				if (!result)
					return -1;
				if (dbproc->CommLayer->rbytes
					&& dbproc->CommLayer->wbytes >= 8u
					&& dbproc->CommLayer->length - dbproc->CommLayer->rbytes >= 8)
				{
					memmove(blob->timestamp, &dbproc->CommLayer->buffer0[dbproc->CommLayer->rbytes], 8u);
					dbproc->CommLayer->rbytes += 8;
					dbproc->CommLayer->wbytes -= 8;
					result = 1;
				}
				else
				{
					result = getbytes_internal(dbproc, (BYTE*)blob->timestamp, 8);
				}
				if (!result)
					return -1;
				if (!gettokenlen(dbproc, (*columns)->coltype, (BYTE*)&Size))
					return -1;
				blob->len = Size;
				(*column_data)->len = Size;
				dbproc->packet_size = Size;
			}
			if (Size >= bufsize)
				Size = bufsize;
			if (dbproc->textlimit_size)
			{
				if (Size >= dbproc->textlimit_size)
					Size = dbproc->textlimit_size;
			}
			if (Size)
			{
				if (dbproc->CommLayer->rbytes
					&& (int)Size <= dbproc->CommLayer->wbytes
					&& (int)Size <= dbproc->CommLayer->length - dbproc->CommLayer->rbytes)
				{
					memmove(buf, &dbproc->CommLayer->buffer0[dbproc->CommLayer->rbytes], Size);
					dbproc->CommLayer->rbytes += Size;
					dbproc->CommLayer->wbytes -= Size;
					result = 1;
				}
				else
				{
					result = getbytes_internal(dbproc, (BYTE*)buf, Size);
				}
				if (result)
				{
					if ((*columns)->coltype == SQLTEXT)
						dbWinConvFromServer(dbproc, (char*)buf, Size);
					dbproc->packet_size -= Size;
					if (dbproc->packet_size == 0)
					{
						dbproc->packet_size = -1;
						++dbproc->nrows;
					}
					dbproc->ret_status |= 1;
					return Size;
				}
				else
				{
					return -1;
				}
			}
			else
			{
				(*column_data)->len = 0;
				dbproc->token = 0;
				++dbproc->nrows;
				return 0;
			}
		case SQLDONE:
		case SQLDONEPROC:
		case SQLDONEINPROC:
			dbproc->rowtype = -2;
			dbproc->firstrow = 0;
			dbproc->lastrow = 0;
			dbproc->currow = 0;
			dbproc->cmd_flag &= ~0x20u;
			dbproc->severity_level = 0;
			result = HandleDoneToken(dbproc, SiZ, dbproc->token, 0);
			if (result == -5)
			{
			LABEL_84:
				dbproc->token = 0;
				continue;
			}
			dbproc->token = 0;
			return -(result != 0) - 1;
		default:
			// "Possible network error: Bad token from SQL Server: Datastream processing out of sync."
			GeneralError(dbproc, SQLEBTOK);
			return -1;
		}
	}
}
int __stdcall CursorCheckDBversion()
{
	return SUCCEED;
}
char cursr_disall[4][20] = { "compute " ,"into " ,"for browse ","union " };
char cursr_aggr[5][20] = { "sum " ,"avg " ,"count","min","max" };
unsigned __int8* __cdecl sub_7334ACF0(char* Str)
{
	char C = 0; 
	char* p1 = 0; 
	int result = 0; 

	p1 = Str;
	result = 0;
	while (*p1)
	{
		if (*p1 == '\'' || *p1 == '"')
		{
			if (strlen(p1) > 1 && (*p1 == '\'' || *p1 == '"') && *p1 == p1[1])
			{
				p1 += 2;
			}
			else if (result)
			{
				if ((unsigned __int8)*p1 == C)
					return (unsigned __int8*)(p1 + 1);
				++p1;
			}
			else
			{
				C = *p1;
				result = 1;
				++p1;
			}
		}
		else
		{
			if (!result)
				return (unsigned __int8*)p1;
			++p1;
		}
	}
	return (unsigned __int8*)Str;
}
char* __stdcall SearchPhrase(char* stmt, char* cursr, char b)
{
	char* p1 = 0; 
	int C = 0; 
	int n1 = 0;
	int B2 = 0;
	int v11 = 0;
	int B1 = 0;
	char* p3 = 0;
	char* pc = 0;
	char* p2 = 0;
	int result = 0; 

	while (__mb_cur_max <= 1 ? _pctype[(unsigned __int8)*stmt] & 8 : _isctype((unsigned __int8)*stmt, 8))
		++stmt;
	pc = cursr;
	for (p1 = (char*)sub_7334ACF0(stmt); ; p1 = (char*)sub_7334ACF0(p2 + 1))
	{
		p2 = p1;
		if (!p1 || !*p1)
			break;
		if (stmt == p1
			|| (__mb_cur_max <= 1
				? (B1 = _pctype[(unsigned __int8)*(p1 - 1)] & 8)
				: (B1 = _isctype((unsigned __int8)*(p1 - 1), 8)),
				B1
				&& (__mb_cur_max <= 1
					? (v11 = _pctype[(unsigned __int8)*p2] & 8)
					: (v11 = _isctype((unsigned __int8)*p2, 8)),
					!v11)))
		{
			result = 1;
		}
		else
		{
			result = 0;
			if (b && p2 != stmt && (*(p2 - 1) == 40 || *(p2 - 1) == 41 || *(p2 - 1) == 44))
				result = 1;
		}
		if ((unsigned __int8)_tolower((unsigned __int8)*p2) == (unsigned __int8)*pc && result)
		{
			p3 = p2;
			while (*p3)
			{
				if (!*pc)
					return p2;
				C = (unsigned __int8)*pc;
				if (C != (unsigned __int8)_tolower((unsigned __int8)*p3)
					|| (__mb_cur_max <= 1
						? (B2 = _pctype[(unsigned __int8)*p3] & 8)
						: (B2 = _isctype((unsigned __int8)*p3, 8)),
						B2))
				{
					if (__mb_cur_max <= 1)
						n1 = _pctype[(unsigned __int8)*pc] & 8;
					else
						n1 = _isctype((unsigned __int8)*pc, 8);
					if (!n1)
						break;
					if (!(__mb_cur_max <= 1 ? _pctype[(unsigned __int8)*p3] & 8 : _isctype((unsigned __int8)*p3, 8)))
						break;
					while (__mb_cur_max <= 1 ? _pctype[(unsigned __int8)*pc] & 8 : _isctype((unsigned __int8)*pc, 8))
						++pc;
					while (__mb_cur_max <= 1 ? _pctype[(unsigned __int8)*p3] & 8 : _isctype((unsigned __int8)*p3, 8))
						++p3;
				}
				else
				{
					++pc;
					++p3;
				}
			}
			if (!*p3)
				return 0;
		}
		pc = cursr;
	}
	return 0;
}
int __cdecl ScanForInvalidPhrases(PDBPROCESS dbproc, char* stmt)
{
	int i = 0;
	char* p0 = 0; 
	char* p1 = 0; 

	for (i = 0; i < 4; ++i)
	{
		if (SearchPhrase(stmt, cursr_disall[i], 0))
		{
			GeneralError(dbproc, 10078);
			return 0;
		}
	}
	for (i = 0; i < 5; ++i)
	{
		p0 = SearchPhrase(stmt, cursr_aggr[i], 1);
		if (p0)
		{
			for (p1 = (char*)(strlen(cursr_aggr[i]) + p0);
				__mb_cur_max <= 1 ? _pctype[(unsigned __int8)*p1] & 8 : _isctype((unsigned __int8)*p1, 8);
				++p1)
			{
				;
			}
			if (*p1 == '(')
			{
				GeneralError(dbproc, 10079);
				return 0;
			}
		}
	}
	return SUCCEED;
}
int __stdcall CursorVerify(DBCURSOR* cursor, PDBPROCESS dbproc)
{
	DBCURSOR** pp = 0;
	int result = 0; 

	result = 0;
	if (!CheckEntry(dbproc))
		return 0;
	if (dbproc->severity_level == 1 || (dbproc->cmd_flag & 0xB0) != 0)
		return 0;
	if (dbproc->nbufrow > 1u)
	{
		GeneralError(dbproc, 10085);
		return 0;
	}
	if (dbproc->cmdbuffer)
	{
		if ((dbproc->cmd_flag & 1) == 0 || (dbproc->option[8].opt & 1) != 0)
		{
			GeneralError(dbproc, 10076);
			return 0;
		}
		free_cmdbuffer(dbproc);
		dbproc->cmd_flag &= ~1u;
	}
	EnterCriticalSection(&dbproc->cursorSem);
	if (cursor == 0)
		return SUCCEED;
	if (cursor->dbproc != dbproc)
	{
		LeaveCriticalSection(&dbproc->cursorSem);
		return 0;
	}
	for (pp = dbproc->cursors; pp < &dbproc->cursors[dbproc->n_cursor]; ++pp)
	{
		if (*pp == cursor)
			result = 1;
	}
	if (result)
		return SUCCEED;

	LeaveCriticalSection(&dbproc->cursorSem);
	return 0;
}
char cursr_select[] = "select ";
char cursr_where[] = "where ";
char cursr_from[] = "from ";
char cursr_groupby[] = "group by ";
char cursr_orderby[] = "order by ";
char cursr_having[] = "having ";
char cursr_desc[] = " desc ";
char cursr_insert[] = "insert ";
char cursr_into[] = "into ";
char cursr_values[] = "values";
char cursr_update[] = "update ";
char cursr_set[] = "set ";
char cursr_wher[] = "where";
char cursr_delete[] = "delete ";
char cursr_dbname[] = "select db_name()";
char cursr_sptabs[] = "sp_tables @table_name = \'%s\'";
char cursr_sptabown[] = " , @table_owner = \'%s\' ";
char cursr_sptabqual[] = " , @table_qualifier = \'%s\' ";
char cursr_spindex[] = "sp_indexes @table_name = \'%s\' ";
char cursr_spcol[] = "sp_special_columns @table_name = \'%s\' ";
char cursr_view[] = "VIEW";
char cursr_timest[] = "select timestamp from %s where 0 = 1 ";
char cursr_timstamp[] = "timestamp";
char cursr_false[] = "where 0 = 1 ";
char cursr_selctall[] = "select * from %s where 0 = 1 ";
char cursr_gt[] = " > ";
char cursr_ge[] = " >= ";
char cursr_lt[] = " < ";
char cursr_tsequ[] = " tsequal(";
char cursr_null[] = " NULL ";
char cursr_isnul[] = " is NULL ";
char cursr_notnul[] = " is not NULL";
char cursr_and[] = " and ";
char cursr_holdl[] = " HOLDLOCK ";
char cursr_or[] = " OR ";


BOOL __stdcall CursorGetTableNames(DBCURSOR* pcursor)
{
	int l1 = 0; 
	int B1 = 0; 
	char* p1 = 0; 
	char* lpMem = 0; 
	DWORD* ptabnext = 0; 
	buf_node_t* tab = 0; 
	char* p2 = 0; 

	lpMem = (char*)AllocateHeapMemory(4, pcursor->dbproc, strlen(pcursor->from) - 4, 1);
	if (!lpMem)
		return 0;
	p1 = pcursor->from + 5;
	ptabnext = (DWORD*)&pcursor->tabname_array;
	while (*p1)
	{
		while (__mb_cur_max <= 1 ? _pctype[(unsigned __int8)*p1] & 8 : _isctype((unsigned __int8)*p1, 8))
			++p1;
		for (p2 = lpMem; ; ++p2)
		{
			B1 = __mb_cur_max <= 1 ? _pctype[(unsigned __int8)*p1] & 8 : _isctype((unsigned __int8)*p1, 8);
			if (B1 || !*p1 || *p1 == ',')
				break;
			*p2 = *p1++;
		}
		*p2 = 0;
		l1 = strlen(lpMem) + 1;
		if (l1 != 1)
		{
			tab = (buf_node_t*)AllocateHeapMemory(4, pcursor->dbproc, 0xCu, 1);
			if (!tab)
			{
				FreeMemory(pcursor->dbproc, lpMem);
				return 0;
			}
			tab->size = l1;
			tab->data = AllocateHeapMemory(4, pcursor->dbproc, l1, 0);
			if (!tab->data)
			{
				FreeMemory(pcursor->dbproc, tab);
				FreeMemory(pcursor->dbproc, lpMem);
				return 0;
			}
			dbmove(lpMem, tab->data, tab->size);
			*ptabnext = (DWORD)tab;
			ptabnext = (DWORD*)&tab->next;
			++pcursor->n_tabs;
			while (*p1 && *p1 != ',')
				++p1;
			if (*p1)
				++p1;
		}
	}
	FreeMemory(pcursor->dbproc, lpMem);
	return pcursor->n_tabs != 0;
}

int __stdcall CursorParseStatement(DBCURSOR* pcursor, char* Src)
{
	char* pbuf = 0; 
	char* p1,*p2,*p3 = 0; 
	char* p_from = 0; 
	int l1 = 0; 

	char* p_having = 0; 
	char* p_where = 0; 
	char* p_groupby = 0; 
	char* p_orderby = 0; 


	while (__mb_cur_max <= 1 ? _pctype[(unsigned __int8)*Src] & 8 : _isctype((unsigned __int8)*Src, 8))
		++Src;
	if (SearchPhrase(Src, cursr_select, 0) != Src || (p_from = SearchPhrase(Src, cursr_from, 0)) == 0)
	{
		GeneralError(pcursor->dbproc, 10075);
		return 0;
	}
	pbuf = (char*)AllocateHeapMemory(4, pcursor->dbproc, p_from - Src + 1, 0);
	if (!pbuf)
		return 0;
	dbmove(Src, pbuf, p_from - Src);
	*(pbuf + (int)p_from - (int)Src) = 0;
	pcursor->stmt = (char*)pbuf;
	p_where = SearchPhrase(p_from, cursr_where, 0);
	p_orderby = SearchPhrase(p_from, cursr_orderby, 0);
	p_having = SearchPhrase(p_from, cursr_having, 0);
	p_groupby = SearchPhrase(p_from, cursr_groupby, 0);
	if (p_orderby)
	{
		if (p_having)
		{
			if (p_having >= p_orderby)
				p1 = p_orderby;
			else
				p1 = p_having;
		}
		else
		{
			p1 = p_orderby;
		}
	}
	else
	{
		p1 = p_having;
	}
	if (p1)
	{
		if (p_groupby)
		{
			if (p1 >= p_groupby)
				p2 = p_groupby;
			else
				p2 = p1;
		}
		else
		{
			p2 = p1;
		}
	}
	else
	{
		p2 = p_groupby;
	}
	if (p2 && (pcursor->scrollopt == 1 || !pcursor->scrollopt))
	{
		GeneralError(pcursor->dbproc, 10080);
		return 0;
	}
	if (p2 || p_where)
	{
		if (p_where)
			p3 = p_where;
		else
			p3 = p2;
		l1 = p3 - p_from + 1;
		pbuf = (char*)AllocateHeapMemory(4, pcursor->dbproc, l1, 0);
	}
	else
	{
		l1 = strlen(p_from) + 1;
		pbuf = (char*)AllocateHeapMemory(4, pcursor->dbproc, l1, 0);
	}

	if (!pbuf)
		return 0;
	dbmove(p_from, pbuf, l1 - 1);
	pbuf[l1 - 1] = 0;
	pcursor->from = pbuf;
	if (p_where)
	{
		if (p2)
			l1 = p2 - p_where + 1;
		else
			l1 = strlen(p_where) + 1;
		pbuf = (char*)AllocateHeapMemory(4, pcursor->dbproc, l1, 0);

		if (!pbuf)
			return 0;
		dbmove(p_where, pbuf, l1 - 1);
		pbuf[l1 - 1] = 0;
		pcursor->p_where = pbuf;
	}
	if (p2)
	{
		l1 = strlen(p2) + 1;
		pbuf = (char*)AllocateHeapMemory(4, pcursor->dbproc, l1, 0);
		if (!pbuf)
			return 0;
		dbmove(p2, pbuf, l1 - 1);
		pbuf[l1 - 1] = 0;
		pcursor->p_groupby = pbuf;
	}
	return CursorGetTableNames(pcursor);
}
int __stdcall CursorChangeDb(PDBPROCESS dbproc, const char* dbname)
{
	int result = 0; 

	dbprocmsghandle_super(dbproc, 0, 2);
	dbprocerrhandle_super(dbproc, 0, 2);
	result = dbuse(dbproc, dbname);
	dbprocmsghandle_super(dbproc, 0, 4);
	dbprocerrhandle_super(dbproc, 0, 4);
	return result;
}

void __stdcall CursorFreeRowdata(DBCURSOR* cursor)
{
	column_data_t** column_data = 0; 
	int i = 0,j = 0; 
	__int16 nrow = 0; 
	column_info_t** columns = 0; 
	col_bind_t** binds = 0; 

	free_rowdata(cursor->dbproc, 1);
	if (cursor->rows_data)
	{
		columns = cursor->dbproc->columns_info;
		binds = cursor->dbproc->binds;
		column_data = cursor->dbproc->columns_data;
		nrow = cursor->dbproc->ncols;
		cursor->dbproc->binds = 0;
		cursor->dbproc->columns_info = cursor->columnsinfo;
		cursor->dbproc->ncols = cursor->ncols;
		if (cursor->useclientcursors)
			++cursor->dbproc->ncols;
		for (i = 0; i < cursor->n_total_rows; ++i)
		{
			cursor->dbproc->columns_data = (column_data_t**)cursor->rows_data[i];
			if (cursor->dbproc->columns_data && cursor->ncols < cursor->nrowmax)
			{
				for (j = cursor->ncols; j < cursor->nrowmax; ++j)
				{
					if (cursor->dbproc->columns_data[j]->data)
						FreeMemory(cursor->dbproc, cursor->dbproc->columns_data[j]->data);
					FreeMemory(cursor->dbproc, cursor->dbproc->columns_data[j]);
					cursor->dbproc->columns_data[j] = 0;
				}
			}
		}
		for (i = 0; i < cursor->n_total_rows; ++i)
		{
			cursor->dbproc->columns_data = (column_data_t**)cursor->rows_data[i];
			if ((column_data_t**)cursor->rows_data[i] == column_data)
			{
				nrow = 0;
				column_data = 0;
				columns = 0;
				binds = 0;
			}
			cursor->rows_data[i] = 0;
			if (cursor->dbproc->columns_data)
				free_rowdata(cursor->dbproc, 1);
		}
		cursor->dbproc->columns_info = columns;
		cursor->dbproc->columns_data = column_data;
		cursor->dbproc->binds = binds;
		cursor->dbproc->ncols = nrow;
	}

}
keycol_t* __stdcall CursorFreeDBKeycol(PDBPROCESS dbproc, keycol_t* keycol)
{
	keycol_t* next = 0; 

	if (keycol->keyname)
		FreeMemory(dbproc, keycol->keyname);
	if (keycol->where_sub)
		FreeMemory(dbproc, keycol->where_sub);
	next = keycol->next;
	FreeMemory(dbproc, keycol);
	return next;
}
void __stdcall CursorFreeKeys(DBCURSOR* cursor)
{
	keycol_t* next = 0; 
	void* lpMem = 0;
	keynode_t* nodenext = 0;
	keycol_t* keycols = 0; 
	keycols = cursor->keycols;
	nodenext = cursor->keys;
	while (keycols)
	{
		next = CursorFreeDBKeycol(cursor->dbproc, cursor->keycols);
		keycols = next;
	}
	while (nodenext)
	{
		for (next = nodenext->keycol; next; next = CursorFreeDBKeycol(cursor->dbproc, next))
			;
		lpMem = (void*)nodenext;
		nodenext = nodenext->next;
		FreeMemory(cursor->dbproc, lpMem);
	}

}
void __stdcall CursorFreeCurbinds(DBCURSOR* cursor)
{
	int i = 0; 
	keyset_t* keyset = 0; 

	if (cursor->keyset)
	{
		for (i = 0; i < cursor->ncols; ++i)
		{
			keyset = &cursor->keyset[i];
			if (keyset->keys)
				FreeMemory(cursor->dbproc, keyset->keys);
		}
		FreeMemory(cursor->dbproc, cursor->keyset);
	}

}
BOOL __stdcall CursorAllocateKeyDataSub(PDBPROCESS dbproc, keycol_t* keycol, int nrows)
{
	unsigned int dwBytes; 

	dwBytes = nrows * (keycol->length + 4);
	if (dwBytes <= 200000)
	{
		keycol->where_sub = (char*)AllocateHeapMemory(4, dbproc, dwBytes, 0);
		return keycol->where_sub != 0;
	}
	else
	{
		GeneralError(dbproc, 10081);
		return 0;
	}
}
int __stdcall CursorSaveOptccData(DBCURSOR* cursor, int keyid, column_data_t** column_data)
{
	keynode_t* next = 0;
	keycol_t* next1 = 0; 
	DWORD* p = 0;

	for (next = cursor->keys; next; next = next->next)
	{
		for (next1 = next->keycol; next1; next1 = next1->next)
		{
			if (!next1->where_sub && !CursorAllocateKeyDataSub(cursor->dbproc, next1, cursor->n_total_rows))
				return 0;
			p = (DWORD*)((char*)next1->where_sub + keyid * (next1->length + 4));
			if (column_data)
			{
				if ((*column_data)->len)
				{
					*p = (*column_data)->len;
					dbmove((*column_data)->data, p + 1, (*column_data)->len);
				}
				else
				{
					*p = 0;
				}
				++column_data;
			}
			else
			{
				dbzero(p, 4u);
			}
		}
	}
	return SUCCEED;
}

int __stdcall CursorCleanUp(DBCURSOR* cursor, LPVOID lpMem, int Status, int Opt)
{
	__int16 l1 = 0; 
	int k = 0; 
	__int16 nrow = 0; 
	int i = 0;
	buf_node_t* tabary = 0; 
	buf_node_t* node = 0; 
	column_info_t** columns = 0; 

	if (cursor->rowcount)
	{
		FreeMemory(cursor->dbproc, cursor->rowcount);
		cursor->rowcount = 0;
	}
	if (lpMem)
		FreeMemory(cursor->dbproc, lpMem);
	if (!Status)
	{
		if (cursor->dbproc)
		{
			free_cmdbuffer(cursor->dbproc);
			cursor->dbproc->binds = 0;
			if (!cursor->dbproc->bclosed)
				dbcanquery(cursor->dbproc);
		}
	}
	if (Opt == 4)
	{
		if (cursor->pstatus && !Status)
		{
			for (i = 0; i < cursor->n_total_rows; ++i)
				cursor->pstatus[i] = 0;
		}
		if (cursor->scrollopt == 1 || !cursor->scrollopt)
			cursor->n_key_row = 0;
		if (cursor->keys)
		{
			for (i = 0; i < cursor->n_total_rows && CursorSaveOptccData(cursor, i, 0); ++i)
				;
		}
	}
	if ((Opt & 2) == 0)
		CursorFreeRowdata(cursor);
	if ((Opt & 0x19) != 0)
	{
		if (cursor->stmt)
			FreeMemory(cursor->dbproc, cursor->stmt);
		if (cursor->from)
			FreeMemory(cursor->dbproc, cursor->from);
		if (cursor->p_where)
			FreeMemory(cursor->dbproc, cursor->p_where);
		if (cursor->p_groupby)
			FreeMemory(cursor->dbproc, cursor->p_groupby);
		if (cursor->select)
			FreeMemory(cursor->dbproc, cursor->select);
		if (cursor->useclientcursors)
		{
			char** pp = (char**)cursor->tabname_array;
			for (k = 0; k < cursor->n_tabs; ++k)
				FreeMemory(cursor->dbproc, pp[k]);
			if (cursor->tabname_array)
				FreeMemory(cursor->dbproc, cursor->tabname_array);
		}
		else
		{
			tabary = (buf_node_t*)cursor->tabname_array;
			while (tabary)
			{
				if (tabary->data)
					FreeMemory(cursor->dbproc, tabary->data);
				node = tabary;
				tabary = tabary->next;
				FreeMemory(cursor->dbproc, node);
			}
		}
		if (cursor->pp_table_array)
		{
			for (i = 0; i < cursor->n_table_array_size; ++i)
				FreeMemory(cursor->dbproc, cursor->pp_table_array[i]);
			FreeMemory(cursor->dbproc, cursor->pp_table_array);
		}
		if (cursor->dbproc)
		{
			columns = 0;
			nrow = 0;
			if (cursor->dbproc->columns_info != cursor->columnsinfo)
			{
				columns = cursor->dbproc->columns_info;
				nrow = cursor->dbproc->ncols;
			}
			if (cursor->useclientcursors)
				l1 = cursor->ncols + 1;
			else
				l1 = cursor->ncols;
			cursor->dbproc->numcols = l1;
			cursor->dbproc->ncols = cursor->dbproc->numcols;
			cursor->dbproc->binds = cursor->binds;
			cursor->dbproc->columns_info = cursor->columnsinfo;
			cursor->dbproc->columns_data = cursor->columnsdata;
			if (cursor->useclientcursors)
				--cursor->dbproc->numcols;
			free_binds(cursor->dbproc);
			if (cursor->useclientcursors)
				++cursor->dbproc->numcols;
			free_rowdata(cursor->dbproc, 1);
			free_coldata(cursor->dbproc);
			if (cursor->rows_data)
				FreeMemory(cursor->dbproc, cursor->rows_data);
			CursorFreeCurbinds(cursor);
			CursorFreeKeys(cursor);
			if (columns)
			{
				cursor->dbproc->columns_info = columns;
				cursor->dbproc->ncols = nrow;
				free_coldata(cursor->dbproc);
			}
		}
	}
	if ((Opt & 0x18) != 0 && cursor->dbproc && cursor->dbproc->n_cursor)
	{
		for (i = 0; i < cursor->dbproc->n_cursor; ++i)
		{
			if (cursor->dbproc->cursors[i] == cursor)
			{
				cursor->dbproc->cursors[i] = 0;
				break;
			}
		}
	}
	if ((Opt & 0x19) != 0)
		FreeMemory(cursor->dbproc, cursor);
	if (Opt != 16)
		LeaveCriticalSection(&cursor->dbproc->cursorSem);
	return Status;
}
void __stdcall dbclosecursors(PDBPROCESS dbproc)
{
	int i = 0; 

	EnterCriticalSection(&dbproc->cursorSem);
	for (i = 0; i < dbproc->n_cursor; ++i)
	{

		if (dbproc->cursors[i])
			CursorCleanUp(dbproc->cursors[i], 0, 1, 16);
	}
	FreeMemory(dbproc, dbproc->cursors);
	dbproc->cursors = 0;
	LeaveCriticalSection(&dbproc->cursorSem);
}
int __stdcall CursorSetupKeyCols(
	DBCURSOR* pcursor,
	buf_node_t* tablink,
	__int16 ntab,
	int indid,
	int keycnt,
	int* lpStatus)
{
	keycol_t* keycol = 0;
	int i = 0; 
	int Size = 0; 
	keycol_t** next = 0;
	PDBPROCESS dbproc = 0; 
	char* p1 = 0; 

	dbproc = pcursor->dbproc;
	for (next = &pcursor->keycols; next; next = &(*next)->next)
		;
	for (i = 1; i <= keycnt; ++i)
	{
		if (!dbfcmd(dbproc, "select INDEX_COL('%s', %d, %d) ", (const char*)tablink->data, indid, i)
			|| !dbsqlexec(dbproc)
			|| dbresults(dbproc) == FAIL
			|| !dbnextrow(dbproc))
		{
			return 0;
		}

		Size = (*dbproc->columns_data)->len;
		if (Size)
		{
			*lpStatus = 1;
			keycol = (keycol_t*)AllocateHeapMemory(4, dbproc, 0x1Cu, 1);
			if (!keycol)
				return 0;
			*next = keycol;

			keycol->keyname = (char*)AllocateHeapMemory(4, dbproc, Size + tablink->size + 1, 0);
			if (!keycol->keyname)
				return 0;

			dbmove(tablink->data, keycol->keyname, tablink->size);
			p1 = &keycol->keyname[tablink->size - 1];
			*p1++ = '.';
			dbmove((void*)(*dbproc->columns_data)->data, p1, Size);
			p1[Size] = 0;
			keycol->size = Size + tablink->size + 1;
			keycol->ntab = ntab;
			keycol->opt = 1;
			++pcursor->keyid;
			if (dbnextrow(dbproc) != NO_MORE_ROWS)
				return 0;
		}
		else
		{
			while (dbnextrow(dbproc) != NO_MORE_ROWS)
				;
		}
	}
	return SUCCEED;
}
char cursr_sysinds[] = "sysindexes";
int __stdcall CursorUseSysTables(DBCURSOR* pcursor, char* tabname)
{
	buf_node_t* tabnamelink = 0; 
	char* p1 = 0; 
	int status_ = 0; 
	int i = 0; 
	int keycnt = 0; 
	int indid = 0; 
	int typ = 0; 
	char* tbname_next = 0; 
	PDBPROCESS dbproc = 0; 
	int indid_ = 0; 
	int status = 0; 
	char* p = 0; 

	dbproc = pcursor->dbproc;
	tabnamelink = pcursor->tabname_array;
	typ = INTBIND;
	dbcancel(dbproc);
	for (i = 0; i < pcursor->n_tabs; ++i)
	{
		tbname_next = (char*)tabnamelink->data;
		*tabname = 0;
		p1 = (char*)tabname;
		for (p = &tbname_next[tabnamelink->size - 1]; p > tbname_next && *p != '.'; --p)
			;
		if (*p == '.')
		{
			while (tbname_next <= p)
				*p1++ = *tbname_next++;
		}
		dbmove(cursr_sysinds, p1, 0xBu);
		if (!dbfcmd(
			dbproc,
			"select indid, status, keycnt from %s where indid >= 1 and id = OBJECT_ID('%s') order by indid, keycnt ",
			tabname,
			(const char*)tabnamelink->data)
			|| !dbsqlexec(dbproc)
			|| dbresults(dbproc) == FAIL)
		{
			return 0;
		}
		dbbind(dbproc, 1, typ, 0, (BYTE*)&indid);
		dbbind(dbproc, 2, typ, 0, (BYTE*)&status);
		dbbind(dbproc, 3, typ, 0, (BYTE*)&keycnt);
		status_ = 0;
		indid_ = 0;
		while (dbnextrow(dbproc) != NO_MORE_ROWS)
		{
			if (status_ || (status & 2) == 0)
			{
				if (!indid_)
					indid_ = indid;
			}
			else
			{
				dbbind(dbproc, 1, typ, 0, 0);
				dbbind(dbproc, 2, typ, 0, 0);
				dbbind(dbproc, 3, typ, 0, 0);
				while (dbnextrow(dbproc) != NO_MORE_ROWS)
					;
				if (!CursorSetupKeyCols(pcursor, tabnamelink, i + 1, indid, keycnt, &status_))
					return 0;
			}
		}
		while (dbresults(dbproc) == SUCCEED)
		{
			while (dbnextrow(dbproc) != NO_MORE_ROWS)
				;
		}
		if (!status_)
			return 0;
		tabnamelink = tabnamelink->next;
	}
	return SUCCEED;
}
int __stdcall CursorFindViewKeys(DBCURSOR* hcursor)
{
	keycol_t* keycol = 0;
	int i = 0;
	keycol_t** p_keycols = 0;
	column_info_t** columns = 0;
	PDBPROCESS dbproc = 0;

	dbproc = hcursor->dbproc;

	if (hcursor->n_tabs == 1)
	{
		if (dbcmd(dbproc, cursr_select) // "select "
			&& dbcmd(dbproc, " * ")
			&& dbcmd(dbproc, hcursor->from)
			&& dbcmd(dbproc, " ")
			&& dbcmd(dbproc, cursr_false) // "where 0 = 1 "
			&& dbcmd(dbproc, "for browse ")
			&& dbsqlexec(dbproc)
			&& dbresults(dbproc))
		{
			hcursor->n_table_array_size = dbproc->ntab - 1;
			hcursor->pp_table_array = dbproc->tabnames;
			columns = dbproc->columns_info;
			for (i = 0; i < dbproc->ncols; ++i)
			{
				if ((columns[i]->type & 8) != 0)
				{
					keycol = (keycol_t*)AllocateHeapMemory(4, dbproc, 0x1Cu, 1);
					if (!keycol)
						return 0;
					*p_keycols = keycol;
					keycol->keyname = (char*)AllocateHeapMemory(4, dbproc, columns[i]->namlen + 1, 0);
					if (!keycol->keyname)
						return 0; 
					dbmove(columns[i]->name, keycol->keyname, columns[i]->namlen);
					keycol->keyname[columns[i]->namlen] = 0;
					keycol->size = columns[i]->namlen + 1;
					keycol->ntab = columns[i]->ntab;
					keycol->opt = 1;
					++hcursor->keyid;
				}
			}
			dbproc->tabnames = 0;
			return SUCCEED;
		}
		else
		{
			return 0;
		}
	}
	else
	{
		GeneralError(dbproc, 10084);
		return 0;
	}
}
BOOL __stdcall CursorFindKeys(DBCURSOR* hcursor)
{
	BYTE* pbyte = 0;
	size_t SiZ = 0;
	buf_node_t* tabnames = 0;
	keycol_t* keycol = 0;
	int e = 0; 
	int Size = 0;
	int bSucc = 0;
	int i = 0;
	char* p0, * p1,* p2,* p3, * p4, * p5, * p6;
	char* data = 0;

	int result = 0;
	char* lpMem = 0;
	keycol_t** pnext = 0;

	int i1 = 0;
	column_data_t** column_data = 0; 

	result = 1;
	tabnames = hcursor->tabname_array;
	bSucc = 0;
	pnext = &hcursor->keycols;
	lpMem = (char*)AllocateHeapMemory(4, hcursor->dbproc, 200u, 0);
	if (!lpMem)
		return 0;
	p1 = lpMem;
	p2 = lpMem + 33;
	p3 = lpMem + 66;
	p4 = lpMem + 100;
	for (i = 0; i < hcursor->n_tabs; ++i)
	{
		data = (char*)tabnames->data;
		*p1 = 0;
		*p2 = 0;
		*p3 = 0;
		*p4 = 0;
		p6 = 0;
		p5 = 0;
		for (p0 = data; p0 < &data[tabnames->size]; ++p0)
		{
			if (*p0 == '.')
			{
				if (p5)
				{
					p6 = p5;
					p5 = p0 + 1;
					break;
				}
				p5 = p0 + 1;
			}
		}
		if (p6)
		{
			if (dbcmd(hcursor->dbproc, cursr_dbname) != 1 || dbsqlexec(hcursor->dbproc) != 1 || dbresults(hcursor->dbproc) != SUCCEED || dbnextrow(hcursor->dbproc) != -1)
			{
				result = 0;
				break;
			}
			Size = dbdatlen(hcursor->dbproc, 1);
			SiZ = Size <= 32 ? Size : 32;
			pbyte = dbdata(hcursor->dbproc, 1);
			dbmove(pbyte, p4, SiZ);
			p4[SiZ] = 0;
			for (p0 = data; p0 < p6 - 1 && p0 - data < 32; ++p0)
				*p1++ = *p0;
			*p1 = 0;
			p1 = lpMem;
			dbnextrow(hcursor->dbproc);
			dbresults(hcursor->dbproc);
			if (CursorChangeDb(hcursor->dbproc, lpMem) != 1)
			{
				*p4 = 0;
				result = 0;
				break;
			}
		}
		if (p5 && (!p6 || *p6 != '.'))
		{
			if (p6)
				p0 = p6;
			else
				p0 = data;
			if ((unsigned int)(p5 - p0 - 1) <= 0x20)
				SiZ = p5 - p0 - 1;
			else
				SiZ = 32;
			dbmove(p0, p2, SiZ);
			p2[SiZ] = 0;
		}
		if (p5)
			p0 = p5;
		else
			p0 = data;
		i1 = (int)IS_N_CHAR_DBCS(p3, 32);
		strncpy(p3, p0, 32 - i1);
		p3[32 - i1] = 0;
		if (dbfcmd(hcursor->dbproc, "sp_tables @table_name = '%s'", p3) != 1)
		{
			result = 0;
			break;
		}
		if (*p2 && dbfcmd(hcursor->dbproc, " , @table_owner = '%s' ", p2) != 1)
		{
			result = 0;
			break;
		}
		if (dbsqlexec(hcursor->dbproc) != SUCCEED || dbresults(hcursor->dbproc) != SUCCEED || dbnextrow(hcursor->dbproc) != MORE_ROWS)
		{
			result = 0;
			break;
		}
		dbmove(*(void**)(*((_DWORD*)hcursor->dbproc->columns_data + 3) + 4), lpMem + 145, 4u);
		dbcancel(hcursor->dbproc);
		if (!_strnicmp(lpMem + 145, cursr_view, 4u))
		{
			result = CursorFindViewKeys(hcursor);
			break;
		}
		if (!dbfcmd(hcursor->dbproc, "sp_special_columns @table_name = '%s' ", p3))
		{
			result = 0;
			break;
		}
		if (*p2 && !dbfcmd(hcursor->dbproc, " , @table_owner = '%s' ", p2))
		{
			result = 0;
			break;
		}
		if (*p1 && !dbfcmd(hcursor->dbproc, " , @table_qualifier = '%s' ", p1))
		{
			result = 0;
			break;
		}
		if (tabnames == hcursor->tabname_array)
		{
			dbprocmsghandle_super(hcursor->dbproc, 0, 2);
			dbprocerrhandle_super(hcursor->dbproc, 0, 2);
		}
		if (!dbsqlexec(hcursor->dbproc) || dbresults(hcursor->dbproc) == FAIL )
		{
			if (tabnames == hcursor->tabname_array)
			{
				dbprocmsghandle_super(hcursor->dbproc, 0, 4);
				dbprocerrhandle_super(hcursor->dbproc, 0, 4);
				bSucc = 1;
			}
			result = 0;
			break;
		}
		if (tabnames == hcursor->tabname_array)
		{
			dbprocmsghandle_super(hcursor->dbproc, 0, 4);
			dbprocerrhandle_super(hcursor->dbproc, 0, 4);
		}
		e = 0;
		while (1)
		{
			result = dbnextrow(hcursor->dbproc);
			if (result == NO_MORE_ROWS || result == FAIL)
				break;
			column_data = hcursor->dbproc->columns_data;
			if (!column_data[1]->len)
			{
				result = 0;
				break;
			}
			if (e == 0)
				e = 1;
			// key  = table name + column [1] name
			hcursor->keycols = (keycol_t*)AllocateHeapMemory(4, hcursor->dbproc, 0x1Cu, 1);
			if (!hcursor->keycols)
			{
				result = 0;
				break;
			}
			*pnext = keycol;
			pnext = &keycol->next;
			keycol->keyname = (char*)AllocateHeapMemory(4, hcursor->dbproc, column_data[1]->len + tabnames->size + 1, 0);
			if (!keycol->keyname)
			{
				result = 0;
				break;
			}

			dbmove(tabnames->data, keycol->keyname, tabnames->size);
			p0 = &keycol->keyname[tabnames->size - 1];
			*p0++ = '.';
			dbmove(column_data[1]->data, p0, column_data[1]->len);
			p0[column_data[1]->len] = 0;
			keycol->size = column_data[1]->len + tabnames->size + 1;
			keycol->ntab = i + 1;
			keycol->opt = 1;
			++hcursor->keyid;
		}
		if (!result)
			break;
		do
			result = dbnextrow(hcursor->dbproc);
		while (result != NO_MORE_ROWS && result);
		if (!result)
			break;
		dbresults(hcursor->dbproc);
		if (*p4)
			CursorChangeDb(hcursor->dbproc, p4);
		*p4 = 0;
		if (e == 0)
		{
			GeneralError(hcursor->dbproc, 10077);
			result = 0;
			break;
		}
		tabnames = tabnames->next;
	}
	if (*p4)
		CursorChangeDb(hcursor->dbproc, p4);
	if (!result)
	{
		if (bSucc)
			result = CursorUseSysTables(hcursor, lpMem);
	}
	FreeMemory(hcursor->dbproc, lpMem);
	return result != 0;
}
int __stdcall CursorChangeRowcount(DBCURSOR* hcursor, unsigned int nrow)
{
	char Buffer[36] = { 0 };
	PDBPROCESS dbproc = 0;

	LPVOID lpMem = 0; 

	dbproc = hcursor->dbproc;

	free_cmdbuffer(dbproc);
	if ((hcursor->opt & 1) != 0)
		lpMem = hcursor->rowcount;
	else
		lpMem = 0;
	hcursor->opt = (BYTE)hcursor->dbproc->option[2].opt; 
	if ((hcursor->opt & 1) != 0)
	{
		hcursor->rowcount = hcursor->dbproc->option[2].name; // "rowcount"
		hcursor->dbproc->option[2].name = 0;
		hcursor->dbproc->option[2].opt &= ~1u;
	}
	_ltoa(nrow, Buffer, 10);
	if (SetDBOption(dbproc, 2, Buffer)
		&& dbsqlexec(dbproc)
		&& dbresults(dbproc))
	{
		if (lpMem)
			FreeMemory(dbproc, lpMem);
		return SUCCEED;
	}
	else
	{
		hcursor->dbproc->option[2].name = hcursor->rowcount;
		hcursor->dbproc->option[2].opt = (BYTE)hcursor->opt;
		hcursor->rowcount = (char*)lpMem;
		if (!lpMem)
			hcursor->opt &= ~1u;
		return 0;
	}
}
int __stdcall CursorAllocateKeyData(DBCURSOR* hcursor, int Size)
{
	int SiZ = 0; 
	int maxsize = 0; 
	keycol_t* next = 0;

	maxsize = 200000;
	if (Size == -1)
	{
		for (next = hcursor->keycols; next; next = next->next)
		{
			if (maxsize >= 200000 / (next->length + 4))
				SiZ = 200000 / (next->length + 4);
			else
				SiZ = maxsize;
			maxsize = SiZ;
		}
	}
	else
	{
		maxsize = Size;
	}
	for (next = hcursor->keycols; next; next = next->next)
	{
		if (!CursorAllocateKeyDataSub(hcursor->dbproc, next, maxsize))
			return 0;
	}
	hcursor->nkey = maxsize;
	return SUCCEED;
}

int __stdcall CursorBuildDynamicWhere(DBCURSOR* hcursor, int opt)
{
	int B1 = 0; 
	int l1 = 0; 
	int i = 0,j = 0; 
	keycol_t* next = 0; 
	keycol_t* keycol_next = 0; 
	int row_ = 0; 
	PDBPROCESS dbproc = 0; 
	int result = 0; 
	char* oper = 0; 
	int* Src = 0; 
	void* Srca = 0; 

	dbproc = hcursor->dbproc;
	result = 1;
	switch (opt)
	{
	case 1:
		return SUCCEED;
	case 2:
		oper = cursr_gt; // " > "
		if (hcursor->n_key_row == 0)
			return 0;
		row_ = hcursor->total_rows_fetched + hcursor->nfetch_row - 2;
		if (row_ < 0)
			row_ = 0;
		break;
	case 3:
		oper = cursr_lt; //  " < "
		row_ = 0;
		break;
	default:
		return 0;
	}
	for (next = hcursor->keycols; next; next = next->next)
		next->cmdstring = 0;
	for (i = 0; i < hcursor->keyid; ++i)
	{
		if (i)
		{
			result = dbcmd(dbproc, " or ");
			if (!result)
				break;
		}
		if (!dbcmd(dbproc, "("))
		{
			result = 0;
			break;
		}
		keycol_next = hcursor->keycols;
		for (j = 0; j <= i; ++j)
		{
			Src = (int*)((char*)keycol_next->where_sub + row_ * (keycol_next->length + 4));
			l1 = keycol_next->where_sub ? *Src : 0;
			Srca = Src + 1;
			if (!dbcmd(dbproc, keycol_next->keyname))
				break;
			if (l1)
			{
				if (!keycol_next->cmdstring)
				{
					keycol_next->cmdstring = CursorWriteBuf(dbproc, keycol_next->type, l1, Srca);
					if (!keycol_next->cmdstring)
						break;
				}
				B1 = i == j ? dbcmd(dbproc, oper) : dbcmd(dbproc, " = ");
				if (!B1 || !dbcmd(dbproc, keycol_next->cmdstring))
					break;
			}
			else
			{
				if (i == j)
					result = dbcmd(dbproc, cursr_notnul); // " is not NULL"
				else
					result = dbcmd(dbproc, cursr_isnul); // " is NULL "
				if (!result)
					break;
			}
			if (i != j && !dbcmd(dbproc, cursr_and))
				break;
			keycol_next = keycol_next->next;
		}
		result = dbcmd(dbproc, ")");
		if (!result)
			break;
	}
	for (next = hcursor->keycols; next; next = next->next)
	{
		if (next->cmdstring)
			FreeMemory(dbproc, next->cmdstring);
		next->cmdstring = 0;
	}
	return result;
}
int __stdcall CursorOrderbyKeyset(DBCURSOR* hcursor, int opt)
{
	keycol_t* next = 0; 
	PDBPROCESS dbproc = 0;

	dbproc = hcursor->dbproc;
	if (!dbcmd(hcursor->dbproc, " ") || !dbcmd(dbproc, cursr_orderby)) // "order by "
		return 0;
	for (next = hcursor->keycols; next; next = next->next)
	{
		if (!dbcmd(dbproc, next->keyname))
			return 0;
		if (opt == 3 && !dbcmd(dbproc, cursr_desc)) // " desc "
			return 0;
		if (next->next && !dbcmd(dbproc, ", "))
			return 0;
	}
	return SUCCEED;
}
int __stdcall CursorBuildKeysetData(DBCURSOR* hcursor, int B)
{
	int result = 0; 
	int Value = 0; 
	size_t Size = 0; 
	int l1, l2, i, k;
	keycol_t* keycols = 0,* next = 0;
	PDBPROCESS dbproc = 0;


	dbproc = hcursor->dbproc;
	l2 = 0;
	if (B == 1)
	{
		keycols = hcursor->keycols;
		hcursor->fetchtype &= 0xFC;
		if (keycols->where_sub == 0)
		{
			if (hcursor->scrollopt != CUR_DYNAMIC && hcursor->scrollopt)
			{
				if (hcursor->scrollopt == CUR_KEYSET)
				{
					l1 = hcursor->scrollopt;       // CUR_KEYSET
				}
				else
				{                                       // CUR_INSENSITIVE
					if ((unsigned int)(hcursor->n_total_rows * hcursor->scrollopt) >= 200000)
					{
						GeneralError(dbproc, 10081);
						return 0;
					}
					l1 = hcursor->n_total_rows * hcursor->scrollopt;
				}
			}
			else
			{                                         // CUR_FORWARD,CUR_DYNAMIC
				l1 = hcursor->n_total_rows;
			}
			if (!CursorAllocateKeyData(hcursor, l1))
				return 0;
		}
		if (hcursor->scrollopt == CUR_FORWARD || hcursor->scrollopt == CUR_DYNAMIC)
			return SUCCEED;
	}
	else
	{
		if (hcursor->scrollopt == CUR_KEYSET || (hcursor->fetchtype & 2) != 0)
			return -2;
		hcursor->fetchtype &= 0xFC;
		if (hcursor->p_groupby)
			l2 = hcursor->field_4C + hcursor->n_key_row - 1;
	}
	if (hcursor->scrollopt != CUR_KEYSET && !CursorChangeRowcount(hcursor, l2 + hcursor->n_total_rows * hcursor->scrollopt + 1))
		return 0;
	if (!dbcmd(dbproc, (char*)hcursor->select)
		|| !dbcmd(dbproc, " ")
		|| !dbcmd(dbproc, hcursor->from)
		|| !dbcmd(dbproc, " ")
		|| !dbcmd(dbproc, hcursor->p_where)
		|| !dbcmd(dbproc, " "))
	{
		return 0;
	}
	if (hcursor->p_groupby)
	{
		if (!dbcmd(dbproc, hcursor->p_groupby))
			return 0;
	}
	else
	{
		if (!B)
		{
			if (hcursor->p_where)
			{
				if (!dbcmd(dbproc, " and ( "))
					return 0;
			}
			else if (!dbcmd(dbproc, cursr_where)) // "where "
			{
				return 0;
			}
			if (!CursorBuildDynamicWhere(hcursor, 2) || !dbcmd(dbproc, " "))
				return 0;
			if (hcursor->p_where && !dbcmd(dbproc, " ) "))
				return 0;
		}
		if (!CursorOrderbyKeyset(hcursor, 2))
			return 0;
	}
	if (!dbsqlexec(dbproc) || dbresults(dbproc) == FAIL)
		return 0;
	if (l2)
	{
		for (i = 0; i < l2; ++i)
		{
			if (!dbnextrow(dbproc))
				return 0;
		}
	}
	for (next = hcursor->keycols; next; next = next->next)
		next->cmdstring = next->where_sub;
	for (k = 0; k < hcursor->nkey; ++k)
	{
		result = dbnextrow(dbproc);
		if (!result)
			return 0;
		if (result == NO_MORE_ROWS)
			break;
		next = hcursor->keycols;
		for (i = 0; i < hcursor->keyid; ++i)
		{
			Size = dbproc->columns_data[i]->len;
			*(_DWORD*)next->cmdstring = dbproc->columns_data[i]->len;
			if (Size)
				dbmove(dbproc->columns_data[i]->data, next->cmdstring + 4, Size);
			next->cmdstring += next->length + 4;
			next = next->next;
		}
	}
	if (result == NO_MORE_ROWS || dbnextrow(dbproc) == NO_MORE_ROWS)
	{
		if (B == 1)
		{
			hcursor->fetchtype |= 2;
		}
		hcursor->fetchtype |= 1;
	}
	if (hcursor->p_groupby && (hcursor->fetchtype & 2) == 0)
	{
		GeneralError(dbproc, 10080);
		return 0;
	}
	if (hcursor->scrollopt == CUR_KEYSET && dbnextrow(dbproc) != NO_MORE_ROWS)
	{
		GeneralError(dbproc, 10081);
		return 0;
	}
	if (dbnextrow(dbproc) != NO_MORE_ROWS)
		return 0;
	if (B == 1)
		l1 = 1;
	else
		l1 = hcursor->n_key_row + hcursor->field_4C;
	hcursor->field_4C = l1;
	hcursor->n_key_row = k;
	result = 1;
	if (hcursor->scrollopt != CUR_KEYSET)
	{
		Value = hcursor->rowcount ? atoi(hcursor->rowcount) : 0;
		if (!CursorChangeRowcount(hcursor, Value))
			return 0;
	}
	return result;
}
int __stdcall CursorBuildOptccSet(DBCURSOR* hcursor, int ntab)
{
	buf_node_t* tabnamelink = 0;
	keynode_t* keynode = 0;
	int i = 0;
	keycol_t* keycol = 0, * next = 0;
	column_info_t** columns = 0;
	keynode_t* keynext = 0;
	PDBPROCESS dbproc = 0;

	keynext = hcursor->keys;
	dbproc = hcursor->dbproc;
	while (keynext)
	{
		if (keynext->ntab == ntab)
			return SUCCEED;
		keynext = keynext->next;
	}
	keynode = (keynode_t*)AllocateHeapMemory(4, hcursor->dbproc, 0xCu, 1);
	if (!keynode)
		return 0;
	tabnamelink = hcursor->tabname_array;
	for (i = 1; i < ntab; ++i)
		tabnamelink = tabnamelink->next;
	dbprocmsghandle_super(dbproc, 0, 2);
	dbprocerrhandle_super(dbproc, 0, 2);
	if (hcursor->n_table_array_size <= 1
		&& dbfcmd(dbproc, "select timestamp from %s where 0 = 1 ", (const char*)tabnamelink->data)
		&& dbsqlexec(dbproc)
		&& dbresults(dbproc))
	{
		keynode->opt = 1;
	}
	else
	{
		keynode->opt = 2;
		if (!dbfcmd(dbproc, "select * from %s where 0 = 1 ", (const char*)tabnamelink->data)
			|| dbsqlexec(dbproc) == FAIL
			|| dbresults(dbproc) == FAIL)
		{
			FreeMemory(dbproc, keynode);
			return 0;
		}
	}
	dbprocmsghandle_super(dbproc, 0, 4);
	dbprocerrhandle_super(dbproc, 0, 4);
	if ((keynode->opt & 1) != 0)
	{
		keycol = (keycol_t*)AllocateHeapMemory(4, dbproc, 0x1Cu, 1);
		if (!keycol)
		{
			FreeMemory(dbproc, keynode);
			return 0;
		}
		keycol->keyname = (char*)AllocateHeapMemory(4, dbproc, tabnamelink->size + 10, 0);
		if (!keycol->keyname)
		{
			FreeMemory(dbproc, keycol);
			FreeMemory(dbproc, keynode);
			return 0;
		}
		columns = dbproc->columns_info;
		dbmove(tabnamelink->data, keycol->keyname, tabnamelink->size - 1);
		keycol->keyname[tabnamelink->size - 1] = '.';
		dbmove(cursr_timstamp, &keycol->keyname[tabnamelink->size], 0xAu);
		keycol->size = tabnamelink->size + 10;
		keycol->ntab = ntab;
		keycol->length = (*columns)->collen;
		keycol->type = GetColumnType(0, (*columns)->coltype, keycol->length);
		keycol->opt = 4;
		keynode->ntab = ntab;
		keynode->keycol = keycol;
		keynext = keynode;
		++hcursor->nset;
	}
	else
	{
		for (i = 0; i < dbproc->ncols; ++i)
		{
			if (dbproc->columns_info[i]->coltype != SQLTEXT && dbproc->columns_info[i]->coltype != SQLIMAGE)
			{
				keycol = (keycol_t*)AllocateHeapMemory(4, dbproc, 0x1Cu, 1);
				if (!keycol)
				{
					FreeMemory(dbproc, keynode);
					return 0;
				}
				keycol->keyname = (char*)AllocateHeapMemory(4, dbproc, tabnamelink->size + dbproc->columns_info[i]->namlen + 1, 1);
				if (!keycol->keyname)
				{
					FreeMemory(dbproc, keycol);
					FreeMemory(dbproc, keynode);
					return 0;
				}
				dbmove(tabnamelink->data, keycol->keyname, tabnamelink->size - 1);
				keycol->keyname[tabnamelink->size - 1] = '.';
				dbmove(dbproc->columns_info[i], &keycol->keyname[tabnamelink->size], dbproc->columns_info[i]->namlen);
				keycol->size = dbproc->columns_info[i]->namlen + LOWORD(tabnamelink->size) + 1;
				keycol->keyname[keycol->size - 1] = 0;
				keycol->ntab = ntab;
				keycol->opt = 8;
				keycol->length = dbproc->columns_info[i]->collen;
				keycol->type = GetColumnType(0, dbproc->columns_info[i]->coltype, keycol->length);
				if (i)
				{
					next->next = keycol;
				}
				else
				{
					keynode->opt = 2;
					keynode->ntab = ntab;
					keynode->keycol = keycol;
					keynext = keynode;
				}
				next = keycol;
				++hcursor->nset;
			}
		}
	}
	dbnextrow(dbproc);
	return SUCCEED;
}
int __stdcall CursorBuildRowColInfo(DBCURSOR* pcursor)
{
	int SiZ = 0; 
	keynode_t* next0 = 0;
	keycol_t* next1,*next = 0; 
	int l3 = 0; 
	PDBPROCESS dbproc = 0; 
	int l1 = 0; 
	int l2 = 0; 

	dbproc = pcursor->dbproc;
	if (!dbcmd(pcursor->dbproc, pcursor->stmt)
		|| !dbcmd(dbproc, " ")
		|| !dbcmd(dbproc, pcursor->from)
		|| !dbcmd(dbproc, " ")
		|| !dbcmd(dbproc, cursr_false)
		|| dbsqlexec(dbproc) == FAIL
		|| dbresults(dbproc) == FAIL)
	{
		return 0;
	}
	l1 = pcursor->keyid + dbproc->numcols;
	if (pcursor->concuropt == CUR_OPTCC)
		l1 += pcursor->nset;
	pcursor->binds = (col_bind_t**)AllocateHeapMemory(4, dbproc, 4 * l1, 1);
	if (!pcursor->binds)
		return 0;
	pcursor->keyset = (keyset_t*)AllocateHeapMemory(4, dbproc, 12 * dbproc->numcols, 1);
	if (!pcursor->keyset)
		return 0;
	pcursor->ncols = dbproc->numcols;
	pcursor->nrowmax = l1;
	pcursor->columnsinfo = dbproc->columns_info;
	pcursor->columnsdata = dbproc->columns_data;
	dbproc->columns_data = 0;
	dbproc->columns_info = 0;
	dbproc->numcols = 0;
	dbproc->ncols = 0;
	l2 = 135 * (pcursor->keyid - 1);
	l3 = 347 * (pcursor->n_tabs - 1) + 106 * (l1 - 1);
	for (next = pcursor->keycols; next; next = next->next)
		l2 += 3 * (next->length + strlen(next->keyname));
	if (pcursor->concuropt == CUR_OPTCC)
	{
		for (next0 = pcursor->keys; next0; next0 = next0->next)
		{
			for (next1 = next0->keycol; next1; next1 = next1->next)
				l2 += 3 * (next1->length + strlen(next1->keyname));
		}
	}
	pcursor->field_78 = 0;
	if (pcursor->n_tabs == 1 && pcursor->n_total_rows > 1)
	{
		l3 += 2040;
		SiZ = l3 + 2 * l2;
		if (SiZ < 128000)
		{
			pcursor->field_7C = 1;
			pcursor->field_78 = (unsigned __int16)((128000 - SiZ) / (l2 + 322) + 2);
			if (pcursor->field_78 > 50)
			{
				pcursor->field_7C = pcursor->field_78 / 50;
				pcursor->field_78 = 50;
			}
		}
	}
	if (pcursor->field_78 == 0)
	{
		pcursor->field_78 = 1;
		pcursor->field_7C = 128000 / (l2 + l3 + 1067);
	}
	return SUCCEED;
}
int __stdcall CursorBuildRowColInfoServer(DBCURSOR* pcursor, char* stmt)
{ 
	char* pbuf = 0; 
	buf_node_t* next = 0; 
	int bSucc = 0; 
	int scrollopt_ = 0;
	int j = 0; 
	int ccopt = 0;
	buf_node_t* rpcbuffer = 0; 
	PDBPROCESS dbproc = 0; 
	int row_ = 0;
	int cursor_ = 0;
	BYTE* pbyt = 0;

	dbproc = pcursor->dbproc;
	row_ = pcursor->n_total_rows;
	bSucc = 0;
	pbyt = 0;
	switch (pcursor->scrollopt)
	{
	case CUR_INSENSITIVE:
		scrollopt_ = STATIC;
		break;
	case CUR_KEYSET:
		scrollopt_ = KEYSET;
		break;
	case CUR_FORWARD:
		scrollopt_ = FORWARD_ONLY;
		break;
	case CUR_DYNAMIC:
		scrollopt_ = DYNAMIC;
		break;
	default:
		break;
	}
	switch (pcursor->concuropt)
	{
	case CUR_READONLY:
		ccopt = READ_ONLY;
		break;
	case CUR_LOCKCC:
		ccopt = SCROLL_LOCKS;
		break;
	case CUR_OPTCC:
		ccopt = OPTIMISTIC;
		break;
	case CUR_OPTCCVAL:
		ccopt = OPTIMISTIC_VAL;
		break;
	default:
		break;
	}
	if ((dbproc->ret_status & 0x80) != 0)
		rpcbuffer = dbproc->rpcbuffer;
	if (dbrpcinit(dbproc, "sp_cursoropen", 0)
		&& dbrpcparam(dbproc, (char*)"@cursor", 1, SQLINT4, -1, -1, (BYTE*)cursor_)
		&& dbrpcparam(dbproc, (char*)"@stmt", 0, SQLTEXT, -1, strlen(stmt), (BYTE*)stmt)
		&& dbrpcparam(dbproc, (char*)"@scrollopt", 1, SQLINT4, -1, -1, (BYTE*)&scrollopt_)
		&& dbrpcparam(dbproc, (char*)"@ccopt", 0, SQLINT4, -1, -1, (BYTE*)&ccopt)
		&& dbrpcparam(dbproc, (char*)"@rows", 1, SQLINT4, -1, -1, (BYTE*)&row_))
	{
		if ((dbproc->ret_status & 0x80) != 0)
		{
			for (next = dbproc->rpcbuffer; next->next; next = next->next)
				;
			next->next = rpcbuffer;
		}
		if (dbrpcsend(dbproc))
		{
			bSucc = 1;
			if (dbsqlok(dbproc))
			{
				if (dbresults(dbproc) == SUCCEED)
				{
					pbyt = dbretdata(dbproc, 2); // ccopt
					if (pbyt)
					{
						pcursor->ncols = dbproc->numcols;
						pcursor->nrowmax = dbproc->numcols;
						pcursor->columnsinfo = dbproc->columns_info;
						pcursor->columnsdata = dbproc->columns_data;
						switch (*pbyt)
						{
						case 1: // FTC_SUCCEED
							pcursor->scrollopt = CUR_KEYSET;
							break;
						case 2: // CUR_LOCKCC
							pcursor->scrollopt = CUR_DYNAMIC;
							break;
						case 4: // CUR_OPTCCVAL
							pcursor->scrollopt = CUR_FORWARD;
							break;
						case 8:
							pcursor->scrollopt = CUR_INSENSITIVE;
							break;
						default:
							break;
						}
						pcursor->n_key_row = row_;
						pcursor->nfetch_row = -1;
						pcursor->field_98 = 0;
						dbproc->columns_data = 0;
						dbproc->columns_info = 0;
						dbproc->numcols = 0;
						dbproc->ncols = 0;
						if (dbresults(dbproc))
						{
							bSucc = 0;
							if ((!dbretstatus(dbproc) || dbretstatus(dbproc) == 2) && dbnumrets(dbproc) == 3)
							{
								pcursor->n_cursor = *(_DWORD*)dbretdata(dbproc, 1);
								pcursor->n_key_row = *(_DWORD*)dbretdata(dbproc, 3);
								pcursor->binds = (col_bind_t**)AllocateHeapMemory(4, dbproc, 4 * pcursor->nrowmax + 4, 1);
								if (pcursor->binds)
								{
									pcursor->binds[pcursor->nrowmax] = 0;
									pcursor->keyset = (keyset_t*)AllocateHeapMemory(4, dbproc, 12 * pcursor->nrowmax, 1);
									if (pcursor->keyset)
									{
										pcursor->n_tabs = dbproc->ntab;
										if (!dbproc->tabnames)
											return SUCCEED;
										if (!dbproc->tabnames[dbproc->ntab - 1])
											--pcursor->n_tabs;

										char** ppbuf = (char**)AllocateHeapMemory(4, dbproc, 4 * pcursor->n_tabs, 1);
										pcursor->tabname_array = (buf_node_t*)ppbuf;
										if (pcursor->tabname_array)
										{
											for (j = 0; j < pcursor->n_tabs; ++j)
											{
												if (dbproc->tabnames[j])
												{
													pbuf = (char*)AllocateHeapMemory(4, dbproc, strlen(dbproc->tabnames[j]) + 1, 0);
													ppbuf[j] = pbuf;
													if (!pbuf)
														goto LABEL_52;
													strcpy(pbuf, dbproc->tabnames[j]);
												}
												else
												{
													pbuf = (char*)AllocateHeapMemory(4, dbproc, 1u, 0);
													if (!pbuf)
														goto LABEL_52;
													*pbuf = null_string[0];
												}
											}
											return SUCCEED;
										}
									}
								}
							}
						}
					}
				}
			}
		}
	}
LABEL_52:
	if (bSucc)
	{
		if (!dbproc->bclosed)
			dbcancel(dbproc);
	}
	return 0;
}
/*
* stmt - The select statement that defines a cursor.
* 
* scrollopt
* 
* Indicator of the desired scrolling technique.
* 
* Keyset driven fixes membership in the result set and order at cursor open time.
* 
* Dynamic determines membership in the result set and order at fetch time.
* 
* lists the possible values for scrollopt.
* 
* CUR_FORWARD - Forward scrolling only.
* CUR_KEYSET - Keyset driven. A copy of the keyset for the result table is kept locally. Number of rows in result table must be less than or equal to 1000.
* CUR_DYNAMIC - Fully dynamic.
* int n - Keyset-driven cursor within (n*nrows) blocks, but fully dynamic outside the keyset.
* 
* concuropt
* 
* Definition of concurrency control.Table 2 - 12 lists the possible values for concuropt:
* CUR_READONLY  - Read-only cursor. The data cannot be modified.
* CUR_LOCKCC - Intent to update locking.
* CUR_OPTCC  - Optimistic concurrency control, based on timestamp values.
* CUR_OPTCCVAL - Optimistic concurrency based on values.
* 
* nrows -  Number of rows
*/
DBCURSOR* __cdecl dbcursoropen(
	PDBPROCESS dbproc,
	const char* stmt,
	int scrollopt,
	int concuropt,
	int nrows,
	int* pstatus)
{
	int l1 = 0; 
	DBCURSOR* pcursor = 0; 

	char* lpMem = 0; 
	int i = 0; 
	int j = 0; 
	int* pbuf = 0; 
	int* pp = 0; 
	int B1 = 0; 
	int scrollopt_ = scrollopt;

	if (!CheckEntry(dbproc))
		return 0;
	if (!CursorCheckDBversion())
	{
		GeneralError(dbproc, 10096);
		return 0;
	}
	if (!stmt || !*stmt || concuropt > 4 || concuropt < 1 || !nrows || !pstatus || scrollopt < CUR_INSENSITIVE)
		goto LABEL_19;
	B1 = 0;
	if (dbproc->bServerType == 1 && dbproc->ServerMajor >= 5u && !dbisopt(dbproc, 16, 0))
		B1 = UseClientCursors == 0;
	if (!B1 && scrollopt == CUR_INSENSITIVE)
	{
	LABEL_19:
		GeneralError(dbproc, SQLEPARM);
		return 0;
	}
	if (B1 && scrollopt > 1)
		scrollopt_ = -1;
	if (!B1 && (unsigned int)(4 * nrows) > 200000)
	{
		GeneralError(dbproc, 10081);
		return 0;
	}
	*pstatus = 0;
	l1 = strlen(stmt) + 1;

	lpMem = (char*)AllocateHeapMemory(4, dbproc, l1, 0);
	if (!lpMem)
		return 0;
	qmemcpy(lpMem, stmt, l1 - 1);
	lpMem[l1 - 1] = 0;
	if (!B1 && !ScanForInvalidPhrases(dbproc, (char*)stmt))
	{
		FreeOnError(lpMem, 0);
		return 0;
	}
	if (!CursorVerify(0, dbproc))
		return 0;
	pcursor = (DBCURSOR*)AllocateHeapMemory(4, dbproc, 0x9Cu, 1);
	if (!pcursor)
	{
		LeaveCriticalSection(&dbproc->cursorSem);
		FreeOnError(lpMem, 0);
		return 0;
	}

	pcursor->n_cursor = 0;
	pcursor->dbproc = dbproc;
	pcursor->scrollopt = scrollopt;
	pcursor->concuropt = concuropt;
	pcursor->n_total_rows = nrows;
	pcursor->nrows1 = nrows;
	pcursor->pstatus = pstatus;
	pcursor->useclientcursors = B1;
	pcursor->field_88 = 1;
	pcursor->field_8C = 0;
	pcursor->field_90 = 0;

	if (B1)
	{
		pcursor->tabname_array = 0;
		pcursor->n_tabs = 0;
		pcursor->rows_data = (column_data_t**)AllocateHeapMemory(4, dbproc, 4 * pcursor->n_total_rows, 1);
		if (!pcursor->rows_data)
		{
			CursorCleanUp(pcursor, lpMem, 0, 1);
			return 0;
		}
	}
	else
	{
		if (!CursorParseStatement(pcursor, lpMem) || !CursorFindKeys(pcursor) || !CursorBuildKeysetSelect(pcursor))
		{
			CursorCleanUp(pcursor, lpMem, 0, 1);
			return 0;
		}
		if (concuropt == 3)
		{
			for (i = 1; i <= pcursor->n_tabs; ++i)
			{
				if (!CursorBuildOptccSet(pcursor, i))
				{
					CursorCleanUp(pcursor, lpMem, 0, 1);
					return 0;
				}
			}
		}
		if (!CursorBuildKeysetData(pcursor, 1))
		{
			CursorCleanUp(pcursor, lpMem, 0, 1);
			return 0;
		}
		pcursor->rows_data = (column_data_t**)AllocateHeapMemory(4, dbproc, 4 * pcursor->n_total_rows, 1);
		if (!pcursor->rows_data)
		{
			CursorCleanUp(pcursor, lpMem, 0, 1);
			return 0;
		}
	}
	if (!B1 && !CursorBuildRowColInfo(pcursor) || B1 && !CursorBuildRowColInfoServer(pcursor, lpMem))
	{
		CursorCleanUp(pcursor, lpMem, 0, 1);
		return 0;
	}
	if (dbproc->n_cursor)
	{
		for (j = 0; j < dbproc->n_cursor; ++j)
		{
			if (!dbproc->cursors[j])
			{
				dbproc->cursors[j] = pcursor;
				j = -1;
				break;
			}
		}
		if (j == -1)
		{
			LeaveCriticalSection(&dbproc->cursorSem);
			FreeMemory(dbproc, lpMem);
			return pcursor;
		}
		pp = (int*)ReallocMemory(dbproc, dbproc->cursors, 4 * dbproc->n_cursor + 4);
		if (pp)
		{
			dbproc->cursors = (DBCURSOR**)pp;
			pp[dbproc->n_cursor++] = (int)pcursor;
			LeaveCriticalSection(&dbproc->cursorSem);
			FreeMemory(dbproc, lpMem);
			return pcursor;
		}

		CursorCleanUp(pcursor, lpMem, 0, 1);
		return 0;
	}
	pbuf = (int*)AllocateHeapMemory(4, dbproc, 4u, 0);
	if (!pbuf)
	{
		CursorCleanUp(pcursor, lpMem, 0, 1);
		return 0;
	}
	*pbuf = (int)pcursor;
	dbproc->n_cursor = 1;
	dbproc->cursors = (DBCURSOR**)pbuf;
	dbproc->db_close_cursors = dbclosecursors;

	LeaveCriticalSection(&dbproc->cursorSem);
	FreeMemory(dbproc, lpMem);
	return pcursor;
}
int __stdcall CursorBuildKeysetSelect(DBCURSOR* hcursor)
{
	char* p2 = 0; 
	keycol_t* next = 0; 
	int i = 0; 
	int Siz = 0; 
	column_info_t** columns = 0; 
	PDBPROCESS dbproc = 0;
	char* lpMem = 0; 
	char* p1 = 0; 


	dbproc = hcursor->dbproc;
	lpMem = (char*)AllocateHeapMemory(4, hcursor->dbproc, 1024u, 1);
	if (!lpMem)
		return 0;
	dbmove(cursr_select, lpMem, 8u); // "select "
	Siz = 7;
	p1 = lpMem + 7;
	next = hcursor->keycols;
	for (i = 0; i < hcursor->keyid; ++i)
	{
		Siz = Siz + next->size - 1;
		if (Siz > 1024u)
		{
			FreeMemory(dbproc, lpMem);
			return 0;
		}
		for (p2 = next->keyname; p2 < &next->keyname[next->size - 1]; ++p2)
			*p1++ = *p2;
		next = next->next;
		if (next)
		{
			*p1++ = ',';
			*p1++ = ' ';
			Siz += 2;
		}
	}
	*p1 = 0;
	hcursor->select = (char*)AllocateHeapMemory(4, dbproc, Siz + 1, 0);
	if (!hcursor->select
		|| (dbmove(lpMem, hcursor->select, Siz + 1), !dbcmd(dbproc, (char*)hcursor->select))
		|| !dbcmd(dbproc, " ")
		|| !dbcmd(dbproc, hcursor->from)
		|| !dbcmd(dbproc, " ")
		|| !dbcmd(dbproc, cursr_false))
	{

		FreeMemory(dbproc, lpMem);
		return 0;
	}
	if (!dbsqlexec(dbproc) || dbresults(dbproc) == FAIL)
	{
		if (hcursor->n_table_array_size)
			GeneralError(dbproc, 10094);
		FreeMemory(dbproc, lpMem);
		return 0;
	}
	next = hcursor->keycols;
	columns = dbproc->columns_info;
	for (i = 0; i < hcursor->keyid; ++i)
	{
		next->length = columns[i]->collen;
		next->type = GetColumnType(0, columns[i]->coltype, next->length);
		next = next->next;
	}
	dbcancel(dbproc);
	FreeMemory(dbproc, lpMem);
	return SUCCEED;
}

BOOL __stdcall CursorUpdateServerRow(DBCURSOR* hcursor, int rownumber, char* table)
{
	int ColumnType = 0; 
	char* data = 0; 
	int i = 0; 
	char buff[32] = { 0 };
	col_bind_t* binds = 0; 
	column_info_t* columns = 0; 
	size_t Count = 0; 
	keyset_t* node = 0;

	if (table)
		return dbrpcparam(hcursor->dbproc, (char*)"@VALUES", 0, SQLTEXT, strlen(table), strlen(table), (BYTE*)table) != 0;
	for (i = 0; i < hcursor->ncols; ++i)
	{
		columns = hcursor->columnsinfo[i];
		binds = hcursor->binds[i];
		node = &hcursor->keyset[i];
		if ((hcursor->dbproc->ret_status & 0x40) == 0 || binds && ((columns->flags >> 2) & 3) != 0)
		{
			buff[0] = '@';
			dbmove(columns->name, &buff[1], columns->namlen);
			buff[columns->namlen + 1] = 0;
			if (!binds)
				return 0;
			Count = node->lengths ? (size_t)node->lengths[rownumber] : binds->length;
			data = (char*)node->keys[rownumber];
			if (Count && (binds->bind_type == STRINGBIND || binds->bind_type == NTBSTRINGBIND))
				Count = strlen(data);
			ColumnType = GetColumnType(hcursor->dbproc, columns->coltype, columns->collen);
			if (!dbrpcparam(hcursor->dbproc, buff, 0, ColumnType, -1, Count, (BYTE*)data))
				return 0;
		}
	}
	return SUCCEED;
}
void __stdcall CursorKeysetFreeRow(DBCURSOR* hcursor, int nrow)
{
	__int16 nrow1 = 0; 
	column_info_t** columns = 0; 
	int i = 0; 
	column_data_t** column_data = 0; 
	PDBPROCESS dbproc = 0; 

	dbproc = hcursor->dbproc;

	if (hcursor->rows_data[nrow])
	{
		column_data = dbproc->columns_data;
		nrow1 = dbproc->ncols;
		columns = dbproc->columns_info;
		dbproc->columns_data = (column_data_t**)hcursor->rows_data[nrow];
		dbproc->ncols = hcursor->ncols;
		dbproc->columns_info = hcursor->columnsinfo;
		for (i = hcursor->ncols; i < hcursor->nrowmax; ++i)
		{
			if (dbproc->columns_data[i]->data)
				FreeMemory(dbproc, dbproc->columns_data[i]->data);
			FreeMemory(dbproc, dbproc->columns_data[i]);
			dbproc->columns_data[i] = 0;
		}
		if (hcursor->useclientcursors)
			++dbproc->ncols;
		free_rowdata(dbproc, 1);
		if (hcursor->useclientcursors)
			--dbproc->ncols;
		hcursor->rows_data[nrow] = 0;
		dbproc->columns_data = column_data;
		dbproc->ncols = nrow1;
		dbproc->columns_info = columns;
	}

}
int __stdcall CursorKeysetAttachBind(DBCURSOR* hcursor, int nrow, int bbind)
{
	col_bind_t* bind = 0; 
	int i = 0;
	int result = 0; 

	result = 1;
	hcursor->dbproc->binds = hcursor->binds;
	for (i = 0; i < hcursor->ncols; ++i)
	{
		bind = hcursor->dbproc->binds[i];
		if (bind)
		{
			bind->buffer = hcursor->keyset[i].keys[nrow];
			bind->buffer[0] = 0;
		}
		if (bbind)
		{
			if (!BindVar(hcursor->dbproc, i))
				result = 0;
		}
	}
	return result;
}
int __stdcall CursorKeysetStoreRow(DBCURSOR* cursor, int nkey, int nrow)
{
	BYTE* p1 = 0; 
	BOOL B1 = 0; 
	int Size = 0; 
	keyset_t* ks1 = 0; 
	BYTE** pdata = 0; 
	int col = 0; 
	keycol_t* kc = 0; 
	PDBPROCESS dbproc = 0; 
	int result = 0; 
	int* pp = 0; 
	column_data_t** column_data = 0; 

	dbproc = cursor->dbproc;
	result = 1;
	column_data = cursor->dbproc->columns_data;
	B1 = cursor->scrollopt != CUR_DYNAMIC && cursor->scrollopt;
	for (col = 0; col < cursor->ncols; ++col)
	{
		ks1 = &cursor->keyset[col];
		if (ks1->lengths)
			ks1->lengths[nrow] = dbdatlen(dbproc, col + 1);
		if (ks1->flag == CUR_INSENSITIVE)
		{
			pdata = (BYTE**)ks1->keys[nrow];
			*pdata = dbdata(dbproc, col + 1);
		}
	}
	if (!cursor->useclientcursors && !B1)
	{
		col = cursor->ncols + 1;
		for (kc = cursor->keycols; kc; kc = kc->next)
		{
			Size = dbdatlen(dbproc, col);
			pp = (int*)&kc->where_sub[nkey * (kc->length + 4)];
			*pp = Size;
			if (Size)
			{
				p1 = dbdata(dbproc, col);
				dbmove(p1, pp + 1, Size);
			}
			++col;
		}
	}
	if (!cursor->useclientcursors)
		col = cursor->keyid + cursor->ncols;
	cursor->rows_data[nrow] = (column_data_t*)column_data;
	if (!cursor->useclientcursors)
	{
		result = CursorSaveOptccData(cursor, nrow, &column_data[col]);
		if (!result)
			return 0;
		cursor->pstatus[nrow] = 1;
		if (nkey + 1 == cursor->n_key_row)
		{
			if ((cursor->fetchtype & 1) != 0)
			{
				cursor->pstatus[nrow] |= 8u;
				if ((cursor->fetchtype & 2) != 0 && (cursor->scrollopt == -1 || cursor->scrollopt > 1))
				{
					cursor->pstatus[nrow] |= 4;
				}
			}
			if ((cursor->scrollopt == -1 || cursor->scrollopt > 1) && cursor->nkey == (unsigned __int16)(nkey + 1))
				cursor->pstatus[nrow] |= 4u;
		}
	}
	dbproc->columns_data = (column_data_t**)AllocateHeapMemory(4, dbproc, 4 * dbproc->ncols, 1);
	if (dbproc->columns_data)
		dbproc->columns_data = AllocateRowData(dbproc, dbproc->columns_data, dbproc->ncols);
	if (!dbproc->columns_data)
		return 0;
	return result;
}

int __cdecl FetchFromServer_Generic(DBCURSOR* hcursor, __int16 type, int row_from, int rows, __int16 a5)
{
	int i1 = 0; 
	int row1 = 0; 
	DWORD* rData = 0; 
	int fetchtype = 0; 
	int v10 = 0; 
	int status = 0; 
	int nrows = 0; 
	int i = 0; 
	int result = 0; 
	int row_ = 0; 
	column_data_t** lpMem = 0; 

	v10 = 0;

	hcursor->total_rows_fetched = 0;
	if (dbsqlok(hcursor->dbproc))
	{
		status = dbretstatus(hcursor->dbproc);
		if (!status || status == 2)
		{
			if (dbresults(hcursor->dbproc))
			{
				switch (type)
				{
				case 1:
					row_ = row_from;
					nrows = row_from + 1;
					break;
				case 2:
					row_ = 0;
					nrows = hcursor->n_total_rows;
					break;
				case 3:
					hcursor->n_total_rows = rows;
					row_ = 0;
					nrows = hcursor->n_total_rows;
					break;
				}
				for (i = row_; i < nrows; ++i)
				{
					hcursor->pstatus[i] = 0;
					CursorKeysetFreeRow(hcursor, i);
				}
				hcursor->dbproc->ncols = hcursor->nrowmax + 1;
				hcursor->dbproc->numcols = hcursor->nrowmax + 1;
				hcursor->dbproc->columns_info = hcursor->columnsinfo;
				lpMem = (column_data_t**)AllocateHeapMemory(4, hcursor->dbproc, 4 * hcursor->nrowmax + 4, 1);
				if (lpMem)
				{
					hcursor->dbproc->columns_data = lpMem;
					lpMem = AllocateRowData(hcursor->dbproc, lpMem, hcursor->nrowmax + 1);
					if (lpMem)
					{
						i = row_;

						while (i < nrows)
						{
							hcursor->dbproc->binds = hcursor->binds;
							CursorKeysetAttachBind(hcursor, i, 0);
							result = dbnextrow(hcursor->dbproc);
							hcursor->dbproc->binds = 0;
							if (result == NO_MORE_ROWS)
							{
								if ((a5 & 1) != 0 && (hcursor->scrollopt == 1 || !hcursor->scrollopt))
								{
									hcursor->fetchtype = 5;
									if (i)
										hcursor->pstatus[i - 1] = 9;
									else
										*hcursor->pstatus = 8;
								}
								if ((a5 & 1) != 0 && (hcursor->scrollopt == CUR_KEYSET || hcursor->scrollopt == CUR_INSENSITIVE || hcursor->scrollopt == CUR_FORWARD))
								{
									i1 = i ? i - 1 : 0;
									hcursor->pstatus[i1] |= 8u;
									if (hcursor->scrollopt >= CUR_INSENSITIVE)
										hcursor->pstatus[i1] |= 4u;
								}
								dbcancel(hcursor->dbproc);
								free_rowdata(hcursor->dbproc, 1);
								hcursor->dbproc->columns_info = 0;
								return SUCCEED;
							}
							if (result != -1)
								goto LABEL_68;
							hcursor->pstatus[i] = *(_DWORD*)hcursor->dbproc->columns_data[hcursor->nrowmax]->data;
							CursorKeysetStoreRow(hcursor, 0, i);
							++hcursor->total_rows_fetched;
							++i;
						}
						if ((a5 & 4) != 0)
						{
							result = dbnextrow(hcursor->dbproc);
							if (result == MORE_ROWS)
							{
								hcursor->field_8C = 1;
							}
							else
							{
								hcursor->pstatus[hcursor->n_total_rows - 1] = 9;
								hcursor->fetchtype = 5;
							}
						}
						if (dbnextrow(hcursor->dbproc) == NO_MORE_ROWS && dbresults(hcursor->dbproc))
						{
							free_rowdata(hcursor->dbproc, 1);
							hcursor->dbproc->columns_info = 0;
							return SUCCEED;
						}
					}
				}
			}
		}
		else
		{
			fetchtype = INFO;
			dbcancel(hcursor->dbproc);
			if (!dbrpcinit(hcursor->dbproc, "sp_cursorfetch", 2))
				return 0;
			if (!dbrpcparam(hcursor->dbproc, (char*)"@cursor", 0, SQLINT4, -1, -1, (BYTE*)&hcursor->n_cursor))
				return 0;
			if (!dbrpcparam(hcursor->dbproc, (char*)"@fetchtype", 0, SQLINT4, -1, -1, (BYTE*)&fetchtype))
				return 0;
			if (!dbrpcparam(hcursor->dbproc, (char*)"@rownumber", 1, SQLINT4, -1, -1, (BYTE*)row1))
				return 0;
			if (!dbrpcparam(hcursor->dbproc, (char*)"@nrows", 1, SQLINT4, -1, -1, (BYTE*)row1))
				return 0;
			if (!dbrpcsend(hcursor->dbproc))
				return 0;
			if (dbsqlok(hcursor->dbproc))
			{
				status = dbretstatus(hcursor->dbproc);
				if (!status)
				{
					if (dbresults(hcursor->dbproc))
					{
						if (dbretlen(hcursor->dbproc, 1) >= 1)
						{
							rData = (DWORD*)dbretdata(hcursor->dbproc, 1);
							if (rData)
							{
								if (!*rData || *rData == -1)
									GeneralError(hcursor->dbproc, 10086);
							}
						}
					}
				}
			}
		}
	}
LABEL_68:
	dbcancel(hcursor->dbproc);
	free_rowdata(hcursor->dbproc, 1);
	hcursor->dbproc->columns_info = 0;
	return 0;
}
/*
* bufno - rownumber
*/
int __cdecl CursorServer(DBCURSOR* hcursor, int optype, int bufno, LPCSTR table, LPCSTR values)
{
	int result = 0,rownumber = 0; 

	switch (optype)
	{
	case CRS_UPDATE:
		optype = 1;
		break;
	case CRS_DELETE:
		optype = 2;
		break;
	case CRS_INSERT:
		optype = 4;
		break;
	case CRS_REFRESH:
		optype = 8;
		break;
	case CRS_LOCKCC:
		optype = 16;
		break;
	default:
		return 0;
	}
	// 请求定位更新。 此过程对游标的提取缓冲区内的一行或多行执行操作。
	if (!dbrpcinit(hcursor->dbproc, "sp_cursor", 2))
		return 0;
	if (!dbrpcparam(hcursor->dbproc, (char*)"@cursor", 0, SQLINT4, -1, -1, (BYTE*)&hcursor->n_cursor))
		return 0;
	if (!dbrpcparam(hcursor->dbproc, (char*)"@optype", 0, SQLINT4, -1, -1, (BYTE*)&optype))
		return 0;
	if (!dbrpcparam(hcursor->dbproc, (char*)"@rownumber", 0, SQLINT4, -1, -1, (BYTE*)&bufno))
		return 0;
	if (optype == 16 || optype == 8)
		goto LABEL_30;
	if (table)
		result = dbrpcparam(hcursor->dbproc, (char*)"@table", 0, SQLINT4, -1, strlen(table), (BYTE*)table);
	else
		result = dbrpcparam(hcursor->dbproc, (char*)"@table", 0, SQLINT4, -1, 0, 0);
	if (!result)
		return 0;
	if ((optype == 1 || optype == 4)
		&& (bufno ? (rownumber = bufno - 1) : (rownumber = 0), !CursorUpdateServerRow(hcursor, rownumber, (char*)values)))
	{
		dbcancel(hcursor->dbproc);
		return 0;
	}
	else
	{
	LABEL_30:
		if (dbrpcsend(hcursor->dbproc))
		{
			if (optype == 8)
			{
				if (bufno)
					return FetchFromServer_Generic(hcursor, 1, bufno - 1, 0, 2);
				else
					return FetchFromServer_Generic(hcursor, 2, 0, 0, 2);
			}
			else if (dbsqlok(hcursor->dbproc))
			{
				return !dbretstatus(hcursor->dbproc) && dbresults(hcursor->dbproc) != FAIL;
			}
			else
			{
				return 0;
			}
		}
		else
		{
			return 0;
		}
	}
}
int __stdcall unformat_money(char* Src, int length)
{
	int i, j;

	j = 0;
	for (i = 0; i < length; ++i)
	{
		if (Src[i] != ThouSep[0])
			Src[j++] = Src[i];
	}
	return j;
}
char* __stdcall CursorWriteBuf(PDBPROCESS dbproc, int ColumnType, int length, void* Src)
{
	const char* p1 = 0; 
	int lll = 0; 
	int ll = 0; 
	char* p31 = 0; 
	int i = 0; 
	char* p2,* p3, * p4, * p5;
	char Buffer[12] = { 0 };
	char* pbuf = 0; 
	int l2, l3, l4;
	BOOL B3 = 0; 
	int min = 0; 
	int l5, l6; 
	char Destination[52] = { 0 };
	char* pSrc = 0; 
	int B1 = 0; 
	int ColumnPrLength = 0; 
	int B2 = 0; 
	char* Source = 0; 
	BYTE typ = 0; 
	int l1 = 0; 

	typ = SQLVARCHAR;
	B1 = 0;
	B2 = 0;
	ColumnPrLength = GetColumnPrLength(ColumnType, 0, length);
	Source = (char*)AllocateHeapMemory(4, dbproc, ColumnPrLength + 3, 0);
	if (!Source)
		return 0;
	pSrc = Source;
	switch (ColumnType)
	{
	case SQLVARBINARY:
	case SQLBINARY:
		*pSrc = SQLINT1;
		pSrc[1] = SQLOFFSET;
		pSrc += 2;
		break;
	case SQLVARCHAR:
	case SQLCHAR:
	case SQLDATETIM4:
	case SQLDATETIME:
	case SQLDATETIMN:
		*pSrc = typ;
		B1 = 1;
		++pSrc;
		break;
	case SQLMONEY:
	case SQLMONEYN:
	case SQLMONEY4:
		*pSrc = 0x24;
		B2 = 1;
		++pSrc;
		break;
	default:
		break;
	}
	l1 = ConvertToChar2(dbproc, ColumnType, (BYTE*)Src, length, SQLCHAR, pSrc, ColumnPrLength, 0);
	if (l1 == -1)
	{
		FreeMemory(dbproc, Source);
		return 0;
	}
	pSrc[l1] = 0;
	if (ColumnType == SQLDATETIM4 || ColumnType == SQLDATETIME || ColumnType == SQLDATETIMN)
	{
		if (Src)
		{
			B3 = 0;
			l2 = strlen(TimeStrAm);
			l3 = strlen(TimeStrPm);
			ColumnPrLength += 8;
			pbuf = (char*)AllocateHeapMemory(4, dbproc, ColumnPrLength + 3, 0);
			if (pbuf)
			{
				strcpy(pbuf, Source);
				FreeMemory(dbproc, Source);
				Source = pbuf;
				pSrc = pbuf + 1;
				l4 = strlen(pbuf);
				l5 = 10 * *((_DWORD*)Src + 1) / 3u;
				l6 = l5 % 1000;
				l5 /= 1000;
				min = l5 % 60;
				B3 = _stricmp(&pbuf[l4 - l2], TimeStrAm) == 0;
				if (B3)
					ll = l2;
				else
					ll = l3;
				strncpy(Destination, Source, l4 - ll);
				if (B3)
					ll = l2;
				else
					ll = l3;
				Destination[l4 - ll] = 0;
				strcat(Destination, TimeSep);
				_itoa(min, Buffer, 10);
				if (min < 10)
					strcat(Destination, "0");
				strcat(Destination, Buffer);
				strcat(Destination, TimeSep);
				_itoa(l6, Buffer, 10);
				if (l6 >= 10)
				{
					if (l6 >= 100)
					{
					LABEL_27:
						strcat(Destination, Buffer);
						if (B3)
							p5 = TimeStrAm;
						else
							p5 = TimeStrPm;
						strcat(Destination, p5);
						l1 = strlen(Destination) - 1;
						strcpy(Source, Destination);
						goto LABEL_31;
					}
					p1 = "0";
					lll = strlen("0") + 1;
					p4 = &Destination[strlen(Destination) + 1];
				}
				else
				{
					p1 = "00";
					lll = strlen("00") + 1;
					p4 = &Destination[strlen(Destination) + 1];
				}
				qmemcpy(p4 - 1, p1, lll);
				goto LABEL_27;
			}
		}
	}
LABEL_31:
	if (B2)
		l1 = unformat_money(pSrc, l1);
	pSrc += l1;
	if (B1)
	{
		if (ColumnType == SQLCHAR || ColumnType == SQLVARCHAR)
		{
			i = 0;
			for (p2 = Source + 1; p2 < pSrc; ++p2)
			{
				if ((unsigned __int8)*p2 == typ)
					++i;
			}
			if (i)
			{
				pbuf = (char*)AllocateHeapMemory(4, dbproc, pSrc - Source + i + 4, 0);
				if (!pbuf)
					return 0;
				*pbuf = typ;
				p3 = Source + 1;
				p31 = pbuf + 1;
				while (p3 < pSrc)
				{
					*p31 = *p3;
					if ((unsigned __int8)*p31 == typ)
						*++p31 = typ;
					++p3;
					++p31;
				}
				FreeMemory(dbproc, Source);
				Source = pbuf;
				pSrc = p31;
			}
		}
		*pSrc++ = typ;
	}
	*pSrc = 0;
	return Source;
}
int __stdcall CursorGetBoundValue(DBCURSOR* hcursor, int ncol, int nrow)
{
	int ColumnType = 0;
	char* Src = 0; 
	col_bind_t* bind = 0; 
	column_info_t* column = 0;
	keyset_t* keyset = 0; 

	int length = 0; 
	void* lpMem = 0; 

	if (!hcursor->keyset || !hcursor->binds)
		return 0;
	bind = hcursor->binds[ncol];
	keyset = &hcursor->keyset[ncol];
	if (!bind)
	{
		GeneralError(hcursor->dbproc, 10093);
		return 0;
	}
	if (keyset->lengths)
		length = keyset->lengths[nrow];
	else
		length = bind->length;
	Src = keyset->keys[nrow];
	if (length)
	{
		if (length == -1 || bind->bind_type == STRINGBIND || bind->bind_type == NTBSTRINGBIND)
			length = strlen(Src);
		column = hcursor->columnsinfo[ncol];
		ColumnType = GetColumnType(0, column->coltype, column->collen);
		lpMem = (void*)CursorWriteBuf(hcursor->dbproc, ColumnType, length, Src);
		if (!lpMem)
			return 0;
		if (!dbcmd(hcursor->dbproc, (char*)lpMem))
		{
			FreeMemory(hcursor->dbproc, lpMem);
			return 0;
		}
		FreeMemory(hcursor->dbproc, lpMem);
	}
	else if (!dbcmd(hcursor->dbproc, cursr_null))
	{
		return 0;
	}
	return SUCCEED;
}
char* __stdcall CursorFindTablePtr(DBCURSOR* hcursor, int ntab)
{
	buf_node_t* next = 0; 
	int i = 0; 

	next = hcursor->tabname_array;
	if (hcursor->n_table_array_size)
	{
		if (ntab <= 0 && ntab > hcursor->n_table_array_size)
			return 0;
	}
	else
	{
		if (ntab > hcursor->n_tabs)
			return 0;
		for (i = 1; i < ntab; ++i)
			next = next->next;
	}
	return (char*)next->data;
}
int __stdcall CursorFindTableName(DBCURSOR* hcursor, const char* table, char* lpValues)
{
	buf_node_t* tabnames = 0;
	int i = 0; 

	char buffer[32] = { 0 };
	char* p1 = 0; 

	tabnames = hcursor->tabname_array;
	if (hcursor->n_tabs == 1 && hcursor->n_table_array_size <= 1 && (!table || !*table))
		return SUCCEED;
	if (hcursor->n_table_array_size)
	{

		for (i = 1; i <= hcursor->n_table_array_size; ++i)
		{
			if (!strcmp((const char*)hcursor->pp_table_array[i - 1], table))
				return i;
		}
	}
	else
	{
		for (i = 1; i <= hcursor->n_tabs; ++i)
		{
			if (!strcmp((const char*)tabnames->data, table))
				return i;
			tabnames = tabnames->next;
		}
	}
	if (!lpValues)
		return 0;
	while (__mb_cur_max <= 1 ? _pctype[(unsigned __int8)*lpValues] & 8 : _isctype((unsigned __int8)*lpValues, 8))
		++lpValues;
	if (_strnicmp(lpValues, cursr_insert, 7u) && _strnicmp(lpValues, cursr_update, 7u))
		return 0;
	for (p1 = lpValues + 7;
		__mb_cur_max <= 1 ? _pctype[(unsigned __int8)*p1] & 8 : _isctype((unsigned __int8)*p1, 8);
		++p1)
	{
		;
	}
	if (!_strnicmp(p1, cursr_into, 5u))
	{
		for (p1 += 5;
			__mb_cur_max <= 1 ? _pctype[(unsigned __int8)*p1] & 8 : _isctype((unsigned __int8)*p1, 8);
			++p1)
		{
			;
		}
	}
	for (i = 0; i < 30; ++i)
	{
		if (__mb_cur_max <= 1 ? _pctype[(unsigned __int8)p1[i]] & 8 : _isctype((unsigned __int8)p1[i], 8))
			break;
		buffer[i] = p1[i];
	}
	buffer[i] = 0;
	return CursorFindTableName(hcursor, buffer, 0);
}
int __stdcall CursorBuildKeysetWhereSub(DBCURSOR* hcursor, int nrow, int ntab, int b)
{
	int l1 = 0; 
	int bSucc = 0; 
	keynode_t* keys = 0; 
	keycol_t* keycols = 0; 
	PDBPROCESS dbproc = 0; 
	char* lpMem = 0; 
	char* Src = 0; 

	dbproc = hcursor->dbproc;
	keycols = hcursor->keycols;
	bSucc = 1;
	while (1)
	{
		while (keycols)
		{
			if (keycols->ntab == ntab)
			{
				if (bSucc)
				{
					bSucc = 0;
				}
				else if (!dbcmd(dbproc, " and "))
				{
					return 0;
				}
				if (keycols->opt == 4)
				{
					if (!dbcmd(dbproc, cursr_tsequ) || !dbcmd(dbproc, keycols->keyname) || !dbcmd(dbproc, ", "))
						return 0;
				}
				else if (!dbcmd(dbproc, keycols->keyname) || !dbcmd(dbproc, " = "))
				{
					return 0;
				}
				Src = &keycols->where_sub[nrow * (keycols->length + 4)];
				l1 = HIWORD(keycols->where_sub) ? *(_DWORD*)Src : 0;
				if (l1)
				{
					lpMem = CursorWriteBuf(dbproc, keycols->type, l1, Src + 4);
					if (!lpMem)
						return 0;
					if (!dbcmd(dbproc, lpMem))
					{
						FreeMemory(dbproc, lpMem);
						return 0;
					}
					FreeMemory(dbproc, lpMem);
				}
				else if (!dbcmd(dbproc, cursr_null))
				{
					return 0;
				}
				if (keycols->opt == 4 && !dbcmd(dbproc, ")"))
					return 0;
			}
			keycols = keycols->next;
		}
		if (!b)
			break;
		b = 0;
		keys = hcursor->keys;
		if (hcursor->n_table_array_size)
		{
			ntab = 1;
		}
		else
		{
			while (keys && keys->ntab != ntab)
				keys = keys->next;
		}
		if (!keys)
			return 0;
		keycols = keys->keycol;
		nrow -= hcursor->nfetch_row - 1;
	}
	return SUCCEED;
}
int __stdcall CursorBuildKeysetWhere(DBCURSOR* hcursor, int nrow, int n)
{
	int n_table_array_size = 0; 
	int j = 0; 
	int i = 0; 
	PDBPROCESS dbproc = 0; 

	dbproc = hcursor->dbproc;
	if (!dbcmd(hcursor->dbproc, " "))
		return 0;
	if (!dbcmd(dbproc, cursr_where))
		return 0;
	if (!dbcmd(dbproc, " ("))
		return 0;
	for (i = 0; i < n; ++i)
	{
		if (i)
		{
			if (!dbcmd(dbproc, cursr_or))
				return 0;
			if (!dbcmd(dbproc, "("))
				return 0;
		}
		if (hcursor->n_table_array_size)
			n_table_array_size = hcursor->n_table_array_size;
		else
			n_table_array_size = hcursor->n_tabs;
		for (j = 1; j <= n_table_array_size; ++j)
		{
			if (!CursorBuildKeysetWhereSub(hcursor, i + nrow, j, 0))
				return 0;
			if (j != n_table_array_size && !dbcmd(dbproc, " and "))
				return 0;
		}
		if (!dbcmd(dbproc, ")"))
			return 0;
	}
	return SUCCEED;
}
int __stdcall CursorBuildRowdataWhere(DBCURSOR* hcursor, int nrow, int ntab)
{
	int ColumnType = 0; 

	int i = 0; 
	column_info_t** columns = 0; 
	PDBPROCESS dbproc = 0; 
	char Src[32] = { 0 };
	LPVOID pwhere = 0; 
	column_data_t** pprow = 0; 

	dbproc = hcursor->dbproc;
	pprow = (column_data_t**)hcursor->rows_data[nrow];
	columns = hcursor->columnsinfo;
	for (i = 0; i < hcursor->ncols; ++i)
	{
		if (!dbcmd(dbproc, " and "))
			return 0;
		dbmove(columns[i], Src, columns[i]->namlen);
		Src[columns[i]->namlen] = 0;
		if (!dbcmd(dbproc, Src))
			return 0;
		if (pprow[i]->len)
		{
			if (!dbcmd(dbproc, " = "))
				return 0;

			ColumnType = GetColumnType(0, columns[i]->coltype, columns[i]->collen);
			pwhere = CursorWriteBuf(dbproc, ColumnType, pprow[i]->len, pprow[i]->data);
			if (!pwhere)
				return 0;
			if (!dbcmd(dbproc, (char*)pwhere))
			{
				FreeMemory(dbproc, pwhere);
				return 0;
			}
			FreeMemory(dbproc, pwhere);
		}
		else if (!dbcmd(dbproc, cursr_isnul)) // " is NULL "
		{
			return 0;
		}
	}
	return SUCCEED;
}
int __stdcall CursorOptccSelect(DBCURSOR* hcursor, int flag)
{
	keynode_t* kn = 0;
	keycol_t* kc = 0; 
	PDBPROCESS dbproc = 0; 

	dbproc = hcursor->dbproc;
	for (kn = hcursor->keys; kn; kn = kn->next)
	{
		for (kc = kn->keycol; kc; kc = kc->next)
		{
			if (!dbcmd(dbproc, ", ") || !dbcmd(dbproc, kc->keyname))
				return 0;
		}
	}
	return SUCCEED;
}
BOOL __stdcall CursorLoadKeysetSelect(DBCURSOR* hcursor, int nrow, int n)
{
	BOOL flag = 0; 
	PDBPROCESS dbproc = 0; 

	dbproc = hcursor->dbproc;
	flag = hcursor->scrollopt != CUR_DYNAMIC && hcursor->scrollopt;
	if (!dbcmd(dbproc, hcursor->stmt))
		return 0;
	if (!dbcmd(dbproc, ", "))
		return 0;
	if (!dbcmd(dbproc, (char*)hcursor->select + 7))
		return 0;
	if (!dbcmd(dbproc, " "))
		return 0;
	if (hcursor->concuropt == CUR_OPTCC)
	{
		if (!CursorOptccSelect(hcursor, flag))
			return 0;
		if (!dbcmd(dbproc, " "))
			return 0;
	}
	if (dbcmd(dbproc, hcursor->from))
		return CursorBuildKeysetWhere(hcursor, nrow, n) != 0;
	return 0;
}
int __stdcall CursorSingleKeysetFetch(DBCURSOR* cursor, int nkey, int nrow)
{
	PDBPROCESS dbproc = 0; 
	int result = 0; 

	dbproc = cursor->dbproc;
	CursorKeysetFreeRow(cursor, nrow);
	CursorKeysetAttachBind(cursor, nrow, 0);
	result = dbnextrow(dbproc);
	if (result == MORE_ROWS)
	{
		result = CursorKeysetStoreRow(cursor, nkey, nrow);
		if (!result)
		{
			dbproc->binds = 0;
			return 0;
		}
	}
	else if (result == NO_MORE_ROWS)
	{
		cursor->pstatus[nrow] = FTC_MISSING;
		result = CursorSaveOptccData(cursor, nrow, 0);
		if (!result)
		{
			dbproc->binds = 0;
			return 0;
		}
	}
	if (dbnextrow(dbproc) != NO_MORE_ROWS)
		result = 0;
	dbproc->binds = 0;
	return result;
}
int __stdcall CursorFetchFromKeysetRow(DBCURSOR* hcursor, int nrow_sel, int nrow)
{
	PDBPROCESS dbproc = 0;
	int result = 0;

	dbproc = hcursor->dbproc;
	hcursor->dbproc->binds = 0;
	if (!CursorLoadKeysetSelect(hcursor, nrow_sel, 1))
		return 0;
	if (!dbsqlexec(dbproc))
		return 0;
	if (dbresults(dbproc) == FAIL)
		return 0;
	result = CursorSingleKeysetFetch(hcursor, nrow_sel, nrow);
	if (result)
		return result;
	else
		return 0;
}
BOOL __stdcall CursorUpdateRow(DBCURSOR* hcursor, int bufno, int ntab, char* lpValue)
{
	void* pSrc = 0; 
	void* pDst = 0; 
	int bSucc = 0; 
	keynode_t* keys = 0; 
	char buffer[32] = { 0 };
	char* TablePtr = 0; 
	int i = 0; 
	column_info_t* column = 0; 
	keycol_t* kc = 0; 
	PDBPROCESS dbproc = 0; 
	int result = 0; 

	dbproc = hcursor->dbproc;
	if (hcursor->nfetch_row <= 0 || bufno > hcursor->total_rows_fetched)
		return 0;
	if (lpValue && (SearchPhrase(lpValue, cursr_wher, 1) || !SearchPhrase(lpValue, cursr_set, 0)))
	{
		GeneralError(dbproc, SQLEPARM);
		return 0;
	}
	if (!lpValue || !SearchPhrase(lpValue, cursr_update, 0)) 
	{
		if (!dbcmd(dbproc, cursr_update)) // "update "
			return 0;
		TablePtr = CursorFindTablePtr(hcursor, ntab);
		if (!TablePtr)
			return 0;
		if (!dbcmd(dbproc, TablePtr) || !dbcmd(dbproc, " "))
			return 0;
	}
	if (lpValue)
	{
		if (!dbcmd(dbproc, lpValue) || !dbcmd(dbproc, " "))
			return 0;
	}
	else
	{
		if (hcursor->n_tabs != 1 || hcursor->n_table_array_size > 1)
		{
			GeneralError(dbproc, 10092);
			return 0;
		}
		if (!dbcmd(dbproc, cursr_set))
			return 0;
		bSucc = 1;
		for (i = 0; i < hcursor->ncols; ++i)
		{
			if (bSucc)
			{
				bSucc = 0;
			}
			else if (!dbcmd(dbproc, ", "))
			{
				return 0;
			}
			column = hcursor->columnsinfo[i];
			dbmove(column, buffer, column->namlen);
			buffer[column->namlen] = 0;
			if (!dbcmd(dbproc, buffer) || !dbcmd(dbproc, " = "))
				return 0;
			if (!CursorGetBoundValue(hcursor, i, bufno - 1))
				return 0;
		}
	}
	if (hcursor->concuropt == 4)
	{
		if (!dbcmd(dbproc, hcursor->from)
			|| !CursorBuildKeysetWhere(hcursor, hcursor->nfetch_row + bufno - 2, 1)
			|| !CursorBuildRowdataWhere(hcursor, bufno - 1, ntab))
		{
			return 0;
		}
	}
	else if (!dbcmd(dbproc, cursr_where)
		|| !CursorBuildKeysetWhereSub(hcursor, hcursor->nfetch_row + bufno - 2, ntab, hcursor->concuropt == 3))
	{
		return 0;
	}
	if (!dbsqlexec(dbproc))
		return 0;
	while (1)
	{
		result = dbresults(dbproc);
		if (result == NO_MORE_RESULTS)
			break;
		if (!result)
			return 0;
	}
	if (hcursor->concuropt == CUR_OPTCC)
	{
		keys = hcursor->keys;
		if (!hcursor->n_table_array_size)
		{
			while (keys && keys->ntab != ntab)
				keys = keys->next;
		}
		if (!keys)
			return 0;
		for (kc = keys->keycol; kc && (kc->ntab != ntab || (kc->opt & 4) == 0); kc = kc->next)
			;
		if (kc)
		{
			pDst = &kc->where_sub[(bufno - 1) * (kc->length + 4) + 4];
			pSrc = dbtsnewval(dbproc);
			dbmove(pSrc, pDst, 8u);
		}
	}
	if (dbproc->DoneRowCount)
		return CursorFetchFromKeysetRow(hcursor, hcursor->nfetch_row + bufno - 2, bufno - 1) != 0;
	GeneralError(dbproc, 10095);
	return 0;
}
int __stdcall CursorDeleteRow(DBCURSOR* hcursor, int nrow, int ntab)
{
	char* Src = 0; 
	PDBPROCESS dbproc = 0; 
	int result = 0; 

	dbproc = hcursor->dbproc;
	if (hcursor->nfetch_row <= 0 || nrow > hcursor->total_rows_fetched)
		return 0;
	if (!dbcmd(dbproc, cursr_delete))
		return 0;
	Src = CursorFindTablePtr(hcursor, ntab);
	if (!Src)
	{
		GeneralError(dbproc, 10091);
		return 0;
	}
	if (!dbcmd(dbproc, Src) || !dbcmd(dbproc, " "))
		return 0;
	if (hcursor->concuropt == CUR_OPTCCVAL)
	{
		if (!dbcmd(dbproc, hcursor->from)
			|| !CursorBuildKeysetWhere(hcursor, hcursor->nfetch_row + nrow - 2, 1)
			|| !CursorBuildRowdataWhere(hcursor, nrow - 1, ntab))
		{
			return 0;
		}
	}
	else if (!dbcmd(dbproc, cursr_where)
		|| !CursorBuildKeysetWhereSub(hcursor, hcursor->nfetch_row + nrow - 2, ntab, hcursor->concuropt == CUR_OPTCC))
	{
		return 0;
	}
	if (!dbsqlexec(dbproc))
		return 0;
	while (1)
	{
		result = dbresults(dbproc);
		if (result == NO_MORE_RESULTS)
			break;
		if (!result)
			return 0;
	}
	if (dbproc->DoneRowCount)
		return SUCCEED;
	GeneralError(dbproc, 10095);
	return 0;
}
int __stdcall CursorInsertRow(DBCURSOR* hcursor, int nrow, int ntab, char* tabname)
{
	int bSucc = 0; 

	char buffer[32] = { 0 };
	char* TablePtr = 0; 
	int ncol = 0; 
	char* pinsert = 0; 
	char* pvals = 0; 
	char* Src = 0; 
	PDBPROCESS dbproc = 0; 
	int result = 0; 

	dbproc = hcursor->dbproc;
	pinsert = 0;
	pvals = 0;
	ncol = 1;
	if (tabname)
	{
		pinsert = SearchPhrase(tabname, cursr_insert, 0);
		pvals = SearchPhrase(tabname, cursr_values, 1);
	}
	if (!pinsert)
	{
		if (!dbcmd(dbproc, cursr_insert))
			return 0;
		TablePtr = CursorFindTablePtr(hcursor, ntab);
		if (!TablePtr)
		{
			GeneralError(dbproc, 10091);
			return 0;
		}
		if (!dbcmd(dbproc, TablePtr) || !dbcmd(dbproc, " "))
			return 0;
	}
	if (!tabname)
	{
		if (hcursor->n_tabs != 1 || hcursor->n_table_array_size > 1)
		{
			GeneralError(dbproc, 10092);
			return 0;
		}
		if (!dbcmd(dbproc, "("))
			return 0;
		bSucc = 1;
		for (ncol = 0; ncol < hcursor->ncols; ++ncol)
		{
			Src = hcursor->columnsinfo[ncol]->name;
			if (bSucc)
			{
				bSucc = 0;
			}
			else if (!dbcmd(dbproc, ", "))
			{
				return 0;
			}
			dbmove(Src, buffer, hcursor->columnsinfo[ncol]->namlen);
			buffer[hcursor->columnsinfo[ncol]->namlen] = 0;
			if (!dbcmd(dbproc, buffer))
				return 0;
		}
		if (!dbcmd(dbproc, ")"))
			return 0;
	}
	if (!pvals && (!dbcmd(dbproc, cursr_values) || !dbcmd(dbproc, " ")))
		return 0;
	if (tabname)
	{
		if (!dbcmd(dbproc, tabname))
			return 0;
	}
	else
	{
		bSucc = 1;
		if (!dbcmd(dbproc, "("))
			return 0;
		for (ncol = 0; ncol < hcursor->ncols; ++ncol)
		{
			if (bSucc)
			{
				bSucc = 0;
			}
			else if (!dbcmd(dbproc, ", "))
			{
				return 0;
			}
			if (!CursorGetBoundValue(hcursor, ncol, nrow - 1))
				return 0;
		}
		if (!dbcmd(dbproc, ")"))
			return 0;
	}
	if (!dbsqlexec(dbproc))
		return 0;
	while (1)
	{
		result = dbresults(dbproc);
		if (result == NO_MORE_RESULTS)
			break;
		if (!result)
			return 0;
	}
	return SUCCEED;
}
int __stdcall CursorLockKeysetTableRow(DBCURSOR* hcursor, int nrow, int ntab)
{
	char* p0,* p1,* Src;
	keycol_t* kc = 0;
	PDBPROCESS dbproc = 0;
	int result = 0; 

	dbproc = hcursor->dbproc;
	result = 1;
	Src = CursorFindTablePtr(hcursor, ntab);
	if (!Src)
		return 0;
	for (kc = hcursor->keycols; kc && kc->ntab != ntab; kc = kc->next)
		;
	if (!kc)
		return 0;
	if (!dbcmd(dbproc, cursr_update)
		|| !dbcmd(dbproc, Src)
		|| !dbcmd(dbproc, " ")
		|| !dbcmd(dbproc, cursr_set)
		|| !dbcmd(dbproc, kc->keyname)
		|| !dbcmd(dbproc, " = ")
		|| !dbcmd(dbproc, kc->keyname)
		|| !dbcmd(dbproc, " ")
		|| !dbcmd(dbproc, cursr_where)
		|| !CursorBuildKeysetWhereSub(hcursor, nrow, ntab, 0)
		|| dbsqlexec(dbproc) == FAIL
		|| dbresults(dbproc) == FAIL )
	{
		return 0;
	}
	if ((kc->opt & 1) == 0)
	{
		while (kc)
		{
			if (kc->ntab == ntab && (kc->opt & 4) != 0)
			{
				p1 = &kc->where_sub[(nrow + hcursor->nfetch_row - 1) * (kc->length + 4) + 4];
				p0 = (char*)dbtsnewval(dbproc);
				dbmove(p0, p1, 8u);
				return result;
			}
			kc = kc->next;
		}
	}
	return result;
}
int __stdcall CursorKeysetFindRow(DBCURSOR* hcursor, int nkey, int n1, int n2)
{
	int l1 = 0; 
	int l2 = 0; 
	char* p1 = 0; 
	keycol_t* kc = 0; 
	int j = 0; 
	int ncols = 0; 
	int i = 0; 
	PDBPROCESS dbproc = 0; 

	dbproc = hcursor->dbproc;
	ncols = hcursor->ncols + 1;
	for (i = 0; i < n2; ++i)
	{
		kc = hcursor->keycols;
		if (!hcursor->rows_data[i + n1])
		{
			for (j = 0; j < hcursor->keyid; ++j)
			{
				l2 = dbdatlen(dbproc, j + ncols);
				p1 = &kc->where_sub[(i + nkey) * (kc->length + 4)];
				l1 = HIWORD(kc->where_sub) ? *(_DWORD*)p1 : 0;
				if (l1 != l2 || l1 && memcmp(p1 + 4, dbdata(dbproc, j + ncols), l2))
					break;
				kc = kc->next;
			}
			if (j == hcursor->keyid)
				return i;
		}
	}
	return -1;
}
int __stdcall CursorFetchFromKeyset(DBCURSOR* hcursor, int n)
{
	int i2, i1,i,j,i_1; 
	int n1, Row, k, r1, lk1; 
	PDBPROCESS dbproc = 0; 
	int result = 0; 

	dbproc = hcursor->dbproc;
	lk1 = hcursor->nfetch_row - 1;
	n1 = 0;
	if (hcursor->n_key_row)
	{
		if (hcursor->rows_data || (hcursor->rows_data = (column_data_t**)AllocateHeapMemory(4, dbproc, 4 * hcursor->n_total_rows, 1)) != 0)
		{
			dbproc->binds = 0;
			for (i_1 = 0; i_1 < n; ++i_1)
			{
				hcursor->pstatus[i_1] = 0;
				CursorKeysetFreeRow(hcursor, i_1);
			}
			for (i = 0; ; ++i)
			{
				if (i >= n)
					goto LABEL_23;
				if (i + lk1 >= hcursor->n_key_row)
					break;
				if (hcursor->concuropt == 2)
				{
					for (j = 1; j <= hcursor->n_tabs; ++j)
					{
						if (!CursorLockKeysetTableRow(hcursor, i + lk1, j))
							return 0;
					}
				}
			}
			if (i)
				i1 = i - 1;
			else
				i1 = 0;
			hcursor->pstatus[i1] |= 4u;
		LABEL_23:
			while (i)
			{
				j = 0;
				r1 = 0;
				while (j < hcursor->field_7C)
				{
					if (hcursor->field_78 >= i)
						i2 = i;
					else
						i2 = hcursor->field_78;
					if (!CursorLoadKeysetSelect(hcursor, r1 + lk1, i2))
						return 0;
					r1 += i2;
					i -= i2;
					if (!i)
						break;
					++j;
				}
				if (!dbsqlexec(dbproc))
					return 0;
				if (dbresults(dbproc) == FAIL)
					return 0;
				do
				{
					while (dbnextrow(dbproc) == -1)
					{
						Row = CursorKeysetFindRow(hcursor, lk1, n1, r1);
						if (Row < 0)
							return 0;
						if (!CursorKeysetAttachBind(hcursor, Row + n1, 1))
							return 0;
						result = CursorKeysetStoreRow(hcursor, Row + lk1, Row + n1);
						dbproc->binds = 0;
						if (!result)
							return 0;
					}
					result = dbresults(dbproc);
					if (result == FAIL)
						return 0;
				} while (result != 2);
				n1 += r1;
				lk1 += r1;
			}
			for (k = 0; k < n1; ++k)
			{
				if (hcursor->rows_data[k])
					hcursor->total_rows_fetched = (unsigned __int16)(k + 1);
				else
					hcursor->pstatus[k] = 2;
			}
			return SUCCEED;
		}
		else
		{
			return 0;
		}
	}
	else
	{
		hcursor->pstatus[0] = 12;
		return SUCCEED;
	}
}
/*
* bufno 
* Row number in the fetch buffer to which the operation applies
* 
* table
* The table to be inserted, updated, deleted, or locked if the cursor declaration
* contains more than one table. If there is only one table, this parameter is not required.
* 
* values
* String values to be updated and/or inserted.
* Use this parameter only with
* update and insert to specify the new column values (that is, Quantity =
* Quantity + 1). In most cases, you can set this parameter to NULL and the
* new values for each column are taken from the fetch buffer (the program
* variable specified by dbcursorbind). If the select statement includes a
* computation (that is, select 5*5...) and a function (for example, select
* getdate(), convert(), and so on), then updating through the buffer array will
* surely not work
* 
* Return value SUCCEED or FAIL.
*/
int __cdecl dbcursor(PDBCURSOR hcursor, int optype, int bufno, LPCSTR table, LPCSTR values) {


	int result = 0;  
	int Size = 0;  

	int ntab = 0;  

	char* lpMem = 0;  

	lpMem = 0;
	if (!hcursor || hcursor == (DBCURSOR*)-1)
		return 0;

	if (!CursorVerify(hcursor, hcursor->dbproc))
		return 0;
	if (hcursor->useclientcursors)
	{
		if (optype == CRS_UPDATE && !bufno && !values)
		{
			GeneralError(hcursor->dbproc, SQLEPARM);
			LeaveCriticalSection(&hcursor->dbproc->cursorSem);
			return 0;
		}
		result = CursorServer(hcursor, optype, bufno, (char*)table, (char*)values);
		if (result == 1 && (optype == CRS_UPDATE || optype == CRS_DELETE) && !hcursor->dbproc->DoneRowCount)
		{
			GeneralError(hcursor->dbproc, 10095);
			result = 0;
		}
		if (result == 1 && optype == CRS_UPDATE)
		{
			if (values)
				result = CursorServer(hcursor, CRS_REFRESH, bufno, (char*)table, (char*)values);
		}
		LeaveCriticalSection(&hcursor->dbproc->cursorSem);
		return result;
	}
	else
	{
		if (hcursor->dbproc->binds != hcursor->binds)
			free_binds(hcursor->dbproc);
		if ((bufno > hcursor->total_rows_fetched || bufno < 0 || optype != CRS_REFRESH && optype != CRS_INSERT && !bufno) && (optype != CRS_INSERT || bufno != 1))
		{
			GeneralError(hcursor->dbproc, SQLEPARM);
			LeaveCriticalSection(&hcursor->dbproc->cursorSem);
			return 0;
		}
		if (hcursor->concuropt == CUR_READONLY && optype != CRS_REFRESH)
		{
			GeneralError(hcursor->dbproc, 10090);
			LeaveCriticalSection(&hcursor->dbproc->cursorSem);
			return 0;
		}
		if (values && *values && (optype == CRS_UPDATE || optype == CRS_INSERT))
		{
			Size = strlen(values);
			if (Size != 1)
			{
				lpMem = (char*)AllocateHeapMemory(4, hcursor->dbproc, Size, 0);
				if (!lpMem)
				{
					LeaveCriticalSection(&hcursor->dbproc->cursorSem);
					return 0;
				}
				dbmove((void*)values, lpMem, Size);
				lpMem[Size] = 0;
			}
		}
		switch (optype)
		{
		case CRS_UPDATE:
			ntab = CursorFindTableName(hcursor, table, lpMem);
			if (!ntab || (!values || !*values) && hcursor->n_tabs != 1)
			{
				GeneralError(hcursor->dbproc, 10091);
				result = 0;
			}
			result = CursorUpdateRow(hcursor, bufno, ntab, lpMem);
			break;
		case CRS_DELETE:
			ntab = CursorFindTableName(hcursor, table, 0);
			if (!ntab)
			{
				GeneralError(hcursor->dbproc, 10091);
				result = 0;
			}
			result = CursorDeleteRow(hcursor, bufno, ntab);
			break;
		case CRS_INSERT:
			ntab = CursorFindTableName(hcursor, table, lpMem);
			if (!ntab && (!lpMem || !SearchPhrase(lpMem, cursr_insert, 0)))
			{
				GeneralError(hcursor->dbproc, 10091);
				result = 0;
			}
			if ((!values || !*values) && !bufno)
			{
				GeneralError(hcursor->dbproc, SQLEPARM);
				result = 0;
				break;
			}
			result = CursorInsertRow(hcursor, bufno, ntab, lpMem);
			break;
		case CRS_REFRESH:
			if (table && *table)
			{
				GeneralError(hcursor->dbproc, SQLEPARM);
				result = 0;
				break;
			}
			if (bufno)
			{
				if (hcursor->nfetch_row)
				{
					result = CursorFetchFromKeysetRow(hcursor, hcursor->nfetch_row + bufno - 2, bufno - 1);
					if (result == -2)
						result = 1;
				}
				else
				{
					result = 0;
				}
			}
			else
			{
				result = CursorFetchFromKeyset(hcursor, hcursor->total_rows_fetched);
			}
			break;
		case CRS_LOCKCC:
			ntab = CursorFindTableName(hcursor, table, 0);
			if (ntab)
			{
				if (!bufno || hcursor->nfetch_row <= 0)
				{
					GeneralError(hcursor->dbproc, SQLEPARM);
					result = 0;
					break;
				}
				result = CursorLockKeysetTableRow(hcursor, hcursor->nfetch_row + bufno - 2, ntab);
				if (result == 1)
					result = CursorFetchFromKeysetRow(hcursor, hcursor->nfetch_row + bufno - 2, bufno - 1);
			}
			else
			{
				GeneralError(hcursor->dbproc, 10091);
				result = 0;
			}
			break;
		default:
			GeneralError(hcursor->dbproc, SQLEPARM);
			result = 0;
			break;
		}
		if (result)
		{
			LeaveCriticalSection(&hcursor->dbproc->cursorSem);
			if (lpMem)
				FreeMemory(hcursor->dbproc, lpMem);
		}
		else
		{
			CursorCleanUp(hcursor, lpMem, 0, 2);
		}
		return result;
	}
	
}
int __cdecl CloseServerCursor(PDBPROCESS dbproc, DBCURSOR* hcursor)
{
	int bSucc = 0; 
	int result = 0; 
	int cursor = 0; 

	bSucc = 0;
	result = 0;
	if (hcursor)
		cursor = hcursor->n_cursor;
	else
		cursor = -1;
	// 关闭和取消分配游标，并释放所有相关资源;也就是说，它会删除用于支持 KEYSET 或 STATIC 游标的临时表。
	if (dbrpcinit(dbproc, "sp_cursorclose", 0))
	{
		if (dbrpcparam(dbproc, (char*)"@cursor", 0, SQLINT4, -1, -1, (BYTE*)&cursor))
		{
			if (dbrpcsend(dbproc))
			{
				bSucc = 1;
				if (dbsqlok(dbproc))
				{
					if (dbresults(dbproc) == SUCCEED)
						result = 1;
				}
			}
		}
	}
	if (bSucc)
		dbcancel(dbproc);
	return result;
}
int __cdecl dbcursorbind(PDBCURSOR hcursor, int col, int vartype, int varlen, int* poutlen, LPBYTE pvaraddr) {

	int i1 = 0; 
	int l1 = 0; 
	keyset_t* ks1 = 0; 
	PDBPROCESS dbproc = 0; 
	int result = 0; 
	char** lpMem = 0; 
	BYTE* p1 = 0; 
	int ncol = 0; 

	result = 1;
	ncol = col - 1;
	lpMem = 0;
	if (!hcursor || hcursor == (DBCURSOR*)-1)
		return 0;
	if (hcursor->nrowmax && ncol >= hcursor->nrowmax)
		return 0;
	dbproc = hcursor->dbproc;
	if (!CursorVerify(hcursor, hcursor->dbproc))
		return 0;
	if (dbproc->binds != hcursor->binds)
		free_binds(dbproc);
	if (pvaraddr)
	{
		if (ncol < hcursor->ncols)
		{
			ks1 = &hcursor->keyset[ncol];
			if (ks1->keys || (lpMem = (char**)AllocateHeapMemory(4, dbproc, 4 * hcursor->n_total_rows, 1)) != 0)
			{
				if (vartype == -2)
				{
					if (!poutlen)
						result = 0;
					l1 = 4;
					if (result == 1 && hcursor->binds && hcursor->binds[ncol])
					{
						FreeMemory(dbproc, hcursor->binds[ncol]);
						hcursor->binds[ncol] = 0;
					}
				}
				else
				{
					switch (vartype)
					{
					case 1:
					case 6:
						l1 = 1;
						break;
					case 2:
						l1 = 2;
						break;
					case 3:
					case 14:
					case 15:
					case 16:
						l1 = 4;
						break;
					case 4:
					case 5:
					case 10:
					case 11:
					case 12:
					case 13:
						if (varlen > 0 && varlen < 0x10000)
							l1 = varlen;
						else
							result = 0;
						break;
					case 7:
					case 8:
					case 9:
						l1 = 8;
						break;
					case 17:
					case 18:
					case 19:
					case 20:
						l1 = 19;
						break;
					default:
						result = 0;
						break;
					}
					if (result == 1)
					{
						dbproc->numcols = hcursor->ncols;
						dbproc->ncols = hcursor->ncols;
						dbproc->columns_info = hcursor->columnsinfo;
						dbproc->columns_data = hcursor->columnsdata;
						dbproc->binds = hcursor->binds;
						result = dbbind(dbproc, col, vartype, varlen, pvaraddr);
						hcursor->binds = dbproc->binds;
						dbproc->binds = 0;
					}
				}
				if (result == 1)
				{
					ks1->lengths = poutlen;
					ks1->flag = vartype;
					if (lpMem)
						ks1->keys = lpMem;
					i1 = 0;
					p1 = pvaraddr;
					while (i1 < hcursor->n_total_rows)
					{
						ks1->keys[i1] = (char*)p1;
						p1 += l1;
						++i1;
					}
				}
				else if (lpMem)
				{
					FreeMemory(dbproc, lpMem);
				}
				dbproc->numcols = 0;
				dbproc->ncols = 0;
				dbproc->columns_info = 0;
				dbproc->columns_data = 0;
				LeaveCriticalSection(&dbproc->cursorSem);
				return result;
			}
			else
			{
				LeaveCriticalSection(&dbproc->cursorSem);
				return 0;
			}
		}
		else
		{
			GeneralError(dbproc, 10042);
			LeaveCriticalSection(&dbproc->cursorSem);
			return 0;
		}
	}
	else
	{
		if (hcursor->keyset)
		{
			ks1 = &hcursor->keyset[ncol];
			if (ks1->lengths)
				ks1->lengths = 0;
			if (ks1->keys)
			{
				FreeMemory(dbproc, ks1->keys);
				ks1->keys = 0;
			}
			ks1->flag = 0;
			if (hcursor->binds)
			{
				if (hcursor->binds[ncol])
				{
					dbproc->binds = hcursor->binds;
					FreeMemory(dbproc, dbproc->binds[ncol]);
					dbproc->binds[ncol] = 0;
					dbproc->binds = 0;
				}
			}
		}
		LeaveCriticalSection(&dbproc->cursorSem);
		return SUCCEED;
	}

}
int __cdecl dbcursorclose_local(DBCURSOR* cursor, int bClean)
{

	if (!CursorVerify(cursor, cursor->dbproc))
		return 0;
	if (!cursor->useclientcursors || bClean || CloseServerCursor(cursor->dbproc, cursor))
	{
		CursorCleanUp(cursor, 0, 1, 8);
		return SUCCEED;
	}
	else
	{
		LeaveCriticalSection(&cursor->dbproc->cursorSem);
		return 0;
	}
}
/*
* Close the cursor associated with the given handle and release all the data 
* belonging to it.
*/
int __cdecl dbcursorclose(PDBHANDLE dbhandle) {
	int B1 = 0; 
	int B2 = 0; 
	__int16 i = 0;
	PDBPROCESS dbproc = (PDBPROCESS)dbhandle;
	PDBCURSOR hcursor = (PDBCURSOR)dbhandle;
	B2 = 1;
	if (!dbhandle || dbhandle == (PDBHANDLE)-1)
		return 0;
	if (!CheckForValidDbproc(dbproc)) // 不是 PDBPROCESS 就是 游标
		return dbcursorclose_local((PDBCURSOR)dbhandle, 0);
	B1 = 0;
	EnterCriticalSection(&dbproc->cursorSem);
	for (i = 0; !B1 && i < dbproc->n_cursor; ++i)
	{

		if (dbproc->cursors[i] && dbproc->cursors[i]->useclientcursors)
		{
			B1 = 1;
			if (!CloseServerCursor(dbproc, 0))
				B2 = 0;
		}
	}
	for (i = 0; i < dbproc->n_cursor; ++i)
	{
		if (dbproc->cursors[i] && !dbcursorclose_local(dbproc->cursors[i], B1))
			B2 = 0;
	}
	if (B2 == 1 && dbproc->cursors)
	{
		FreeMemory(dbproc, dbproc->cursors);
		dbproc->cursors = 0;
		dbproc->n_cursor = 0;
	}
	LeaveCriticalSection(&dbproc->cursorSem);
	return B2;
}
int __cdecl dbcursorcolinfo(PDBCURSOR hcursor, int column, LPSTR colname, LPINT coltype, int* collen, LPINT usertype) {
	int utype = 0; 
	column_info_t* Src = 0; 
	PDBPROCESS dbproc = 0;

	if (!hcursor || hcursor == (DBCURSOR*)-1 || column <= 0 || column > hcursor->ncols)
		return 0;
	dbproc = hcursor->dbproc;
	if (!CursorVerify(hcursor, hcursor->dbproc))
		return 0;
	Src = hcursor->columnsinfo[column - 1];
	if (colname && colname != (char*)-1)
	{
		if (Src->namlen)
			dbmove(Src, colname, Src->namlen);
		colname[Src->namlen] = 0;
	}
	if (coltype && coltype != (int*)-1)
		*coltype = Src->coltype;
	if (collen && collen != (int*)-1)
		*collen = Src->collen;
	if (usertype && usertype != (int*)-1)
	{
		if (Src->usertype <= 0x64u)
			utype = -1;
		else
			utype = Src->usertype;
		*usertype = utype;
	}
	LeaveCriticalSection(&dbproc->cursorSem);
	return SUCCEED;
}
int __cdecl FetchFromServer(DBCURSOR* hcursor, int fetchtype, int rownumber, int n1, __int16 flag)
{
	int result = 0; 
	int l2 = 0; 
	int i = 0; 
	int l1 = 0; 
	int nrows_ = 0; 
	int fetchtype_ = 0; 
	PDBPROCESS dbproc = 0;

	dbproc = hcursor->dbproc;
	hcursor->field_98 = 1;
	if (flag == 1 && hcursor->nfetch_row >= 0)
	{
		switch (fetchtype)
		{
		case FETCH_FIRST:
			if (hcursor->scrollopt == CUR_DYNAMIC)
				hcursor->fetchtype = 0;
			break;
		case FETCH_NEXT:
			if (hcursor->scrollopt >= -2 && hcursor->total_rows_fetched + hcursor->nfetch_row > hcursor->n_key_row)
			{
				GeneralError(dbproc, 10086);
				for (i = 0; i < hcursor->n_total_rows; ++i)
					hcursor->pstatus[i] = 0;
				return 0;
			}
			if ((hcursor->scrollopt == CUR_DYNAMIC || !hcursor->scrollopt) && hcursor->fetchtype == FETCH_RELATIVE)
			{
				*hcursor->pstatus = 8;
				hcursor->total_rows_fetched = 0;
				return SUCCEED;
			}
			break;
		case FETCH_PREV:
			if (hcursor->scrollopt == 1 && hcursor->nfetch_row == 1)
			{
				memset(hcursor->pstatus, 0, 4 * hcursor->nrows1);
				*hcursor->pstatus = 8;
				return SUCCEED;
			}
			if (hcursor->nfetch_row == 1)
			{
			LABEL_22:
				GeneralError(dbproc, 10086);
				return 0;
			}
			if (hcursor->scrollopt == 1)
				hcursor->fetchtype = 0;
			break;
		case FETCH_RANDOM:
			if (rownumber <= hcursor->n_key_row && rownumber > 0)
				break;
			goto LABEL_22;
		case FETCH_RELATIVE:
			l1 = rownumber + hcursor->nfetch_row;
			if (l1 > 0 && l1 <= hcursor->n_key_row)
				break;
			goto LABEL_22;
		default:
			break;
		}
	}
	if (flag == 1 && (hcursor->scrollopt == CUR_DYNAMIC || !hcursor->scrollopt))
	{
		nrows_ = hcursor->n_total_rows + 1;
		flag |= 4u;
	}
	else if (n1)
	{
		nrows_ = n1;
	}
	else if (flag == 2)
	{
		nrows_ = 0;
	}
	else
	{
		nrows_ = hcursor->n_total_rows;
	}
	switch (fetchtype)
	{
	case FETCH_FIRST:
		fetchtype_ = FIRST;
		break;
	case FETCH_NEXT:
		if ((flag & 1) != 0)
		{
			if (hcursor->nfetch_row == -1)
			{
				fetchtype_ = FIRST;
			}
			else if (hcursor->scrollopt != 1 && hcursor->scrollopt)
			{
				fetchtype_ = NEXT;
			}
			else
			{
				fetchtype_ = _RELATIVE;
				rownumber = hcursor->n_total_rows;
			}
		}
		else
		{
			fetchtype_ = NEXT;
		}
		break;
	case FETCH_PREV:
		if ((flag & 1) != 0 && (hcursor->scrollopt == 1 || !hcursor->scrollopt))
		{
			fetchtype_ = _RELATIVE;
			rownumber = -hcursor->n_total_rows;
		}
		else if (hcursor->nfetch_row == -1)
		{
			fetchtype_ = FIRST;
		}
		else
		{
			fetchtype_ = PREV;
		}
		break;
	case FETCH_RANDOM:
		fetchtype_ = _ABSOLUTE;
		break;
	case FETCH_RELATIVE:
		fetchtype_ = _RELATIVE;
		break;
	case FETCH_LAST:
		fetchtype_ = LAST;
		break;
	case 7:
		fetchtype_ = 0x40; // 不支持值 0x40。
		break;
	case 8:
		fetchtype_ = REFRESH;

		break;
	default:

		return 0;
	}
	// 从数据库中提取由一行或多行组成的缓冲区。 此缓冲区中的行组称为游标的 提取缓冲区。
	if (dbrpcinit(dbproc, "sp_cursorfetch", 2))
	{
		if (dbrpcparam(dbproc, (char*)"@cursor", 0, SQLINT4, -1, -1, (BYTE*)&hcursor->n_cursor))
		{
			if (dbrpcparam(dbproc, (char*)"@fetchtype", 0, SQLINT4, -1, -1, (BYTE*)&fetchtype_))
			{
				if (dbrpcparam(dbproc, (char*)"@rownumber", 0, SQLINT4, -1, -1, (BYTE*)&rownumber))
				{
					if (dbrpcparam(dbproc, (char*)"@nrows", 0, SQLINT4, -1, -1, (BYTE*)&nrows_))
					{
						if (dbrpcsend(dbproc))
						{
							if ((flag & 4) != 0)
								result = FetchFromServer_Generic(hcursor, 3, 0, nrows_ - 1, flag);
							else
								result = FetchFromServer_Generic(hcursor, 3, 0, nrows_, flag);
							if (result == 1 && (flag & 1) == 0)
								hcursor->nfetch_row = 0;
							if (result == 1 && (flag & 1) != 0)
							{
								switch (fetchtype)
								{
								case FETCH_FIRST:
									hcursor->nfetch_row = 1;
									break;
								case FETCH_NEXT:
									if (hcursor->nfetch_row == -1)
									{
										hcursor->nfetch_row = 1;
									}
									else if (hcursor->scrollopt == CUR_DYNAMIC)
									{
										hcursor->nfetch_row += hcursor->total_rows_fetched;
									}
									else
									{
										hcursor->nfetch_row += hcursor->n_total_rows;
									}
									break;
								case FETCH_PREV:
									if (hcursor->nfetch_row <= hcursor->n_total_rows)
										hcursor->nfetch_row = 1;
									else
										hcursor->nfetch_row -= hcursor->n_total_rows;
									break;
								case FETCH_RANDOM:
									hcursor->nfetch_row = rownumber;
									break;
								case FETCH_RELATIVE:
									hcursor->nfetch_row += rownumber;
									break;
								case FETCH_LAST:
									if (hcursor->n_key_row > hcursor->n_total_rows)
										hcursor->nfetch_row = hcursor->n_key_row - hcursor->n_total_rows + 1;
									else
										hcursor->nfetch_row = 1;
									break;
								default:
									break;
								}
								if ((flag & 4) != 0)
									l2 = nrows_ - 1;
								else
									l2 = nrows_;
								if (hcursor->nfetch_row + l2 - 1 == hcursor->n_key_row)
								{
									hcursor->pstatus[l2 - 1] |= 0xC;
								}
							}
							if (result == 1 && !hcursor->field_90)
								hcursor->field_90 = 1;

						}
						else
						{
							result = 0;
						}
					}
					else
					{
						result = 0;
					}
				}
				else
				{
					result = 0;
				}
			}
			else
			{
				result = 0;
			}
		}
		else
		{
			result = 0;
		}
	}
	else
	{
		result = 0;
	}
	return result;
}
int __stdcall CursorDynamicFetchSub(DBCURSOR* cursor, int fetchtype)
{

	BYTE* p1 = 0; 
	int Size = 0; 
	col_bind_t* bd1 = 0; 
	BYTE** ppdata = 0; 
	int col, j, L; 

	keynode_t* n = 0; 
	int i, r1; 

	buf_node_t* next = 0;
	keycol_t* kc = 0; 
	keycol_t* m = 0; 
	keycol_t* ii = 0; 
	column_info_t** columns = 0; 
	keyset_t* ks1 = 0; 
	PDBPROCESS dbproc = 0; 
	int result = 0; 
	int* Src = 0; 
	column_data_t** column_data = 0; 
	column_data_t* rd1 = 0; 


	dbproc = cursor->dbproc;
	i = 0;

	cursor->fetchtype &= 0xFC;
	while (i < cursor->n_total_rows)
		cursor->pstatus[i++] = 0;
	if (!cursor->rows_data)
	{
		cursor->rows_data = (column_data_t**)AllocateHeapMemory(4, dbproc, 4 * cursor->n_total_rows, 1);
		if (!cursor->rows_data)
			return 0;
	}
	if (!dbcmd(dbproc, cursor->stmt)
		|| !dbcmd(dbproc, ", ")
		|| !dbcmd(dbproc, (char*)cursor->select + 7)
		|| !dbcmd(dbproc, " "))
	{
		return 0;
	}
	if (cursor->concuropt == CUR_OPTCC && (!CursorOptccSelect(cursor, 0) || !dbcmd(dbproc, " ")))
		return 0;
	if (cursor->concuropt == CUR_LOCKCC)
	{
		if (!dbcmd(dbproc, cursr_from))
			return 0;
		for (next = cursor->tabname_array; next; next = next->next)
		{
			if (!dbcmd(dbproc, (char*)next->data) || !dbcmd(dbproc, cursr_holdl)) // " HOLDLOCK "
				return 0;
			if (next->next && !dbcmd(dbproc, ", "))
				return 0;
		}
	}
	else if (!dbcmd(dbproc, cursor->from) || !dbcmd(dbproc, " "))
	{
		return 0;
	}
	if (cursor->p_where)
	{
		if (!dbcmd(dbproc, cursor->p_where))
			return 0;
		if (fetchtype != 1 && !dbcmd(dbproc, " and  ("))
			return 0;
	}
	else if (fetchtype != 1 && !dbcmd(dbproc, cursr_where))
	{
		return 0;
	}
	if (!CursorBuildDynamicWhere(cursor, fetchtype))
		return 0;
	if (fetchtype != 1 && cursor->p_where && !dbcmd(dbproc, " ) "))
		return 0;
	if (!dbcmd(dbproc, " ") || !CursorOrderbyKeyset(cursor, fetchtype))
		return 0;
	if (!dbsqlexec(dbproc) || dbresults(dbproc) == FAIL)
		return 0;
	for (i = 0; i < cursor->n_total_rows; ++i)
	{
		r1 = fetchtype == 3 ? cursor->n_total_rows - (unsigned __int16)i - 1 : i;
		dbproc->binds = cursor->binds;
		for (col = 0; col < cursor->ncols; ++col)
		{
			bd1 = dbproc->binds[col];
			if (bd1)
				bd1->buffer = cursor->keyset[col].keys[r1];
		}
		result = dbnextrow(dbproc);
		if (result != MORE_ROWS)
			break;
		if (!i)
		{
			dbproc->binds = 0;
			column_data = dbproc->columns_data;
			dbproc->columns_data = 0;
			columns = dbproc->columns_info;
			CursorFreeRowdata(cursor);
			dbproc->columns_data = column_data;
			dbproc->binds = cursor->binds;
			dbproc->columns_info = columns;
			dbproc->ncols = cursor->nrowmax;
		}
		rd1 = (column_data_t*)dbproc->columns_data;
		for (j = 0; j < cursor->ncols; ++j)
		{
			ks1 = &cursor->keyset[j];
			if (ks1->lengths)
				ks1->lengths[r1] = dbdatlen(dbproc, j + 1);
			if (ks1->flag == -2)
			{
				ppdata = (BYTE**)ks1->keys[r1];
				*ppdata = dbdata(dbproc, j + 1);
			}
		}
		cursor->pstatus[r1] = 1;
		L = cursor->ncols + 1;
		for (kc = cursor->keycols; kc; kc = kc->next)
		{
			Size = dbdatlen(dbproc, L);
			Src = (int*)&kc->where_sub[r1 * (kc->length + 4)];
			*Src = Size;
			if (Size)
			{
				p1 = dbdata(dbproc, L);
				dbmove(p1, Src + 1, Size);
			}
			++L;
		}
		cursor->rows_data[r1] = rd1;
		dbproc->columns_data = 0;
		if (!CursorSaveOptccData(cursor, r1, (column_data_t**)&rd1->len + cursor->keyid + cursor->ncols))
			return 0;
		dbproc->columns_data = (column_data_t**)AllocateHeapMemory(4, dbproc, 4 * cursor->nrowmax, 1);
		if (!dbproc->columns_data)
			return 0;

		for (j = 0; j < cursor->nrowmax; ++j)
		{
			dbproc->columns_data[j] = (column_data_t*)AllocateHeapMemory(4, dbproc, 8 * cursor->nrowmax, 1);
			if (!dbproc->columns_data[j])
				return 0;
		}
	}
	dbproc->binds = 0;
	cursor->nfetch_row = 1;
	if (i)
	{
		cursor->n_key_row = (unsigned __int16)i;
		cursor->total_rows_fetched = (unsigned __int16)i;
	}
	if (result)
	{
		if (result == NO_MORE_ROWS && !i && fetchtype == 1)
		{
			GeneralError(dbproc, 10083);
			*cursor->pstatus = 8;
			return 2;
		}
		if (i && i < cursor->n_total_rows && fetchtype == 3)
		{
			for (m = cursor->keycols; m; m = m->next)
				dbmove(&m->where_sub[(cursor->n_total_rows - i) * (m->length + 4)], m->where_sub, i * (m->length + 4));
			if (cursor->keys)
			{
				for (n = cursor->keys; n; n = n->next)
				{
					for (ii = n->keycol; ii; ii = ii->next)
						dbmove(&ii->where_sub[(cursor->n_total_rows - i) * (ii->length + 4)], ii->where_sub, (i - 1) * (ii->length + 4));
				}
			}
			for (j = 0; j < i; ++j)
			{
				if (!CursorFetchFromKeysetRow(cursor, j, j))
				{
					cursor->total_rows_fetched = (unsigned __int16)j;
					cursor->n_key_row = (unsigned __int16)j;
					break;
				}
			}
			cursor->pstatus[i] |= 8u;
			while (j < cursor->n_total_rows)
				cursor->pstatus[j++] = 0;
		}
		else if (i < cursor->n_total_rows || dbnextrow(dbproc) == -2)
		{
			cursor->fetchtype |= 1;
			if (fetchtype == 1)
			{
				cursor->fetchtype |= 2;
			}
			if (i)
			{
				cursor->pstatus[i - 1] |= 8;
			}
			else
			{
				*cursor->pstatus |= 8u;
			}
		}
		result = 1;
	}
	else
	{
		cursor->nfetch_row = 0;
		cursor->total_rows_fetched = 0;
		cursor->n_key_row = 0;
	}
	do
		result = dbnextrow(dbproc);
	while (result != NO_MORE_ROWS && result);
	return result;
}
int __stdcall CursorDynamicFetch(DBCURSOR* hcursor, int fetchtype)
{
	int result = 0; 
	int Value = 0; 
	int Sub = 0; 
	int i,j = 0; 
	int nrows = 0; 
	int status = 0; 

	status = 1;
	if (fetchtype == 3)
		nrows = hcursor->n_total_rows;
	else
		nrows = hcursor->n_total_rows + 1;
	if (!CursorChangeRowcount(hcursor, nrows))
		return 0;
	Sub = CursorDynamicFetchSub(hcursor, fetchtype);
	if (Sub == 1)
	{
		if (hcursor->concuropt == CUR_LOCKCC)
		{
			i = 0;
			do
			{
				if (i >= hcursor->n_total_rows || (hcursor->pstatus[i] & 1) == 0)
					break;
				status = 1;
				for (j = 1; j <= (int)(unsigned __int16)hcursor->n_tabs; ++j)
				{
					if (!CursorLockKeysetTableRow(hcursor, i, j))
					{
						status = 0;
						break;
					}
				}
				if (status == 1)
				{
					status = CursorFetchFromKeysetRow(hcursor, i, i);
					if (status == 1)
						++i;
				}
			} while (status == 1);
			if (i)
				hcursor->total_rows_fetched = i;
			if (status != 1)
				status = 0;
		}
	}
	else if (Sub == 2)
	{
		status = 2;
	}
	else
	{
		status = 0;
	}
	if (hcursor->rowcount)
	{
		Value = atoi(hcursor->rowcount);
		result = CursorChangeRowcount(hcursor, Value);
	}
	else
	{
		result = CursorChangeRowcount(hcursor, 0);
	}
	if (result)
		return status;
	else
		return 0;
}
int __cdecl dbcursorfetch(PDBCURSOR hcursor, int fetchtype, int rownum) {
	int result = 0; 
	int i, j; 
	int nrows = 0; 
	PDBPROCESS dbproc = 0; 
	int l1, l2, l3; 
	int nfetch_row_ = 0; 

	if (!hcursor || hcursor == (DBCURSOR*)-1)
		return 0;

	if (hcursor->field_88 == 1)
	{
		hcursor->field_88 = 2;
	}
	else if (hcursor->field_88 == 3)
	{
		return 0;
	}
	dbproc = hcursor->dbproc;
	switch (fetchtype)
	{
	case FETCH_FIRST:
	case FETCH_NEXT:
		break;
	case FETCH_PREV:
		if (hcursor->scrollopt == 0)
		{
			GeneralError(dbproc, 10087);
			return 0;
		}
		break;
	case FETCH_RANDOM:
	case FETCH_RELATIVE:
		if (hcursor->scrollopt && hcursor->scrollopt != CUR_DYNAMIC)
			break;
		GeneralError(dbproc, 10088);
		return 0;
	case FETCH_LAST:
		if (hcursor->scrollopt == CUR_DYNAMIC
			|| !hcursor->scrollopt
			|| hcursor->scrollopt != CUR_KEYSET && hcursor->scrollopt != CUR_INSENSITIVE && (hcursor->fetchtype & 2) == 0)
		{
			GeneralError(dbproc, 10089);
			return 0;
		}

		break;
	default:
		return 0;
	}

	if (hcursor->useclientcursors)
	{
		hcursor->total_rows_fetched = 0;
		if (hcursor->n_cursor && CursorVerify(hcursor, dbproc))
		{
			result = FetchFromServer(hcursor, fetchtype, rownum, 0, 1);
			LeaveCriticalSection(&dbproc->cursorSem);
		}
		else
		{
			result = 0;
		}
	}
	else
	{
		if (!CursorVerify(hcursor, dbproc))
			return 0;
		if (dbproc->binds != hcursor->binds)
			free_binds(dbproc);
		if (!hcursor->nfetch_row && fetchtype == FETCH_PREV)
		{
			GeneralError(dbproc, 10086);
			LeaveCriticalSection(&dbproc->cursorSem);
			return 0;
		}
		if (hcursor->scrollopt != 1 && hcursor->scrollopt)
		{
			nfetch_row_ = hcursor->nfetch_row;
			nrows = hcursor->n_total_rows;
			switch (fetchtype)
			{
			case FETCH_FIRST:
				hcursor->nfetch_row = 1;
				if (hcursor->field_4C != 1 && !CursorBuildKeysetData(hcursor, 1))
					return CursorCleanUp(hcursor, 0, 0, 4);
				break;
			case FETCH_NEXT:
				l1 = hcursor->total_rows_fetched + hcursor->nfetch_row;
				if (!l1)
					l1 = 1;
				if ((hcursor->fetchtype & 1) != 0
					&& (unsigned __int16)(LOWORD(hcursor->total_rows_fetched) + LOWORD(hcursor->nfetch_row)) > hcursor->n_key_row)
				{
					GeneralError(dbproc, 10086);
					for (i = 0; i < hcursor->n_total_rows; ++i)
						hcursor->pstatus[i] = 0;
					LeaveCriticalSection(&dbproc->cursorSem);
					return 0;
				}
				if (l1 <= hcursor->n_key_row)
				{
					hcursor->nfetch_row = (unsigned __int16)l1;
					break;
				}
				result = CursorBuildKeysetData(hcursor, 0);
				if (!result)
					return CursorCleanUp(hcursor, 0, 0, 4);
				if (result != -2)
				{
					hcursor->nfetch_row = 1;
					break;
				}
				*hcursor->pstatus = 8;
				for (j = 1; j < hcursor->n_total_rows; ++j)
					hcursor->pstatus[j] = 0;
				break;
			case FETCH_PREV:
				if (hcursor->nfetch_row == 1)
				{
					if (hcursor->field_4C > 1)
						GeneralError(dbproc, 10082);
					else
						GeneralError(dbproc, 10086);

					LeaveCriticalSection(&dbproc->cursorSem);
					return 0;
				}
				if (hcursor->nfetch_row <= hcursor->n_total_rows)
					hcursor->nfetch_row = 1;
				else
					hcursor->nfetch_row -= hcursor->n_total_rows;
				break;
			case FETCH_RANDOM:
				if (rownum > hcursor->n_key_row || rownum <= 0)
				{
					GeneralError(dbproc, 10086);
					LeaveCriticalSection(&dbproc->cursorSem);
					return 0;
				}
				hcursor->nfetch_row = rownum;
				break;
			case FETCH_RELATIVE:
				l2 = rownum + hcursor->nfetch_row;
				if (!l2 || l2 > hcursor->n_key_row)
				{
					GeneralError(dbproc, 10086);
					LeaveCriticalSection(&dbproc->cursorSem);
					return 0;
				}
				hcursor->nfetch_row = l2;
				break;
			case FETCH_LAST:
				if (hcursor->n_key_row <= hcursor->n_total_rows)
					l3 = 1;
				else
					l3 = hcursor->n_key_row - hcursor->n_total_rows + 1;
				hcursor->nfetch_row = l3;
				break;
			default:
				break;
			}

			if (!CursorFetchFromKeyset(hcursor, nrows))
			{
				hcursor->nfetch_row = hcursor->nfetch_row;
				dbprocerrhandle_super(dbproc, 0, 2);
				CursorCleanUp(hcursor, 0, 0, 4);
				dbprocerrhandle_super(dbproc, 0, 4);
				return 0;
			}
		}
		else
		{
			if (fetchtype == 2 && !hcursor->n_key_row)
				fetchtype = 1;
			result = CursorDynamicFetch(hcursor, fetchtype);
			if (!result)
				return CursorCleanUp(hcursor, 0, 0, 4);
			if (result == 2)
			{
				CursorCleanUp(hcursor, 0, 1, 4);
				return SUCCEED;
			}
			if (fetchtype == 1)
				hcursor->nfetch_row = 1;
		}
		LeaveCriticalSection(&dbproc->cursorSem);
		result = 1;
	}
	return result;
	
}
int __cdecl dbcursorfetchex(PDBCURSOR hcursor, int fetchtype, int rownum,  int rows, int) {

	PDBPROCESS dbproc = 0; 
	int result = 0; 

	if (!hcursor || hcursor == (DBCURSOR*)-1)
		return 0;
	dbproc = hcursor->dbproc;
	if (rows < 0)
	{
		GeneralError(hcursor->dbproc, SQLEPARM);
		return 0;
	}
	if (!hcursor->useclientcursors)
		return 0;
	if (rows > hcursor->nrows1)
		return 0;
	if (!hcursor->n_cursor || !CursorVerify(hcursor, hcursor->dbproc))
		return 0;
	hcursor->total_rows_fetched = 0;

	if (hcursor->field_88 == 1)
	{
		hcursor->field_88 = 3;
	}
	else if (hcursor->field_88 == 2)
	{
		LeaveCriticalSection(&dbproc->cursorSem);
		return 0;
	}
	result = FetchFromServer(hcursor, fetchtype, rownum, rows, 2);
	LeaveCriticalSection(&dbproc->cursorSem);
	return result;
}
int __cdecl dbcursorinfo(PDBCURSOR hcursor, int* ncols, int* nrows) {
	PDBPROCESS dbproc = 0; 

	if (!hcursor || hcursor == (DBCURSOR*)-1 || !nrows || !ncols)
		return 0;
	dbproc = hcursor->dbproc;
	if (!CursorVerify(hcursor, hcursor->dbproc))
		return 0;
	*ncols = hcursor->ncols;
	*nrows = -1;
	if (!hcursor->useclientcursors && (hcursor->fetchtype & 3) != 0
		|| hcursor->useclientcursors && hcursor->scrollopt == CUR_KEYSET
		|| hcursor->useclientcursors && hcursor->scrollopt == CUR_INSENSITIVE)
	{
		*nrows = hcursor->n_key_row;
	}
	else if (hcursor->useclientcursors 
		&& hcursor->field_88 == 2 
		&& hcursor->scrollopt == CUR_DYNAMIC 
		&& hcursor->fetchtype == FETCH_RELATIVE)
	{
		*nrows = hcursor->total_rows_fetched;
	}
	LeaveCriticalSection(&dbproc->cursorSem);
	return SUCCEED;
}

int __cdecl GetDynamicServerInfo(DBCURSOR* hcursor, int* nrows, int* rownumber)
{
	PDBPROCESS dbproc = 0; 
	int fetchtype = 0; 

	dbproc = hcursor->dbproc;
	fetchtype = PREV_NOADJUST;
	*nrows = -1;
	*rownumber = -1;
	/*
	* 从数据库中提取由一行或多行组成的缓冲区。 此缓冲区中的行组称为游标的 提取缓冲区。
	* sp_cursorfetch
	* fetchtype 值 REFRESH 和 INFO 将忽略此参数。
	* 对于 NEXT、PREV、ABSOLUTE、RELATIVE 和 PREV_NOADJUST 的 fetchtype 值， nrow 值为 0 无效
	* 
	* 返回代码值
	* 0
	*/
	if (!dbrpcinit(dbproc, "sp_cursorfetch", 2))
		return 0;
	if (!dbrpcparam(dbproc, (char*)"@cursor", 0, SQLINT4, -1, -1, (BYTE*)&hcursor->n_cursor))
		return 0;
	if (!dbrpcparam(dbproc, (char*)"@fetchtype", 0, SQLINT4, -1, -1, (BYTE*)&fetchtype))
		return 0;
	if (!dbrpcparam(dbproc, (char*)"@rownumber", 1, SQLINT4, -1, -1, (BYTE*)rownumber))
		return 0;
	if (!dbrpcparam(dbproc, (char*)"@nrows", 1, SQLINT4, -1, -1, (BYTE*)nrows))
		return 0;
	if (!dbrpcsend(dbproc))
		return 0;
	if (dbsqlok(dbproc))
	{
		if (dbresults(dbproc))
		{
			if (!dbretstatus(dbproc))
			{
				*rownumber = *(int*)dbretdata(dbproc, 1);
				*nrows = *(int*)dbretdata(dbproc, 2);
				if (dbresults(dbproc))
					return SUCCEED;
			}
		}
	}
	dbcancel(dbproc);
	return 0;
}
int __cdecl dbcursorinfoex(PDBCURSOR hcursor, LPDBCURSORINFO cursorinfo) {

	DBINT ncols = 0;
	DBINT nrows = 0;
	int nrows_ = 0;
	int rownumber_ = 0;
	int bSucc = 0; 

	bSucc = 0;
	if (!cursorinfo)
		return 0;
	if (cursorinfo->SizeOfStruct != 28)
		return 0;
	if (!dbcursorinfo(hcursor, &ncols, &nrows))
		return 0;
	cursorinfo->TotCols = ncols;
	cursorinfo->TotRows = nrows;
	cursorinfo->TotRowsFetched = hcursor->total_rows_fetched;
	cursorinfo->Type = 0;
	cursorinfo->Type |= (hcursor->useclientcursors != 0) + 1;
	switch (hcursor->scrollopt)
	{
	case CUR_INSENSITIVE:
		cursorinfo->Type |= 0x40u;
		break;
	case CUR_KEYSET:
		cursorinfo->Type |= 4u;
		break;
	case CUR_FORWARD:
		cursorinfo->Type |= 0x20u;
		break;
	case CUR_DYNAMIC:
		cursorinfo->Type |= 0x10u;
		break;
	default:
		cursorinfo->Type |= 8u;
		break;
	}
	switch (hcursor->concuropt)
	{
	case CUR_READONLY:
		cursorinfo->Type |= 0x80;
		break;
	case CUR_LOCKCC:
		cursorinfo->Type |= 1;
		break;
	case CUR_OPTCC:
		cursorinfo->Type |= 2;
		break;
	case CUR_OPTCCVAL:
		cursorinfo->Type |= 4;
		break;
	default:
		break;
	}
	if (hcursor->useclientcursors && hcursor->scrollopt != 1 && hcursor->scrollopt && hcursor->n_key_row == -1)
	{
		bSucc = 1;
		if (!GetDynamicServerInfo(hcursor, &nrows_, &rownumber_))
			return 0;
		if (nrows_ == -1)
			cursorinfo->Status = 1;
		else
			cursorinfo->Status = 2;
	}
	else
	{
		cursorinfo->Status = 2;
	}
	if (hcursor->useclientcursors && hcursor->field_98)
	{
		if (bSucc)
		{
			cursorinfo->CurRow = rownumber_;
		}
		else
		{
			if (!GetDynamicServerInfo(hcursor, &nrows_, &rownumber_))
				return 0;
			cursorinfo->CurRow = rownumber_;
		}
	}
	else
	{
		cursorinfo->CurRow = 1;
	}
	hcursor->field_98 = 1;
	return SUCCEED;
}

BYTE* __cdecl dbgetuserdata(PDBPROCESS dbproc)
{
	if (!CheckEntrySkipDead(dbproc))
		return 0;
	if (dbproc && dbproc->CommLayer && dbproc->CommLayer->userdata)
		return (BYTE*)dbproc->CommLayer->userdata;
	return 0;
}
void __cdecl dbsetuserdata(PDBPROCESS dbproc, BYTE* ptr)
{
	int result = 0; 

	result = CheckEntry(dbproc);
	if (result)
	{
		dbproc->CommLayer->userdata = ptr;
	}

}
void __stdcall ffputs(const char* Src)
{
	int Character = 0;

	while (*Src)
	{
		Character = *Src++;
		putchar(Character);
	}
	fflush(stdout);
	fflush(stdin);

}
void linebreak(PDBPROCESS dbproc, const char* Src)
{
	char buffer[256] = { 0 };
	int ColumnPrLength = 0; 
	int i = 0; 
	column_info_t** columns = 0; 
	int B1 = 0; 
	int l1 = 0; 
	int j = 0; 

	B1 = 1;
	columns = dbproc->columns_info;
	l1 = 0;
	ffputs(" ");
	for (i = 0; i < dbproc->ncols; ++i)
	{
		if ((columns[i]->type & 0x10) == 0)
		{
			ColumnPrLength = GetColumnPrLength(columns[i]->coltype, columns[i]->namlen, columns[i]->collen);
			if (l1 + ColumnPrLength + 1 > 80)
			{
				ffputs("\n");
				l1 = ColumnPrLength + 9;
			}
			else if (columns[i]->coltype == SQLTEXT && B1)
			{
				ffputs("\t");
				l1 = ColumnPrLength + 9;
			}
			else
			{
				l1 += ColumnPrLength + 1;
			}
			if (columns[i]->coltype == SQLTEXT && B1)
				ffputs(" ");
			if (B1)
				B1 = 0;
			if (ColumnPrLength > 255)
			{
				memset(buffer, *Src, 255);
				buffer[255] = 0;
				for (j = 0; j < ColumnPrLength / 255; ++j)
					ffputs(buffer);
				buffer[ColumnPrLength % 255] = 0;
				ffputs(buffer);
			}
			else
			{
				memset(buffer, *Src, ColumnPrLength);
				buffer[ColumnPrLength] = 0;
				ffputs(buffer);
			}
			ffputs(" ");
		}
	}
	ffputs("\n");
}
/*
* print the column headings for rows returned from the server. 
*/
void __cdecl dbprhead(PDBPROCESS dbproc)
{
	int result = 0; 
	char* Destination = 0; 
	int Count = 0; 
	int ColumnPrLength = 0; 
	int i = 0; 
	column_info_t** columns = 0; 
	int B1 = 0; 
	int l1 = 0; 
	int B2 = 0; 

	i = 0;
	B1 = 1;
	B2 = 0;
	result = CheckEntry(dbproc);
	if (result)
	{
		columns = dbproc->columns_info;
		Destination = (char*)AllocateHeapMemory(4, dbproc, 0x201u, 1);
		if (Destination)
		{
			l1 = 0;
			while (i < dbproc->ncols)
			{
				if ((columns[i]->type & 0x10) != 0)
				{
					++i;
				}
				else
				{
					Count = columns[i]->namlen;
					strncpy(Destination, columns[i]->name, Count);
					ColumnPrLength = GetColumnPrLength(columns[i]->coltype, Count, columns[i]->collen);
					memset(&Destination[Count], 0x20u, ColumnPrLength - Count);
					Destination[ColumnPrLength] = 0;
					if (l1 + ColumnPrLength + 1 > 80)
					{
						ffputs("\n");
						ffputs("\t");
						l1 = ColumnPrLength + 9;
						B2 = 1;
					}
					else if (columns[i]->coltype == SQLTEXT && B1)
					{
						ffputs("\t");
						l1 = ColumnPrLength + 9;
					}
					else
					{
						l1 += ColumnPrLength + 1;
					}
					if (B1)
						B1 = 0;
					if (B2)
						B2 = 0;
					else
						ffputs(" ");
					ffputs(Destination);
					++i;
				}
			}
			ffputs(" ");
			ffputs("\n");
			linebreak(dbproc, "-");
			FreeMemory(dbproc, Destination);
		}
	}

}
unsigned int __stdcall JustifyOutput(int coltype, char* lpBuffer, char* Src, int length)
{
	int result = 0; 
	int l1 = 0; 

	result = coltype - 34;
	switch (coltype)
	{
	case SQLIMAGE:
	case SQLTEXT:
	case SQLVARBINARY:
	case SQLVARCHAR:
	case SQLBINARY:
	case SQLCHAR:
		l1 = strlen(lpBuffer) + 1;
		if ((int)(l1 - 1) >= length)
		{
			result = length;
		}
		else
		{
			memset(&lpBuffer[l1 - 1], ' ', length - (l1 - 1));
		}
		lpBuffer[length] = 0;
		break;
	case SQLINTN:
	case SQLINT1:
	case SQLBIT:
	case SQLINT2:
	case SQLINT4:
	case SQLDATETIM4:
	case SQLFLT4:
	case SQLMONEY:
	case SQLDATETIME:
	case SQLFLT8:
	case SQLDECIMAL:
	case SQLNUMERIC:
	case SQLFLTN:
	case SQLMONEYN:
	case SQLDATETIMN:
	case SQLMONEY4:
		l1 = strlen(lpBuffer);
		if (l1 >= length)
			l1 = length;
		else
			memset(Src, ' ', length - l1);
		Src[length - l1] = 0;
		strcat(Src, lpBuffer);
		result = strlen(Src) + 1;
		qmemcpy(lpBuffer, Src, result);
		break;
	default:
		return result;
	}
	return result;
}
int __stdcall PrintRowColumnData(PDBPROCESS dbproc, int ncol, int* length)
{
	char* Src = 0; 
	int len = 0; 
	column_info_t** columns = 0; 
	int ColumnPrLength = 0; 
	void* pbuf = 0; 
	int coltype = 0; 
	char* lpMem = 0; 
	column_data_t** column_data = 0; 

	columns = dbproc->columns_info;
	column_data = dbproc->columns_data;
	if ((columns[ncol]->type & 0x10) != 0)
		return SUCCEED;
	ColumnPrLength = GetColumnPrLength(columns[ncol]->coltype, columns[ncol]->namlen, columns[ncol]->collen);
	Src = (char*)column_data[ncol]->data;
	len = column_data[ncol]->len;
	if (!len && ColumnPrLength < 4)
		ColumnPrLength = 4;
	coltype = columns[ncol]->coltype;
	if (coltype == SQLTEXT || coltype == SQLIMAGE)
	{
		blob_t *ptxt = (blob_t*)column_data[ncol]->data;
		len = ptxt->len;
		Src = (char*)ptxt->data;
		if (len >= 256)
			ColumnPrLength = len;
		else
			ColumnPrLength = 256;
	}
	lpMem = (char*)AllocateHeapMemory(4, dbproc, ColumnPrLength + 15, 0);
	if (!lpMem)
		return FreeOnError(0, dbproc);
	pbuf = AllocateHeapMemory(4, dbproc, ColumnPrLength + 15, 0);
	if (!pbuf)
		return FreeOnError(lpMem, dbproc);
	if (*length + ColumnPrLength + 1 > 0x50)
	{
		ffputs("\n");
		ffputs("\t");
		*length = ColumnPrLength + 9;
	}
	else
	{
		*length += ColumnPrLength + 1;
		ffputs(" ");
	}
	if (len)
	{
		switch (coltype)
		{
		case SQLIMAGE:
			goto LABEL_34;
		case SQLVARBINARY:
		case SQLBINARY:
			coltype = SQLBINARY;
		LABEL_34:
			*lpMem = SQLINT1;
			lpMem[1] = SQLOFFSET;
			ConvertToChar(dbproc, coltype, (BYTE*)Src, len, SQLCHAR, lpMem + 2, -1);
			break;
		case SQLINTN:
			if (len == 1)
			{
				ConvertToChar(dbproc, SQLINT1, (BYTE*)Src, 1, SQLCHAR, lpMem, -1);
			}
			else if (len == 2)
			{
				ConvertToChar(dbproc, SQLINT2, (BYTE*)Src, 2, SQLCHAR, lpMem, -1);
			}
			else
			{
				ConvertToChar(dbproc, SQLINT4, (BYTE*)Src, len, SQLCHAR, lpMem, -1);
			}
			break;
		case SQLVARCHAR:
			ConvertToChar(dbproc, SQLCHAR, (BYTE*)Src, len, SQLCHAR, lpMem, -1);
			break;
		case SQLDECIMAL:
			ConvertToChar(dbproc, SQLDECIMAL, (BYTE*)Src, len, SQLCHAR, lpMem, -1);
			break;
		case SQLNUMERIC:
			ConvertToChar(dbproc, SQLNUMERIC, (BYTE*)Src, len, SQLCHAR, lpMem, -1);
			break;
		case SQLFLTN:
			if (len == 4)
				ConvertToChar(dbproc, SQLFLT4, (BYTE*)Src, 4, SQLCHAR, lpMem, -1);
			else
				ConvertToChar(dbproc, SQLFLT8, (BYTE*)Src, len, SQLCHAR, lpMem, -1);
			break;
		case SQLMONEYN:
			if (len == 4)
				ConvertToChar(dbproc, SQLMONEY4, (BYTE*)Src, 4, SQLCHAR, lpMem, -1);
			else
				ConvertToChar(dbproc, SQLMONEY, (BYTE*)Src, len, SQLCHAR, lpMem, -1);
			break;
		case SQLDATETIMN:
			if (len == 4)
				ConvertToChar(dbproc, SQLDATETIM4, (BYTE*)Src, 4, SQLCHAR, lpMem, -1);
			else
				ConvertToChar(dbproc, SQLDATETIME, (BYTE*)Src, len, SQLCHAR, lpMem, -1);
			break;
		default:
			ConvertToChar(dbproc, coltype, (BYTE*)Src, len, SQLCHAR, lpMem, -1);
			break;
		}
	}
	else
	{
		strcpy(lpMem, "NULL");
	}
	JustifyOutput(columns[ncol]->coltype, lpMem, (char*)pbuf, ColumnPrLength);
	ffputs(lpMem);
	FreeMemory(dbproc, lpMem);
	FreeMemory(dbproc, pbuf);
	return SUCCEED;
}
int __cdecl dbprrow(PDBPROCESS dbproc)
{
	int i = 0; 
	int bSucc = 0;
	int result = 0;
	int l1 = 0;

	if (!CheckEntry(dbproc))
		return 0;
	bSucc = 0;
	while (1)
	{
		result = dbnextrow(dbproc);
		if (result == NO_MORE_ROWS)
			break;
		if (!result)
			return 0;
		if (result == MORE_ROWS)
		{
			bSucc = 1;
			l1 = 0;
			for (i = 0; i < dbproc->ncols; ++i)
			{
				if (!PrintRowColumnData(dbproc, i, &l1))
					return 0;
			}
			ffputs(" ");
			ffputs("\n");
		}
		else if (result < 1)
		{
			if (result != BUF_FULL)
			{
				ffputs(" ");
				ffputs("\n");
			}else
				dbclrbuf(dbproc, 1);
		}
	}
	if (!bSucc && dbproc->severity_level == EXNONFATAL)
		return 0;
	linebreak(dbproc, " ");
	return SUCCEED;
}

__int16 __cdecl dbconnectionread(PDBPROCESS dbproc, BYTE* ReadBuffer, unsigned __int16 ReadMinSize, unsigned __int16 ReadMaxSize, int* lpErr)
{
	int timeout_ = 0; 

	if (!dbproc)
		return 0;
	if (dbisopt(dbproc, 17, 0))
		timeout_ = dbproc->timeout;
	else
		timeout_ = DbTimeOut;
	// ConnectionRead(pConnectionObject, ReadBuffer, ReadMinSize, ReadMaxSize, timeout, E);
	return dbproc->CommLayer->ConnectionRead(
		dbproc->conn_object,
		ReadBuffer,
		ReadMaxSize,
		ReadMinSize,
		(TIMEINT)timeout_,
		lpErr);
}
char szKey[] = "SOFTWARE\\Microsoft\\MSSQLServer\\Client\\ConnectTo";
int __cdecl dbserverenum(unsigned __int16 flag, LPSTR lpValueName, unsigned __int16 length, __int16* serverenum)
{
	__int16 num = 0; 
	DWORD cbData = 0; 
	DWORD cchValueName = 0; 
	LSTATUS pstatus = 0; 
	DWORD dwIndex = 0; 
	int(__stdcall * ConnectionServerEnum)(char*, USHORT, USHORT*); 

	int result = 0; 
	HMODULE hModule = 0; 
	BYTE Data[264] = { 0 };
	HKEY phkResult = 0; 
	BYTE* p = 0; 
	int len = length;
	result = 0;
	ConnectionServerEnum = 0;

	flag &= 0xFC;
	if (flag)
		return 16;
	if (!lpValueName)
		return 16;
	if (len <= 2u)
		return 16;
	if (!serverenum)
		return 16;
	if (len < 3u)
		return 1;
	lpValueName[1] = 0;
	*lpValueName = 0;
	*serverenum = 0;
	Data[0] = 0;
	if (!RegOpenKeyExA(HKEY_LOCAL_MACHINE, szKey, 0, 0x20019u, &phkResult) && (flag & 2) != 0)
	{
		for (dwIndex = 0; len > 2u; ++dwIndex)
		{
			cchValueName = len - 2;
			pstatus = RegEnumValueA(phkResult, dwIndex, lpValueName, &cchValueName, 0, 0, 0, 0);
			if (pstatus == 259)
				break;
			if (pstatus)
			{
				result |= 1u;
				break;
			}
			if (!_stricmp(lpValueName, DSQUERY))
			{
				*lpValueName = 0;
			}
			else
			{
				++*serverenum;
				lpValueName[cchValueName] = 0;
				lpValueName += cchValueName + 1;
				len -= cchValueName + 1;
			}
		}
	}
	if ((flag & 1) == 0 || (result & 1) != 0 || len <= 3u)
	{
		lpValueName[1] = 0;
		*lpValueName = 0;
	}
	else
	{
		cbData = 260;
		if (phkResult && !RegQueryValueExA(phkResult, DSQUERY, 0, 0, Data, &cbData))
			Data[cbData] = 0;
		else
			strcpy((char*)Data, "DBNMPNTW");
		for (p = Data; *p != ',' && *p && *p != ' '; ++p)
			;
		*p = 0;
		lstrcatA((LPSTR)Data, ".DLL");
		hModule = LoadLibraryA((LPCSTR)Data);
		if (hModule)
			ConnectionServerEnum = (int(__stdcall*)(char*, USHORT, USHORT*))GetProcAddress(hModule, "ConnectionServerEnum");
		if (ConnectionServerEnum)
		{
			num = *serverenum;
			result |=  ((int(__cdecl*)(LPSTR, int, __int16*))ConnectionServerEnum)(lpValueName, len, serverenum);

			*serverenum += num;
		}
		else
		{
			lpValueName[1] = 0;
			*lpValueName = 0;
			result |= 2u;
		}
		if (hModule)
			FreeLibrary(hModule);
	}
	if (phkResult)
		RegCloseKey(phkResult);
	return result;
}
int __cdecl dbsetlpacket(db_login_t* login, USHORT packet_size)
{
	int l1 = 0; 
	char Buffer[4] = { 0 };

	if (login)
	{
		if (packet_size)
		{
			if (packet_size >= 512u)
				_ultoa(packet_size, Buffer, 10);
			else
				strcpy(Buffer, "512");
		}
		else
		{
			strcpy(Buffer, "000");
		}
		l1 = strlen(Buffer) + 1;
		dbzero(login->PacketSize, 6u);
		strncpy(login->PacketSize, Buffer, l1 - 1);
		login->cbPacketSize = l1 - 1;
		return SUCCEED;
	}
	else
	{
		GeneralError(0, 10031);
		return 0;
	}
}
UINT __cdecl dbgetpacket(PDBPROCESS dbproc)
{
	if (CheckEntry(dbproc))
		return dbproc->CommLayer->bufsize;
	else
		return 0;
}

int __cdecl dbprocinfo(PDBPROCESS dbproc, DBPROCINFO* proc)
{
	if (!CheckEntry(dbproc))
		return 0;
	if (!proc)
		return 0;
	if (proc->SizeOfStruct != 0x22C)
		return 0;
	proc->ServerType = dbproc->bServerType;
	proc->ServerMajor = dbproc->ServerMajor;
	proc->ServerMinor = (unsigned __int8)dbproc->ServerMinor;
	proc->ServerRevision = (unsigned __int8)dbproc->ServerRevision;
	if (dbproc->backupserver)
	{
		proc->ServerName[0] = 0;
	}
	else
	{
		strncpy(proc->ServerName, dbproc->backupserver, 0x1Fu);
		proc->ServerName[30] = 0;
	}
	if (dbproc->dbnetlib)
	{
		proc->NetLibName[0] = 0;
	}
	else
	{
		strncpy(proc->NetLibName, dbproc->dbnetlib, 0x100u);
		proc->NetLibName[255] = 0;
	}
	if (dbproc->servername)
	{
		proc->NetLibConnStr[0] = 0;
	}
	else
	{
		strncpy(proc->NetLibConnStr, dbproc->servername, 0x100u);
		proc->NetLibConnStr[255] = 0;
	}
	return SUCCEED;
}

int __cdecl dbupdatetext(
	PDBPROCESS dbproc,
	LPCSTR objname,
	BYTE* textptr,
	BYTE* timestamp,
	char flag,
	int insert_offset,
	int delete_length,
	LPCSTR tabname,
	int size,
	BYTE* text)
{

	char* p1 = 0; 
	int l1 = 0; 
	char* p2 = 0; 

	char object_name[132] = { 0 };
	char* Buffer = 0; 
	char szTabName[36] = { 0 };
	char* lpMem = 0; 
	int exec = 0; 
	int status = 0; 

	lpMem = 0;
	Buffer = 0;
	if (!CheckEntry(dbproc))
		return 0;
	dbfreebuf(dbproc);
	if (!objname || !*objname)
		return 0;
	if (insert_offset >= -1 && delete_length >= -1 && textptr && timestamp)
	{
		GetFullName(dbproc, object_name, (char*)objname, 4);
		status = flag & 0xF;
		switch (flag & 0xF)
		{
		case 1:
			if (!tabname || !*tabname || !text || size)
				goto LABEL_68;
			break;
		case 2:
			if (tabname || !text || size < 1)
				goto LABEL_68;
			break;
		case 4:
			if (tabname || text || size < 1)
				goto LABEL_68;
			break;
		case 8:
			if (tabname || text || size)
				goto LABEL_68;
			break;
		default:
			break;
		}
		lpMem = (char*)AllocateHeapMemory(4, 0, strlen(object_name) + 220, 1);
		if (!lpMem)
			return 0;
		Buffer = (char*)AllocateHeapMemory(4, 0, 0x50u, 1);
		if (!Buffer)
			return FreeOnError(lpMem, 0);

		strcpy(lpMem, "updatetext");

		if (status == 2 || status == 4)
			strcat(lpMem, "bulk ");
		strcat(lpMem, object_name);
		if (ConvertToChar(dbproc, SQLBINARY, (BYTE*)textptr, 16, SQLCHAR, Buffer, -1) != -1)
		{
			strcat(lpMem, " 0x");
			strcat(lpMem, Buffer); // dest_text_ptr
			if (ConvertToChar(dbproc, SQLBINARY, (BYTE*)timestamp, 8, SQLCHAR, Buffer, -1) != -1)
			{
				strcat(lpMem, " timestamp = 0x");
				strcat(lpMem, Buffer);
				if (insert_offset == -1)
				{
					p1 = (char*)" NULL";
					l1 = strlen(" NULL") + 1;
					p2 = lpMem + strlen((const char*)lpMem) + 1;
				}
				else
				{
					strcat(lpMem, " ");
					p1 = _itoa(insert_offset, Buffer, 10);
					l1 = strlen(p1) + 1;
					p2 = lpMem + strlen((const char*)lpMem) + 1;
				}
				qmemcpy(p2 - 1, p1, l1);
				if (delete_length == -1)
				{
					p1 = (char*)" NULL";
					l1 = strlen(" NULL") + 1;
					p2 = lpMem + strlen((const char*)lpMem) + 1;
				}
				else
				{
					strcat(lpMem, " ");
					p1 = _itoa(delete_length, Buffer, 10);
					l1 = strlen(p1) + 1;
					p2 = lpMem + strlen((const char*)lpMem) + 1;
				}
				qmemcpy(p2 - 1, p1, l1);
				if ((flag & 0x10) != 0)
					strcat(lpMem, " with log");
				if (status == 1)
				{
					GetFullName(dbproc, szTabName, (char*)tabname, 1);
					strcat(lpMem, " ");
					strcat(lpMem, szTabName);
					if (ConvertToChar(dbproc, SQLBINARY, (BYTE*)text, 16, SQLCHAR, Buffer, -1) == -1)
					{
						FreeMemory(0, lpMem);
						return FreeOnError(Buffer, 0);
					}
					strcat(lpMem, " 0x");
					strcat(lpMem, Buffer);
				}
				if (dbcmd(dbproc, lpMem)
					&& (status != 1 && status != 8 && status != 4 || dbsqlsend(dbproc) && dbsqlok(dbproc) && dbresults(dbproc)))
				{
					if (status != 2
						|| (exec = dbproc->exec, dbproc->exec = 1, dbsqlsend(dbproc))
						&& (dbproc->exec = exec, *(_DWORD*)&dbproc->field_7C = 0, dbproc->packet_size = size, dbsqlok(dbproc))
						&& dbresults(dbproc)
						&& dbmoretext(dbproc, size, (BYTE*)text)
						&& dbsqlok(dbproc)
						&& dbresults(dbproc))
					{
						FreeMemory(0, lpMem);
						FreeMemory(0, Buffer);
						return SUCCEED;
					}
				}
			}
		}
	}
	else
	{
	LABEL_68:
		GeneralError(dbproc, SQLEPARM);
	}
	if (lpMem)
		FreeMemory(0, lpMem);
	if (Buffer)
		return FreeOnError(Buffer, 0);
	else
		return 0;
}
int __cdecl StartDTCTransaction(WORD* Src)
{
	Src[0] = 0;
	Src[1] = 0;
	return SUCCEED;
}
int __cdecl FinishDTCTransaction(BYTE* rgbWhereabouts,int cbWhereabouts, ITransactionExport**ppTransactionExport, void* lpBuffer, LPVOID pTransaction,int* lpErr) {
	HRESULT hr = S_OK;
	ITransaction* pTransaction_ = (ITransaction*)pTransaction;
	//ITransactionDispenser* pTransactionDispenser = (ITransactionDispenser*)pTransaction;
	IGetDispenser* pGetDispenser = nullptr;
	ITransactionExportFactory* pTransactionExportFactory = nullptr;
	ITransactionExport * pTransExport = nullptr;
	ULONG propagationStringLength = 0, cbUsed = 0;
	// 初始化COM库  , 放到初始化中执行
	if(0)
	{
		hr = CoInitialize(nullptr);
		if (FAILED(hr)) {
			std::cerr << "Failed to initialize COM library." << std::endl;
			return hr;
		}

		// 获取事务分发器  
		hr = CoCreateInstance(
			__uuidof(ITransactionDispenser),
			nullptr,
			CLSCTX_INPROC_SERVER,
			__uuidof(ITransactionDispenser),
			reinterpret_cast<void**>(&pTransaction_)
		);
		if (FAILED(hr)) {
			std::cerr << "Failed to create TransactionDispenser." << std::endl;
			CoUninitialize();
			return hr;
		}

	}
	if (*ppTransactionExport)
	{
		pTransExport = *ppTransactionExport;
	}
	else
	{
		hr = pTransaction_->QueryInterface(IID_IGetDispenser, (LPVOID*)&pGetDispenser);
		if (FAILED(hr))
		{
			*lpErr = hr;
			SetLastError(hr);
			return 0;
		}
		hr = pGetDispenser->GetDispenser(IID_ITransactionExportFactory, (LPVOID*)&pTransactionExportFactory);
		if (FAILED(hr))
		{
			*lpErr = hr;
			SetLastError(hr);
			pGetDispenser->Release();
			return 0;
		}
		hr = pTransactionExportFactory->Create(cbWhereabouts, rgbWhereabouts, (ITransactionExport**)&pTransExport);
		if (FAILED(hr))
		{
			*lpErr = hr;
			SetLastError(hr);
			pGetDispenser->Release();
			pTransactionExportFactory->Release();
			return 0;
		}
		pGetDispenser->Release();
		pTransactionExportFactory->Release();
		*ppTransactionExport = pTransExport;
	}
	hr = pTransExport->Export((IUnknown*)pTransaction, &propagationStringLength);
	if (FAILED(hr))
	{
		*lpErr = hr;
		SetLastError(hr);
		return 0;
	}
	BYTE * pTransactionCookie = (BYTE*)malloc(propagationStringLength);
	if (pTransactionCookie)
	{
		hr = pTransExport->GetTransactionCookie((IUnknown*)pTransaction, propagationStringLength, pTransactionCookie, &cbUsed);
		if (FAILED(hr))
		{
			*lpErr = hr;
			SetLastError(hr);
			free(pTransactionCookie);
			return 0;
		}
		unsigned int length = *((unsigned __int16*)lpBuffer + 1);// pEvent->length
		if (length < propagationStringLength)
			assert(length < propagationStringLength);

		*((WORD*)lpBuffer + 0) = 1;
		*((WORD*)lpBuffer + 1) = (WORD)propagationStringLength;
		
		qmemcpy((char*)lpBuffer + 2, pTransactionCookie, propagationStringLength);
		free(pTransactionCookie);
		return SUCCEED;
	
	}
	else
	{
		SetLastError(0x2710u);
		*lpErr = 10000;
		return 0;
	}
	if(0)
	{
		// 卸载COM库  
		CoUninitialize();
		return SUCCEED;
	}
	
}
int __cdecl dbenlisttrans(PDBPROCESS dbproc, LPVOID pTransaction)
{
	int l1 = 0; 
	int Err = 0; 
	BYTE* buffer1 = 0; 
	BYTE* pdata = 0;
	char Src[260] = { 0 };

	if (!CheckEntry(dbproc) || (dbproc->ret_status & 0x40) == 0 && !dbproc->ServerMinor && dbproc->ServerMajor < 7u)
	{
		GeneralError(dbproc, 10107);
		return 0;
	}
	if (!dbproc->CommLayer->rbytes)
		dbproc->CommLayer->ConnectionStatus();// (dbproc->conn_object, -1, e);
	if (dbproc->dtc_resources == 0)
	{
		if (!StartDTCTransaction((WORD*)Src))
			goto LABEL_30;
		buffer1 = dbproc->CommLayer->buffer1;
		*buffer1 = PT_TRANSAC;
		buffer1[1] = 0;
		buffer1[6] = 0;
		dbproc->CommLayer->packet_size = 8;
		if (!queuepacket(dbproc, (BYTE*)Src, 0x104u))
			goto LABEL_30;
		if (!sendflush(dbproc))
			goto LABEL_30;
		tidyproc(dbproc);
		dbproc->cmd_flag = 0x81;
		dbproc->curcmd = 0;
		dbproc->exec = 0;
		dbproc->token = 0;
		dbproc->rpcbuffer = 0;
		dbproc->change_dirty = 0;
		dbproc->isavail = 0;
		if (!dbsqlok(dbproc) || dbresults(dbproc) == FAIL || dbnextrow(dbproc) != MORE_ROWS)
		{
		LABEL_30:
			GeneralError(dbproc, 10107);
			return 0;
		}
		pdata = dbdata(dbproc, 1);
		l1 = dbdatlen(dbproc, 1);
	}
	if (pTransaction)
	{
		*(WORD*)&Src[2] = 256;
		if (!FinishDTCTransaction(pdata, l1, (ITransactionExport**)&dbproc->dtc_resources, (void*)Src, pTransaction, (int*)&Err))
		{
			dbcanquery(dbproc);
			GeneralError(dbproc, 10107);
			return 0;
		}
		dbcanquery(dbproc);
	}
	else
	{
		*(WORD*)Src = 1;
		*(WORD*)&Src[2] = 0;
	}
	buffer1 = dbproc->CommLayer->buffer1;
	*buffer1 = PT_TRANSAC;
	buffer1[1] = 0;
	buffer1[6] = 0;
	dbproc->CommLayer->packet_size = 8;
	if (!queuepacket(dbproc, (BYTE*)Src, *(unsigned __int16*)&Src[2] + 4))
		goto LABEL_30;
	if (!sendflush(dbproc))
		goto LABEL_30;
	tidyproc(dbproc);
	dbproc->cmd_flag = 0x81;
	dbproc->curcmd = 0;
	dbproc->exec = 0;
	dbproc->token = 0;
	dbproc->rpcbuffer = 0;
	dbproc->change_dirty = 0;
	dbproc->isavail = 0;
	if (!dbsqlok(dbproc) || dbresults(dbproc) == FAIL)
		goto LABEL_30;
	return SUCCEED;
}
int __cdecl XARelease(ITransaction* pTransaction)
{
	if (pTransaction)
		return pTransaction->Release();
	return 0;
}

DTC_GET_TRANSACTION_MANAGER __cdecl LoadDtcHelper()
{
	HMODULE hLibrary = 0; 
	DTC_GET_TRANSACTION_MANAGER result = 0; 

	hLibrary = LoadLibraryA("XOLEHLP.DLL");

	if (hLibrary)
	{
		result = (DTC_GET_TRANSACTION_MANAGER)GetProcAddress(hLibrary, "DtcGetTransactionManager");
		if (result)
			return result;
		FreeLibrary(hLibrary);
	}
	return 0;
}
int __cdecl StartXATransaction(void** xa_transaction, ITransaction** ppTransaction, int* lpErrCode)
{
	int dwErrCode = 0;
	int result = 0;
	IXATransLookup* pXATransLookup = (IXATransLookup*)*xa_transaction;
	result = 1;
	if (pXATransLookup == 0)
	{
		if (fnGetTranMan == 0)
			fnGetTranMan = LoadDtcHelper();
		if (fnGetTranMan)
		{
			dwErrCode = fnGetTranMan(0, 0, IID_IXATransLookup, 0, 0, 0, xa_transaction);
			if (dwErrCode < 0)
			{
				*lpErrCode = dwErrCode;
				SetLastError(dwErrCode);
				return 0;
			}
		}
	}
	dwErrCode = pXATransLookup->Lookup(ppTransaction);
	if (dwErrCode >= 0)
		return result;

	*lpErrCode = dwErrCode;
	SetLastError(dwErrCode);
	return 0;

}
int __cdecl dbenlistxatrans(PDBPROCESS dbproc, int bXa)
{
	int err = 0; 
	ITransaction* pTransaction = nullptr;
	int result = 0; 

	err = 0;

	result = 0;
	if (!CheckEntry(dbproc))
	{
		GeneralError(dbproc, 10107);
		return 0;
	}
	if (bXa)
	{
		if (!StartXATransaction((void**)&dbproc->xa_transaction, &pTransaction, &err))
		{
			GeneralError(dbproc, 10107);
			return 0;
		}
		result = dbenlisttrans(dbproc, (LPVOID)pTransaction);
		XARelease(pTransaction);
	}
	else
	{
		result = dbenlisttrans(dbproc, 0);
		if (!result)
			GeneralError(dbproc, 10107);
	}
	return result;
}

int __stdcall SQLDebug(DBSSDEBUG* debug)
{
	char Buffer[12] = { 0 };
	char Name[32] = { 0 };
	HANDLE hFileMappingObject = 0; 

	if (debug->SizeOfStruct < 0x48u)
		return 0;
	_ultoa(debug->ProcessId, Buffer, 16);
	strcpy(Name, "DBSSDebug");
	strcat(Name, Buffer);
	hFileMappingObject = CreateFileMappingA((HANDLE)0xFFFFFFFF, 0, PAGE_READWRITE, 0, 0x13Cu, Name);
	if (!hFileMappingObject)
		return 0;
	pMemMap = MapViewOfFile(hFileMappingObject, FILE_MAP_READ| FILE_MAP_WRITE, 0, 0, 0);
	if (!pMemMap)
		return 0;
	*(DWORD*)pMemMap = (DWORD)debug->pMemmap;
	*((DWORD*)pMemMap + 1) = debug->ThreadId;
	memmove((char*)pMemMap + 8, debug->Cmd, 0x20u);
	memmove((char*)pMemMap + 40, debug->dbgCtx, 0x10u);
	*((DWORD*)pMemMap + 14) = debug->DataSize;
	memmove((char*)pMemMap + 60, (const void*)debug->Data, debug->DataSize);
	UnmapViewOfFile(pMemMap);
	return SUCCEED;
}
#pragma warning (default : 4996)