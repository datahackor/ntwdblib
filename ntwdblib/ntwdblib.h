#pragma once

#ifndef _ntwdblib_h_
#define _ntwdblib_h_

#ifdef __cplusplus
extern "C"
{
#endif

#ifdef NTWDBLIB_EXPORTS
#define DBLIB_API __declspec(dllexport)
#define DllExtern
#else
#define DBLIB_API __declspec(dllimport)
#define DllExtern extern
#endif

#include <windows.h>
#include <sspi.h>
#include "SQL.H"


struct DBPROCESS;
struct cursor_t;
struct db_login_t;
struct col_bind_t;
struct column_info_t;
struct bcp_column_t;
struct bcp_bindinfo_t;
struct buf_node_t;
struct column_data_t;


typedef db_login_t* PLOGINREC;
typedef void* PDBHANDLE;
typedef cursor_t* PDBCURSOR;
typedef DBPROCESS* PDBPROCESS;
typedef db_login_t LOGINREC;   // login record type

// DBNETLIB.DLL
typedef int (__cdecl* CONNECTIONCLOSE)(void* pConnectionObject,NETERR UNALIGNED*);
typedef IOINT (__cdecl*CONNECTIONOBJECTSIZE)(void);
// ConnectionRead(pConnectionObject, ReadBuffer, ReadMinSize, ReadMaxSize, timeout, E);
typedef IOINT (__cdecl*CONNECTIONREAD)(void* pConnectionObject, BYTE*Src, IOINT rdMinSize, IOINT rdMaxSize, TIMEINT, NETERR UNALIGNED*);
typedef IOINT (__cdecl*CONNECTIONWRITE)(void* pConnectionObject, BYTE* Src, IOINT WtSize, NETERR UNALIGNED*);
/*
* ConnectionTransact
* 调用 ConnectionWrite 然后调用 ConnectionRead，相当于同时进行写和读
*/
typedef IOINT (__cdecl*CONNECTIONTRANSACT)(void* pConnectionObject, BYTE* ReadBuffer, BYTE* WriteBuffer, IOINT WriteSize, IOINT ReadSize, IOINT, TIMEINT timeout, NETERR UNALIGNED*);
typedef IOINT (__cdecl*CONNECTIONWRITEOOB)(void* pConnectionObject, BYTE* Src, IOINT Size, NETERR UNALIGNED*);
typedef int (__cdecl*CONNECTIONOPEN)(void* pConnectionObject, char*, NETERR*);
typedef void (__cdecl* CONNECTIONMODE)(void);
typedef void (__cdecl* CONNECTIONSTATUS)(void);
typedef int (__cdecl* CONNECTIONCHECKFORDATA)(void* pConnectionObject, int*, NETERR UNALIGNED*);
typedef BOOL (__cdecl* CONNECTIONERROR)(void* pConnectionObject, NETERR*, char**, NETERR*);

typedef int(__cdecl* CONVERTFUNC0)(PDBPROCESS dbproc, int dtIn, BYTE* lpSrc, int Length, int dtOut, void* lpOutBuffer, int Outlength, int* lpSize);
typedef int(__cdecl* CONVERTFUNC)(PDBPROCESS dbproc, int dtIn, BYTE* lpSrc, int Length, int dtOut, void* lpOutBuffer, int Outlength);

typedef long(__cdecl* DTC_GET_TRANSACTION_MANAGER)(char* pszHost, char* pszTmName, REFIID riid, DWORD dwReserved1, WORD wcbReserved2, void* pvReserved2, void** ppv);
typedef PSecurityFunctionTableA (__stdcall* INITSECURITYINTERFACE)();
typedef int(__cdecl* DBERRHANDLE_PROC)(PDBPROCESS, int severity, int dberr, int oserr, LPCSTR dberrstr, LPCSTR oserrstr);
typedef int(__cdecl* DBMSGHANDLE_PROC)(PDBPROCESS, int Number, int State, int Class, LPCSTR MsgText, LPCSTR ServerName, LPCSTR ProcName, DBUSMALLINT LineNumber);

#pragma pack(2)

struct keyset_t {
	int flag;
	int* lengths;
	char** keys;
}; // sizeof=0xC
struct datasub_t {
	int len;
	char data[1];
};
struct keycol_t {
	char* keyname;
	short size;
	short ntab;
	short opt;
	short length;
	int type;
	char* where_sub;
	char* cmdstring;
	keycol_t* next;
}; // sizeof=0x1C

struct keynode_t {
	short opt;
	short ntab;
	keycol_t* keycol;
	keynode_t* next;
}; // sizeof=0xC
typedef struct // 0x7C ,old 0x7A
{
	DBINT SizeOfStruct;
	char  Name[MAXCOLNAMELEN + 1];
	char  ActualName[MAXCOLNAMELEN + 1];
	char  TableName[MAXTABLENAME + 1];
	char padding;
	SHORT Type;
	DBINT UserType;
	DBINT MaxLength;
	BYTE  Precision;
	BYTE  Scale;
	BOOL  B1;     // TRUE, FALSE
	BYTE  VarLength;     // for old version
	BYTE  Null1;     // for old version
	BYTE  Null;  // TRUE, FALSE or DBUNKNOWN
	BYTE  CaseSensitive; // TRUE, FALSE or DBUNKNOWN
	int  Updatable;     // TRUE, FALSE or DBUNKNOWN
	short  Identity; // TRUE, FALSE
} dbcol_t, * lpdbcol; 

struct cursor_t {
	PDBPROCESS dbproc;
	short scrollopt;
	short concuropt;
	int n_total_rows;
	int* pstatus;
	char* stmt;
	char* from;
	char* p_where;
	char* p_groupby;
	char* select;
	short fetchtype;
	short n_tabs;
	buf_node_t* tabname_array;
	short n_table_array_size;
	short field_2E;
	char** pp_table_array;
	int keyid;
	keycol_t* keycols;
	keynode_t* keys;
	int nset;
	int nkey;
	int n_key_row;
	int field_4C;
	char* rowcount;
	short opt;
	short nrowmax;
	column_info_t** columnsinfo;
	column_data_t** rows_data;
	col_bind_t** binds;
	keyset_t* keyset;
	column_data_t** columnsdata;
	short ncols;
	short field_6E;
	int nfetch_row;
	int total_rows_fetched;
	int field_78;
	int field_7C;
	int n_cursor;
	int useclientcursors;
	BYTE field_88;
	BYTE field_89;
	BYTE field_8A;
	BYTE field_8B;
	int field_8C;
	int field_90;
	int nrows1;
	int field_98;

}; // sizeof=0x9C
struct bcp_t {
	HANDLE m_hFile;
	HANDLE m_hFileMapping;
	BYTE* m_pMap;
	int field_C;
	__int64 m_nFileSize;
	__int64 m_nToWriteSize;
	__int64 m_nMapSize;
	BYTE* m_pBuffer;
	BOOL m_bMaped;
}; // sizeof=0x30
struct bcp_bindinfo_t {
	BYTE type;
	BYTE status; 
	BYTE usertype;
	BYTE length;
	short colid;
	BYTE* vardata;
	int datsize;
	char* offset_val;
	short offset;
	bcp_column_t* columnsinfo;
	int cdefault;
	char* name;
	BYTE precision;
	BYTE scale;
	void* convfunc;
	ushort commontype;
	int have_data;
	ushort from_type;
	ushort to_type;
	int data_len;
};// sizeof=0x34

struct bcp_column_t {
	BYTE usertype;
	BYTE field_1;
	int collen;
	int varlen;
	BYTE* vardata;
	BYTE* varaddr;
	ushort prefixlen;
	ushort termlen;
	char* terminator;
	int column_datsize;
	__int64 data_pos;
	bcp_bindinfo_t* bindinfo;
	BYTE balloced;
	BYTE field_2B;

};// sizeof=0x2C
struct bcp_blob_t {
	bcp_bindinfo_t* bindinfo;
	bcp_column_t* columns;
	int textsize;
	short field_C;
	BYTE type;
	BYTE offset;
	ushort length;
	int datsize;
}; // sizeof=0x16
/*
 * Information about blobs (e.g. text or image).
 */
struct blob_t {
	// image
	BYTE size;
	BYTE field_1;
	BYTE* txptr;
	BYTE timestamp[8];
	int len;
	BYTE* data;
};// sizeof=0x16
struct bcp_info_t
{
	BYTE b_loaded;
	BYTE direction;
	int dcol; // data column
	int result;
	int batch;
	short lcol; // log column
	short maxerrs;
	bcp_t* bcpdata;
	char* p_tabname;
	ushort ncols;
	bcp_column_t* columns;
	bcp_t* bcplog;
	ushort num_cols;
	bcp_bindinfo_t* bindinfo;
	ushort minlen;
	ushort maxlen;
	char* offset_val;
	int first;
	int last;
	ushort textcount;
	ushort maxcount;
	ushort textindex;
	bcp_blob_t* textdata;
	char tablename[31];
	char field_63[31];
	char tabname1[31];
	char dbname[31];
	BOOL read_fail;
	BYTE* blkbuffer;
	__int64 read_pos;
	__int64 total_size;
	__int64 read_size;
	char object_id[100];
	int keepnul;
	__int64 filesize;
	int charset;
	PDBPROCESS dbproc;
}; // sizeof=0x158

struct SmallDateTime {
	ushort dtdays;
	ushort dttime;
};
struct null_value_t {
	char* p_nchar;
	short nchar_length;
	char* p_nstring;
	char* p_ntbstring;
	DBVARYCHAR* p_nvarychar;
	void* p_nbinary;
	short nbinary_length;
	DBVARYBIN* p_nvarybin;
	BYTE ntiny;
	BYTE padd0;
	short nsmall;
	int nint;
	double nfloat8;
	short nbit;
	DBMONEY nmoney;
	DBDATETIME ndatetime;
	int nsmallmoney;
	int nsmalldate;
	float nfloat4;
	DBNUMERIC nnumeric;
	DBDECIMAL ndecimal;
}; //sizeof = 0x70

typedef struct dbbigmoney
{
	int mnyhigh;
	ULONG mnylow;
	int hold;
} DBBIGMONEY;
typedef struct db_option
{
	BYTE opt;
	BYTE opt1;
	USHORT mask;
	char* name;
} DBPTION;

struct column_data_t {
	int len;
	BYTE* data; //  blob_t
};
//struct altdata_t {
//	int length;
//	LPCBYTE data;
//};
struct offset_t {
	ushort index;
	ushort off;
	offset_t* next;
};
/*
* top
*     The type of aggregate operator.
*     AOPCNT = %x4B ; Count of rows (COUNT)
*     AOPSUM = %x4D ; Sum of the values in the rows (SUM)
*     AOPAVG = %x4F ; Average of the values in the rows (AVG)
*     AOPMIN = %x51 ; Minimum value of the rows (MIN)
*     AOPMAX = %x52 ; Maximum value of the rows (MAX)
* Operand
*     The column number, starting from 1, in the result set that is the operand for the aggregate 
*     operator.
*/
struct altcol_t {
	char* name;
	BYTE len;
	BYTE token;
	int UserType;
	int length;
	BYTE top; // The type of aggregate operator.
	BYTE Operand; //  column number
	BYTE precision;
	BYTE scale;
}; // sizeof=0x12
struct col_bind_t {
	ushort ncol;
	ushort bind_type;
	int length;
	char* buffer;
	void* conv_func;
	int* indicator;
};// sizeof=0x14
struct null_bind_t {
	ushort ncol;
	ushort bind_type;
	int length;
	BOOL bconvert;
	void* conv_func;
	int field_10;
};// sizeof=0x14

struct altcol_link_t {
	ushort n_alts;
	ushort nrow;
	altcol_t** altcols;
	BYTE caltcols;
	BYTE data_length;
	BYTE* databuffer;
	col_bind_t** altbinds;
	altcol_link_t* next;
};// sizeof=0x16

struct alt_column_data_t {
	short nrow;
	short ncol;
	column_data_t** columnsdata;
};
struct rowbuffer_t {
	int nrow;
	column_data_t** columnsdata;
	alt_column_data_t** altcoldata;
};
struct numeric_t {
	int size;
	BYTE sign;
	BYTE field_5[3];
	BYTE* values;
};
/*
* Flags 
* Bit flags in least significant bit order:
* Flags = 0   - fNullable
*         1   - fCaseSen
*         2,3 - usUpdateable (2BIT, 0 = ReadOnly,1 = Read/Write,2 = Unused)
*         4   - fIdentity
*         5   - FRESERVEDBIT 
*         6,7 - usReservedODBC (2BIT)
*         8   - FRESERVEDBIT
*/
struct column_info_t {
	char name[31];
	BYTE namlen;
	ushort usertype;
	ushort flags;
	BYTE coltype;
	BYTE padding;
	int collen; // column data type length
	BYTE type;
	BYTE padding1;
	char* actualname;
	short ntab; // table number
	char* format;
	BYTE precision;
	BYTE scale;
	int varlength;
};
/*
* name
* The parameter name length and parameter name (within B_VARCHAR).
*
* Status 
* 0x01: If ReturnValue corresponds to the OUTPUT parameter of a stored procedure invocation.
* 0x02: If ReturnValue corresponds to the return value of the UDF
*/
struct retval_t {
	char* name; //  parameter name B_VARCHAR
	BYTE type;
	BYTE field_5;
	int retlen;
	BYTE* values;
	BYTE Status;
	BYTE field_F;
};
struct db_login_t {
	char HostName[30]; // HostName
	BYTE cbHostName;   // cbHostName
	char UserName[30] ;
	BYTE cbUserName;
	char Password[30];
	BYTE cbPassword;
	char HostProc[8];
	char Reservedbyte1[16]; 
	char AppType[6]; // Node ID
	BYTE cbHostProc;
	BYTE lInt2;
	BYTE lInt4;
	BYTE lChar;
	BYTE lFloat;
	BYTE Reservedbyte2;
	BYTE lUseDb;
	BYTE lDumpLoad; // bulk_copy
	BYTE lInterface;
	BYTE lType;
	char Reservedbyte3[6];
	BYTE lDBLIBFlags;
	char AppName[30];
	BYTE cbAppName;
	char ServerName[30];
	BYTE cbServerName;
	char RemotePassword[255];
	BYTE cbRemotePassword;
	char TDSVersion[4]; // 4.2 = <BYTES>04 02 00 00 </BYTES>
	char ProgName[10];
	BYTE cbProgName;
	char ProgVersion[5]; //  <BYTES>06 00 00 00 </BYTES> 保留 1 字节
	BYTE lFloat4;
	BYTE lDate4;
    char Language[30];
	BYTE cbLanguage;
	BYTE SetLang;
	BYTE Reservedbyte4[45];
	char PacketSize[6];
	BYTE cbPacketSize;
	int Padding;
	DBERRHANDLE_PROC err_handler;
	DBMSGHANDLE_PROC msg_handler;
	int logintime;
	int fallback;
}; // sizeof=0x248
/*
* 通讯协议层 
* 包头 8 字节
* Type 
* 1 - SQL batch. This can be any language that the server understands.
* 2 - Login.
* 3 - RPC.
* 4 - Tabular result. This indicates a stream that contains the server response to a client request.
* 5 - Unused.
* 6 - Attention signal.
* 7 - Bulk load data. This type is used to send binary data to the server.
* 8-13 - Unused.
* 14 - Transaction manager request.
* 15 - Unused.
* 16 - Unused.
* 17 - SSPI message.
* 18 - Pre-login message.
* 
* Status
* 0 - "Normal" message.
* 1 - End of message (EOM). EOM indicates the last packet of the message.
* 2 - From client to server. Ignore this event (0x01 MUST also be set).
* 
* SPID
* SPID is the process ID on the server, network byte order (big-endian).
* 
* Length 
* the size of the packet
* 
* PacketID 
* PacketID is incremented by 1, up to 255 
* 
* Window
* This 1-byte item is currently not used. This byte SHOULD be set to 0x00 and SHOULD be ignored by the receiver.
*/
struct PacketHeader {
	BYTE Type;  
	BYTE Status;
	ushort Length;
	ushort SPID; 
	BYTE Packet;
	BYTE Window;
};
struct commlayer_t {
	ushort length;
	ushort rbytes;
	ushort wbytes;
	ushort packet_size;
	BYTE* userdata;
	int status;
	BYTE* buffer0;
	BYTE* buffer1;
	BYTE* buffer_0;
	BYTE* buffer_1;
	CONNECTIONOBJECTSIZE ConnectionObjectSize;
	CONNECTIONREAD ConnectionRead;
	CONNECTIONWRITE ConnectionWrite;
	CONNECTIONTRANSACT ConnectionTransact;
	CONNECTIONWRITEOOB ConnectionWriteOOB;
	CONNECTIONSTATUS ConnectionMode;
	CONNECTIONSTATUS ConnectionStatus;
	CONNECTIONOPEN ConnectionOpen;
	CONNECTIONCLOSE ConnectionClose;
	CONNECTIONCHECKFORDATA ConnectionCheckForData;
	void* null_sub;
	CONNECTIONERROR ConnectionError;
	HMODULE module;
	ushort bufsize;
	short lastbufsize;
	short field_58;
}; // sizeof=0x5A
struct buf_node_t {
	void* data;
	int size;
	buf_node_t* next;
};
struct SecSession {
	BOOL first_time ;
	SecHandle CredHandle;
	int have_credential;
	int have_securitycontext;
	_SecHandle secHandle;
	const char* authentication;
}; // sizeof=0x20
struct SecEntry {
	PDBPROCESS dbproc;
	SecSession * session;
	SecEntry* next;
};
__declspec(align(2)) struct DBPROCESS
{ //sizeof 0x3DAu
	BYTE ver; // 当前数据库版本，比如4.2，那就是 0x42
	BYTE cmd_flag;
	BOOL exec;
	commlayer_t* CommLayer;
	LPVOID conn_object; // Connect Object
	uchar token;
	//char field_F;
	int bclosed;
	short severity_level;
	LPVOID control_info;
	buf_node_t* cmdbuffer;
	buf_node_t* rpcbuffer;
	short ncols; 
	column_info_t** columns_info;
	rowbuffer_t* rowbuffer;
	int nbufrow; // buffer row 
	int firstrow;
	int lastrow;
	int currow;
	int nextrowidx;
	int rowidx;
	column_data_t** columns_data;
	int nrows;
	short n_compute_row;
	altcol_link_t* altcolinfo;
	alt_column_data_t** altrowdata;
	int DoneRowCount;
	offset_t* offsets;
	int proc_id;
	short n_orders; // orderby
	BYTE* ordercols;
	short ntab;
	char** tabnames;
	int return_status;
	short numrets; // Return values  Count
	retval_t** retvals;
	int packet_size;
	char field_7C;
	char field_7D;
	char field_7E;
	char field_7F;
	short field_80;
	db_option option[19];
	int textlimit_size;
	char name[32];
	int rowtype;
	short curcmd;
	short numcols;
	int isavail;
	col_bind_t** binds;
	null_value_t* nulls;
	int change_dirty;
	bcp_info_t* bcpinfo;
	char opmask;
	char field_15B;
	short n_cursor;
	cursor_t** cursors;
	void* db_close_cursors;
	CRITICAL_SECTION cursorSem;
	int ansi;
	short nretval;
	ushort ret_status;
	DBERRHANDLE_PROC err_handler;
	DBMSGHANDLE_PROC msg_handler;
	DBERRHANDLE_PROC last_err_handler;
	DBMSGHANDLE_PROC last_msg_handler;
	int field_196;
	int field_19A;
	BYTE bServerType;
	BYTE ServerMajor;
	BYTE ServerMinor;
	BYTE ServerRevision;
	int timeout;
	char backupserver[31];
	char dbnetlib[256];
	//BYTE password;
	//char field_1CA[26];
	//char field_1E4[84];
	//DBERRHANDLE_PROC errhandler;
	//DBMSGHANDLE_PROC msghandler1;
	char servername[257];
	HANDLE hHeap;
	void* dtc_resources; // ITransactionExport*
	void* xa_transaction; // IXATransLookup *
	int ThreadId;
	int b_security;
	
};

struct option_t {
	BYTE index;
	BYTE optmask;
	char* parmname;
	char* optname;
	ushort option;
};

struct DBSSDEBUG {
	int SizeOfStruct;
	void* pMemmap;
	int ProcessId;
	char Cmd[32];
	int Data;
	int DataSize;
	char dbgCtx[16];
	int ThreadId;
}; // sizeof=0x48

#pragma pack(show) 



// Macros for setting the PLOGINREC
#define DBSETLHOST(a,b)    dbsetlname   ((a), (b), DBSETHOST)
#define DBSETLUSER(a,b)    dbsetlname   ((a), (b), DBSETUSER)
#define DBSETLPWD(a,b)     dbsetlname   ((a), (b), DBSETPWD)
#define DBSETLAPP(a,b)     dbsetlname   ((a), (b), DBSETAPP)
#define BCP_SETL(a,b) bcp_setl     ((a), (b))
#define DBSETLNATLANG(a,b) dbsetlname   ((a), (b), DBSETLANG)
#define DBSETLPACKET(a,b)  dbsetlpacket ((a), (b))
#define DBSETLSECURE(a)    dbsetlname   ((a), 0,   DBSETSECURE)
#define DBSETLVERSION(a,b) dbsetlname   ((a), 0,  (b))
#define DBSETLTIME(a,b)		dbsetlname    ((a), (LPCSTR)(ULONG)(b), DBSETLOGINTIME)
#define DBSETLFALLBACK(a,b) dbsetlname   ((a), (b),   DBSETFALLBACK)

//typedef int(__cdecl* ERRORHANDLER)(db_dbprocess*, int, int, int, char*, _BYTE*);

void* __stdcall dbmove(void* Src, void* Dst, size_t Size);

DBLIB_API DBERRHANDLE_PROC __cdecl dberrhandle(DBERRHANDLE_PROC);
DBLIB_API DBMSGHANDLE_PROC __cdecl dbmsghandle(DBMSGHANDLE_PROC);
DBLIB_API DBERRHANDLE_PROC __cdecl dbprocerrhandle(PDBPROCESS, DBERRHANDLE_PROC);
DBLIB_API DBMSGHANDLE_PROC __cdecl dbprocmsghandle(PDBPROCESS, DBMSGHANDLE_PROC);

// BCP functions
DBLIB_API int __cdecl bcp_batch(PDBPROCESS);
DBLIB_API int __cdecl bcp_bind(PDBPROCESS, LPCBYTE, int, int, LPCBYTE, int, int, int);
DBLIB_API int __cdecl bcp_colfmt(PDBPROCESS, int, BYTE, int, int, LPCBYTE, int, int);
DBLIB_API int __cdecl bcp_collen(PDBPROCESS, int, int);
DBLIB_API int __cdecl bcp_colptr(PDBPROCESS, LPCBYTE, int);
DBLIB_API int __cdecl bcp_columns(PDBPROCESS, int);
DBLIB_API int __cdecl bcp_control(PDBPROCESS, int, int);
DBLIB_API int __cdecl bcp_done(PDBPROCESS);
DBLIB_API int __cdecl bcp_exec(PDBPROCESS, int *);
DBLIB_API int __cdecl bcp_init(PDBPROCESS, LPCSTR tblname, LPCSTR hfile, LPCSTR errfile, int direction);
DBLIB_API int __cdecl bcp_moretext(PDBPROCESS, int, LPCBYTE);
DBLIB_API int __cdecl bcp_readfmt(PDBPROCESS, LPCSTR);
DBLIB_API int __cdecl bcp_sendrow(PDBPROCESS);
DBLIB_API int __cdecl bcp_setl(PLOGINREC, bool);
DBLIB_API int __cdecl bcp_writefmt(PDBPROCESS, LPCSTR);

// Standard DB-Library functions
DBLIB_API LPCBYTE __cdecl dbadata(PDBPROCESS dbproc, int computeid, int colnum);
DBLIB_API int __cdecl dbadlen(PDBPROCESS dbproc, int computeid, int column);
DBLIB_API int __cdecl dbaltbind(PDBPROCESS, int computeid, int column, int vartype, int varlen, LPCBYTE varaddr);
DBLIB_API int  __cdecl dbaltcolid(PDBPROCESS, int computeid, int column);
DBLIB_API int __cdecl dbaltlen(PDBPROCESS, int computeid, int column);
DBLIB_API int  __cdecl dbaltop(PDBPROCESS, int computeid, int column);
DBLIB_API int  __cdecl dbalttype(PDBPROCESS, int computeid, int column);
DBLIB_API int __cdecl dbaltutype(PDBPROCESS, int computeid, int column);
DBLIB_API int __cdecl dbanullbind(PDBPROCESS, int computeid, int column, LPCDBINT indicator);
DBLIB_API int __cdecl dbbind(PDBPROCESS, int column, int vartype, int varlen, LPBYTE varaddr);
DBLIB_API LPCBYTE __cdecl dbbylist(PDBPROCESS, int computeid, LPINT size);
DBLIB_API int __cdecl dbcancel(PDBPROCESS);
DBLIB_API int __cdecl dbcanquery(PDBPROCESS);
DBLIB_API LPCSTR  __cdecl dbchange(PDBPROCESS);
DBLIB_API int __cdecl dbclose(PDBPROCESS);
DBLIB_API void __cdecl dbclrbuf(PDBPROCESS, int n);
DBLIB_API int __cdecl dbclropt(PDBPROCESS, int option, LPCSTR param);
DBLIB_API int __cdecl dbcmd(PDBPROCESS, LPCSTR cmdstring);
DBLIB_API int __cdecl dbcmdrow(PDBPROCESS);
DBLIB_API BOOL __cdecl dbcolbrowse(PDBPROCESS, int colnum);
DBLIB_API int __cdecl dbcolinfo(PDBHANDLE, int, int, int, LPDBCOL);
DBLIB_API int __cdecl dbcollen(PDBPROCESS, int column);
DBLIB_API LPCSTR  __cdecl dbcolname(PDBPROCESS, int column);
DBLIB_API LPCSTR  __cdecl dbcolsource(PDBPROCESS, int colnum);
DBLIB_API int __cdecl dbcoltype(PDBPROCESS, int column);
DBLIB_API int __cdecl dbcolutype(PDBPROCESS, int column);
DBLIB_API int  __cdecl dbconvert(PDBPROCESS dbproc, int srctype, LPCBYTE src, int srclen, int desttype, LPBYTE dest, int destlen);
DBLIB_API int __cdecl dbcount(PDBPROCESS);
DBLIB_API int  __cdecl dbcurcmd(PDBPROCESS);
DBLIB_API int __cdecl dbcurrow(PDBPROCESS);
DBLIB_API int __cdecl dbcursor(PDBCURSOR hc, int optype, int bufno, LPCSTR table, LPCSTR values);
DBLIB_API int __cdecl dbcursorbind(PDBCURSOR, int col, int vartype, int varlen, int * poutlen, LPBYTE pvaraddr);
DBLIB_API int __cdecl dbcursorclose(PDBHANDLE);
DBLIB_API int __cdecl dbcursorcolinfo(PDBCURSOR, int column, LPSTR colname, LPINT coltype, int * collen, LPINT usertype);
DBLIB_API int __cdecl dbcursorfetch(PDBCURSOR, int fetchtype, int rownum);
DBLIB_API int __cdecl dbcursorfetchex(PDBCURSOR, int, int, int, int);
DBLIB_API int __cdecl dbcursorinfo(PDBCURSOR, int* ncols, int * nrows);
DBLIB_API int __cdecl dbcursorinfoex(PDBCURSOR, LPDBCURSORINFO);
DBLIB_API PDBCURSOR __cdecl dbcursoropen(PDBPROCESS, LPCSTR stmt, int scrollopt, int concuropt, int nrows, int * pstatus);
DBLIB_API LPCBYTE __cdecl dbdata(PDBPROCESS, int column);
DBLIB_API BOOL __cdecl dbdataready(PDBPROCESS);
DBLIB_API int __cdecl dbdatecrack(PDBPROCESS, LPDBDATEREC dateinfo, LPCDBDATETIME datetime);
DBLIB_API int __cdecl dbdatlen(PDBPROCESS, int column);
DBLIB_API BOOL __cdecl dbdead(PDBPROCESS);
DBLIB_API void __cdecl dbexit(void);
DBLIB_API int __cdecl dbenlisttrans(PDBPROCESS, LPVOID);
DBLIB_API int __cdecl dbenlistxatrans(PDBPROCESS, BOOL);
DBLIB_API int __cdecl dbfcmd(PDBPROCESS dbproc, LPCSTR cmdstring, ...);
DBLIB_API int __cdecl dbfirstrow(PDBPROCESS);
DBLIB_API void __cdecl dbfreebuf(PDBPROCESS);
DBLIB_API void __cdecl dbfreelogin(PLOGINREC);
DBLIB_API void __cdecl dbfreequal(LPCSTR);
DBLIB_API LPSTR __cdecl dbgetchar(PDBPROCESS, int n);
DBLIB_API SHORT __cdecl dbgetmaxprocs(void);
DBLIB_API int  __cdecl dbgetoff(PDBPROCESS, DBUSMALLINT offtype, int startfrom);
DBLIB_API UINT __cdecl dbgetpacket(PDBPROCESS);
DBLIB_API int  __cdecl dbgetrow(PDBPROCESS, int row);
DBLIB_API int  __cdecl dbgettime(void);
DBLIB_API BYTE*  __cdecl dbgetuserdata(PDBPROCESS);
DBLIB_API BOOL __cdecl dbhasretstat(PDBPROCESS);
DBLIB_API LPCSTR  __cdecl dbinit(void);
DBLIB_API BOOL __cdecl dbisavail(PDBPROCESS);
DBLIB_API BOOL __cdecl dbiscount(PDBPROCESS);
DBLIB_API BOOL __cdecl dbisopt(PDBPROCESS, int option, LPCSTR param);
DBLIB_API int __cdecl dblastrow(PDBPROCESS);
DBLIB_API void __cdecl dblocklib();
DBLIB_API PLOGINREC __cdecl dblogin(void);
DBLIB_API int __cdecl dbmorecmds(PDBPROCESS);
DBLIB_API int __cdecl dbmoretext(PDBPROCESS, int size, LPCBYTE text);
DBLIB_API LPCSTR  __cdecl dbname(PDBPROCESS);
DBLIB_API int  __cdecl dbnextrow(PDBPROCESS);
DBLIB_API int __cdecl dbnullbind(PDBPROCESS, int column, LPCDBINT indicator);
DBLIB_API int  __cdecl dbnumalts(PDBPROCESS, int computeid);
DBLIB_API int  __cdecl dbnumcols(PDBPROCESS);
DBLIB_API int  __cdecl dbnumcompute(PDBPROCESS);
DBLIB_API int  __cdecl dbnumorders(PDBPROCESS);
DBLIB_API int  __cdecl dbnumrets(PDBPROCESS);
DBLIB_API PDBPROCESS   __cdecl dbopen(PLOGINREC, LPCSTR server);
DBLIB_API int  __cdecl dbordercol(PDBPROCESS, int order);
DBLIB_API int __cdecl dbprocinfo(PDBPROCESS, LPDBPROCINFO);
DBLIB_API void __cdecl dbprhead(PDBPROCESS);
DBLIB_API int __cdecl dbprrow(PDBPROCESS);
DBLIB_API LPCSTR  __cdecl dbprtype(int token);
DBLIB_API LPCSTR  __cdecl dbqual(PDBPROCESS, int tabnum, LPCSTR tabname);
DBLIB_API int __cdecl dbreadpage(PDBPROCESS, LPCSTR, int, int, LPBYTE);
DBLIB_API int __cdecl dbreadtext(PDBPROCESS, LPVOID buf, int bufsize);
DBLIB_API int __cdecl dbresults(PDBPROCESS);
DBLIB_API LPCBYTE __cdecl dbretdata(PDBPROCESS, int retnum);
DBLIB_API int __cdecl dbretlen(PDBPROCESS, int retnum);
DBLIB_API LPCSTR  __cdecl dbretname(PDBPROCESS, int retnum);
DBLIB_API int __cdecl dbretstatus(PDBPROCESS);
DBLIB_API int  __cdecl dbrettype(PDBPROCESS, int retnum);
DBLIB_API int __cdecl dbrows(PDBPROCESS);
DBLIB_API int  __cdecl dbrowtype(PDBPROCESS);
DBLIB_API int __cdecl dbrpcinit(PDBPROCESS, LPCSTR rpcname, DBSMALLINT options);
DBLIB_API int __cdecl dbrpcparam(PDBPROCESS dbproc, char* paramname, BYTE status, int type, int maxlen, int datalen, BYTE* value);
DBLIB_API int __cdecl dbrpcsend(PDBPROCESS);
DBLIB_API int __cdecl dbrpcexec(PDBPROCESS);
DBLIB_API void __cdecl dbrpwclr(PLOGINREC);
DBLIB_API int __cdecl dbrpwset(PLOGINREC, LPCSTR srvname, LPCSTR password, int pwlen);
DBLIB_API int  __cdecl dbserverenum(USHORT, LPSTR, USHORT, LPUSHORT);
DBLIB_API void __cdecl dbsetavail(PDBPROCESS);
DBLIB_API int __cdecl dbsetmaxprocs(SHORT);
DBLIB_API int __cdecl dbsetlname(PLOGINREC, LPCSTR value, int which);
DBLIB_API int __cdecl dbsetlogintime(int seconds);
DBLIB_API int __cdecl dbsetlpacket(PLOGINREC login, USHORT packet_size);
DBLIB_API int __cdecl dbsetnull(PDBPROCESS, int bindtype, int bindlen, LPCBYTE bindval);
DBLIB_API int __cdecl dbsetopt(PDBPROCESS dbproc, int option, LPCSTR param);
DBLIB_API int __cdecl dbsettime(int seconds);
DBLIB_API void __cdecl dbsetuserdata(PDBPROCESS, BYTE* ptr);
DBLIB_API int __cdecl dbsqlexec(PDBPROCESS);
DBLIB_API int __cdecl dbsqlok(PDBPROCESS);
DBLIB_API int __cdecl dbsqlsend(PDBPROCESS);
DBLIB_API int __cdecl dbstrcpy(PDBPROCESS, int start, int numbytes, LPSTR dest);
DBLIB_API int  __cdecl dbstrlen(PDBPROCESS);
DBLIB_API BOOL __cdecl dbtabbrowse(PDBPROCESS, int tabnum);
DBLIB_API int  __cdecl dbtabcount(PDBPROCESS);
DBLIB_API LPCSTR  __cdecl dbtabname(PDBPROCESS, int tabnum);
DBLIB_API LPCSTR  __cdecl dbtabsource(PDBPROCESS, int colnum, LPINT tabnum);
DBLIB_API int  __cdecl dbtsnewlen(PDBPROCESS);
DBLIB_API BYTE* __cdecl dbtsnewval(PDBPROCESS);
DBLIB_API int __cdecl dbtsput(PDBPROCESS, BYTE* newts, int newtslen, int tabnum, LPCSTR tabname);
DBLIB_API BYTE* __cdecl dbtxptr(PDBPROCESS, int column);
DBLIB_API BYTE* __cdecl dbtxtimestamp(PDBPROCESS, int column);
DBLIB_API BYTE* __cdecl dbtxtsnewval(PDBPROCESS);
DBLIB_API int __cdecl dbtxtsput(PDBPROCESS, BYTE* newtxts, int colnum);
DBLIB_API int __cdecl dbuse(PDBPROCESS, LPCSTR dbname);
DBLIB_API BOOL __cdecl dbvarylen(PDBPROCESS, int column);
DBLIB_API BOOL __cdecl dbwillconvert(int srctype, int desttype);
DBLIB_API int __cdecl dbwritepage(PDBPROCESS dbproc, LPCSTR dbname, int fileno,int pageno, int size, LPBYTE buf);
DBLIB_API int __cdecl dbwritetext(PDBPROCESS dbproc, LPCSTR objname, BYTE* textptr, DBTINYINT textptrlen, BYTE* timestamp, BOOL log, int size, LPCBYTE text);
DBLIB_API int __cdecl dbupdatetext(PDBPROCESS dbproc, LPCSTR objname, BYTE* textptr, BYTE* timestamp, int, int, int, LPCSTR, int size, BYTE* text);
DBLIB_API void __cdecl dbwinexit();
DBLIB_API int __cdecl msdblib_datecrack(DBPROCESS* dbproc, DBDATEREC* di, DBDATETIME* datetime);
DBLIB_API int __cdecl abort_xact(PDBPROCESS dbproc, int Value);
DBLIB_API int __cdecl build_xact_string(const char* xact_name, const char* service_name, int commid, char* lpResult);
DBLIB_API int __cdecl close_commit(PDBPROCESS connect);
DBLIB_API void __cdecl dbunlocklib();
DBLIB_API PDBPROCESS __cdecl open_commit(db_login_t* login, const char* servername);
DBLIB_API int __cdecl remove_xact(PDBPROCESS connect, int commid, int n);
DBLIB_API int __cdecl start_xact(PDBPROCESS connect, const char* application_name, const char* xact_name, int site_count);
DBLIB_API int __cdecl stat_xact(PDBPROCESS connect, int commid);
DBLIB_API int __cdecl dbcolntype(PDBPROCESS connect, int col);
DBLIB_API int __cdecl dbbcmd(PDBPROCESS dbproc, const char* cmd, size_t Size);


int __cdecl ConvertToFloat(PDBPROCESS dbproc, int dtIn, BYTE* Src, int Length, int dtOut, double* lpValue);
int __cdecl ConvertToInt(PDBPROCESS dbproc, int dtIn, BYTE* Src, int Length, int dtOut, void* lpValue);
int __cdecl ConvertToLong(PDBPROCESS dbproc, int dtIn, BYTE* Src, int Length, int dtOut, void* lpValue);
int __cdecl ConvertToChar(PDBPROCESS dbproc, int dtIn, BYTE* Src, int Length, int dtOut, char* lpOutString, int Outlength);
int __cdecl ConvertToChar2(PDBPROCESS dbproc, int dtIn, BYTE* Src, int Length, int dtOut, char* lpOutString, int Outlength, int* lpSize);
int __cdecl ConvertToBinary(PDBPROCESS dbproc, int dtIn, BYTE* Src, int Length, int dtOut, void* lpOutBuffer, int Outlength);
int __cdecl ConvertToDateTime(PDBPROCESS dbproc, int dtIn, SmallDateTime* Src, int Length, int dtOut, DBDATETIME* datetime);
int __cdecl ConvertToBit(PDBPROCESS dbproc, int dtIn, BYTE* Src, int Length, int dtOut, char* lpBuffer);
int __cdecl ConvertToMoney(PDBPROCESS dbproc, int dtIn, BYTE* Src, int Length, int dtOut, DBMONEY* lpBuffer, int OutLength);
int __cdecl ConvertToReal(PDBPROCESS dbproc, int dtIn, BYTE* Src, int Length, int dtOut, float* lpValue);
int __cdecl ConvertToSmallMoney(PDBPROCESS dbproc, int dtIn, BYTE* Src, int Length, int dtOut, DWORD* lpMoney, int OutLength);
int __cdecl ConvertToSmallDate(PDBPROCESS dbproc, int dtIn, SmallDateTime* Src, int Size, int dtOut, SmallDateTime* date);
int __cdecl ConvertToNumericDecimal(PDBPROCESS dbproc, int dtIn, BYTE* Src, int Length, int dtOut, DBNUMERIC* lpDecimal, int OutLength);

#ifdef __cplusplus
}
#endif

#endif // _ntwdblib_h_

