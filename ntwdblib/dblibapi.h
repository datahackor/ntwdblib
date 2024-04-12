#pragma once

#ifndef _dblib_h_
#define _dblib_h_

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

#include "ntwdblib.h"

typedef db_login_t* PLOGINREC;
typedef void* PDBHANDLE;
typedef cursor_t* PDBCURSOR;
typedef db_process_t DBPROCESS;
typedef db_process_t* PDBPROCESS;
typedef db_login_t LOGINREC;   // login record type

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
DBLIB_API int __cdecl bcp_exec(PDBPROCESS, int*);
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
DBLIB_API int __cdecl dbcursorbind(PDBCURSOR, int col, int vartype, int varlen, int* poutlen, LPBYTE pvaraddr);
DBLIB_API int __cdecl dbcursorclose(PDBHANDLE);
DBLIB_API int __cdecl dbcursorcolinfo(PDBCURSOR, int column, LPSTR colname, LPINT coltype, int* collen, LPINT usertype);
DBLIB_API int __cdecl dbcursorfetch(PDBCURSOR, int fetchtype, int rownum);
DBLIB_API int __cdecl dbcursorfetchex(PDBCURSOR, int, int, int, int);
DBLIB_API int __cdecl dbcursorinfo(PDBCURSOR, int* ncols, int* nrows);
DBLIB_API int __cdecl dbcursorinfoex(PDBCURSOR, LPDBCURSORINFO);
DBLIB_API PDBCURSOR __cdecl dbcursoropen(PDBPROCESS, LPCSTR stmt, int scrollopt, int concuropt, int nrows, int* pstatus);
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
DBLIB_API BYTE* __cdecl dbgetuserdata(PDBPROCESS);
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
DBLIB_API int __cdecl dbwritepage(PDBPROCESS dbproc, LPCSTR dbname, int fileno, int pageno, int size, LPBYTE buf);
DBLIB_API int __cdecl dbwritetext(PDBPROCESS dbproc, LPCSTR objname, BYTE* textptr, DBTINYINT textptrlen, BYTE* timestamp, BOOL log, int size, LPCBYTE text);
DBLIB_API int __cdecl dbupdatetext(PDBPROCESS dbproc, LPCSTR objname, BYTE* textptr, BYTE* timestamp, int, int, int, LPCSTR, int size, BYTE* text);
DBLIB_API void __cdecl dbwinexit();
DBLIB_API int __cdecl msdblib_datecrack(DBPROCESS* dbproc, DBDATEREC* di, DBDATETIME* datetime);
DBLIB_API int __cdecl abort_xact(db_process_t* dbproc, int Value);
DBLIB_API int __cdecl build_xact_string(const char* xact_name, const char* service_name, int commid, char* lpResult);
DBLIB_API int __cdecl close_commit(db_process_t* connect);
DBLIB_API void __cdecl dbunlocklib();
DBLIB_API db_process_t* __cdecl open_commit(db_login_t* login, const char* servername);
DBLIB_API int __cdecl remove_xact(db_process_t* connect, int commid, int n);
DBLIB_API int __cdecl start_xact(db_process_t* connect, const char* application_name, const char* xact_name, int site_count);
DBLIB_API int __cdecl stat_xact(db_process_t* connect, int commid);
DBLIB_API int __cdecl dbcolntype(db_process_t* connect, int col);
DBLIB_API int __cdecl dbbcmd(db_process_t* dbproc, const char* cmd, size_t Size);


int __cdecl ConvertToFloat(db_process_t* dbproc, int dtIn, BYTE* Src, int Length, int dtOut, double* lpValue);
int __cdecl ConvertToInt(db_process_t* dbproc, int dtIn, BYTE* Src, int Length, int dtOut, void* lpValue);
int __cdecl ConvertToLong(db_process_t* dbproc, int dtIn, BYTE* Src, int Length, int dtOut, void* lpValue);
int __cdecl ConvertToChar(db_process_t* dbproc, int dtIn, BYTE* Src, int Length, int dtOut, char* lpOutString, int Outlength);
int __cdecl ConvertToChar2(db_process_t* dbproc, int dtIn, BYTE* Src, int Length, int dtOut, char* lpOutString, int Outlength, int* lpSize);
int __cdecl ConvertToBinary(db_process_t* dbproc, int dtIn, BYTE* Src, int Length, int dtOut, void* lpOutBuffer, int Outlength);
int __cdecl ConvertToDateTime(db_process_t* dbproc, int dtIn, SmallDateTime* Src, int Length, int dtOut, DBDATETIME* datetime);
int __cdecl ConvertToBit(db_process_t* dbproc, int dtIn, BYTE* Src, int Length, int dtOut, char* lpBuffer);
int __cdecl ConvertToMoney(db_process_t* dbproc, int dtIn, BYTE* Src, int Length, int dtOut, DBMONEY* lpBuffer, int OutLength);
int __cdecl ConvertToReal(db_process_t* dbproc, int dtIn, BYTE* Src, int Length, int dtOut, float* lpValue);
int __cdecl ConvertToSmallMoney(db_process_t* dbproc, int dtIn, BYTE* Src, int Length, int dtOut, DWORD* lpMoney, int OutLength);
int __cdecl ConvertToSmallDate(db_process_t* dbproc, int dtIn, SmallDateTime* Src, int Size, int dtOut, SmallDateTime* date);
int __cdecl ConvertToNumericDecimal(db_process_t* dbproc, int dtIn, BYTE* Src, int Length, int dtOut, DBNUMERIC* lpDecimal, int OutLength);



#ifdef __cplusplus
}
#endif

#endif // _dblib_h_

