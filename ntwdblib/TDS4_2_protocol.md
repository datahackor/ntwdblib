# 4.2

## Login Request
<PacketHeader>
     <Type>
       <BYTE>02 </BYTE>
     </Type>
     <Status>
       <BYTE>01 </BYTE>
     </Status>
     <Length>
       <BYTE>02 </BYTE>
       <BYTE>3F </BYTE>
     </Length>
     <SPID>
       <BYTE>00 </BYTE>
       <BYTE>00 </BYTE>
     </SPID>
     <Packet>
       <BYTE>01 </BYTE>
     </Packet>
     <Window>
       <BYTE>00 </BYTE>
     </Window>
   </PacketHeader>
   <PacketData>
     <Login>
       <HostName>
         <BYTES>53 51 4C 50 4F 44 30 36 38 2D 30 35 00 00 
 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 </BYTES>
       </HostName>
         <cbHostName>
           <BYTE>0C </BYTE>
         </cbHostName>
       <UserName>
         <BYTES>73 61 00 00 00 00 00 00 00 00 00 00 00 00 
 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 </BYTES>
       </UserName>
         <cbUserName>
           <BYTE>02 </BYTE>
         </cbUserName>
       <Password>
         <BYTES>59 75 6B 6F 6E 39 30 30 00 00 00 00 00 00 
 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 </BYTES>
       </Password>
         <cbPassword>
           <BYTE>08 </BYTE>
         </cbPassword>
       <HostProc>
         <BYTES>00 00 00 00 00 00 00 00 </BYTES>
       </HostProc>
         <FRESERVEDBYTE>
           <BYTES>00 00 00 00 00 00 00 00 00 00 00 00 00 00 
 00 00 </BYTES>
         </FRESERVEDBYTE>
         <AppType>
           <BYTES>00 00 00 00 00 00 </BYTES>
         </AppType>
         <cbHostProc>
           <BYTE>00 </BYTE>
         </cbHostProc>
       <lInt2>
         <BYTE>03 </BYTE>
       </lInt2>
       <lInt4>
         <BYTE>01 </BYTE>
       </lInt4>
       <lChar>
         <BYTE>06 </BYTE>
       </lChar>
       <lFloat>
         <BYTE>0A </BYTE>
       </lfloat>
       <FRESERVEDBYTE>
         <BYTE>09 </BYTE>
       </FRESERVEDBYTE>
       <lUseDb>
         <BYTE>01 </BYTE>
       </lUseDb>
       <lDumpLoad>
         <BYTE>01 </BYTE>
       </lDumpLoad>
       <lInterface>
         <BYTE>00 </BYTE>
       </lInterface>
       <lType>
         <BYTE>00 </BYTE>
       </lType>
       <FRESERVEDBYTE>
         <BYTES>00 00 00 00 00 00 </BYTES>
       </FRESERVEDBYTE>
       <lDBLIBFlags>
         <BYTE>00 </BYTE>
       </lDBLIBFlags>
       <AppName>
         <BYTES>4F 53 51 4C 2D 33 32 00 00 00 00 00 00 00 00 
 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 </BYTES>
       </AppName>
         <cbAppName>
           <BYTE>07 </BYTE>
         </cbAppName>
       <ServerName>
         <BYTES>00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 
 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 </BYTES>
       </ServerName>
         <cbServerName>
           <BYTE>00 </BYTE>
         </cbServerName>
       <RemotePassword>
         <BYTES>00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 
 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 
 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 
 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 
 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 
 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 
 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 
 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 
 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 
 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 
 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 
 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 
 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 </BYTES>
       </RemotePassword>
         <cbRemotePassword>
           <BYTE>00 </BYTE>
         </cbRemotePassword>
       <TDSVersion>
         <BYTES>04 02 00 00 </BYTES>
       </TDSVersion>
       <ProgName>
         <BYTES>4D 53 44 42 4C 49 42 00 00 00 </BYTES>
       </ProgName>
         <cbProgName>
           <BYTE>07 </BYTE>
         </cbProgName>
       <ProgVersion>
         <BYTES>06 00 00 00 </BYTES>
       </ProgVersion>
       <FRESERVEDBYTE>
         <BYTE>00 </BYTE>
       </FRESERVEDBYTE>
       <lFloat4>
         <BYTE>0D </BYTE>
       </lFloat4>
       <lDate4>
         <BYTE>11 </BYTE>
       </lDate4>
       <Language>
         <BYTES>00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 
 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 </BYTES>
         <cbLanguage>
           <BYTE>00 </BYTE>
         </cbLanguage>
       </Language>
       <SetLang>
         <BYTE>01 </BYTE>
       </SetLang>
       <FRESERVEDBYTES>
         <BYTES>00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 
 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 
 00 00 00 00 00 00 00 00 00 00 </BYTES>
       </FRESERVEDBYTES>
       <PacketSize>
         <BYTES>35 31 32 00 00 00 </BYTES>
       </PacketSize>
         <cbPacketSize>
           <BYTE>03 </BYTE>
         </cbPacketSize>
       <Padding>
         <BYTES>00 00 00 </BYTES>
       </Padding>
     </Login>
   </PacketData>


## Login Response

04 01 00 e7 00 33 01 00 e3 12 00 01 09 61 64 76  ...?.3..?....adv
61 6e 74 61 67 65 06 6d 61 73 74 65 72 ab 36 00  antage.master?6.
45 16 00 00 02 00 24 00 d2 d1 bd ab ca fd be dd  E.....$.????????
bf e2 c9 cf cf c2 ce c4 b8 fc b8 c4 ce aa 20 27  ?????????????? '
61 64 76 61 6e 74 61 67 65 27 a1 a3 06 4f 55 4d  advantage'??.OUM
50 2d 44 00 01 00 e3 0d 00 02 0a 75 73 5f 65 6e  P-D...?....us_en
67 6c 69 73 68 00 ab 39 00 47 16 00 00 01 00 27  glish.?9.G.....'
00 43 68 61 6e 67 65 64 20 6c 61 6e 67 75 61 67  .Changed languag
65 20 73 65 74 74 69 6e 67 20 74 6f 20 75 73 5f  e setting to us_
65 6e 67 6c 69 73 68 2e 06 4f 55 4d 50 2d 44 00  english..OUMP-D.
01 00 e3 09 00 03 05 63 70 39 33 36 01 00 ad 20  ..?....cp936..? 
00 01 04 02 00 00 16 4d 69 63 72 6f 73 6f 66 74  .......Microsoft
20 53 51 4c 20 53 65 72 76 65 72 00 00 5f 0b 00   SQL Server.._..
ff e3 0a 00 04 04 34 30 39 36 03 35 31 32 fd 00  .?....4096.512?.

   <PacketHeader >
     <Type>
       <BYTE>04 </BYTE>
     </Type>
     <Status>
       <BYTE>01 </BYTE>
     </Status>
     <Length>
       <BYTE>00 </BYTE>
       <BYTE>E8 </BYTE>
     </Length>
     <SPID>
       <BYTE>00 </BYTE>
       <BYTE>00 </BYTE>
     </SPID>
     <Packet>
       <BYTE>01 </BYTE>
     </Packet>
     <Window>
       <BYTE>00 </BYTE>
     </Window>
   </PacketHeader >
   <PacketData>
     <TableResponse>
       <ENVCHANGE>
         <TokenType>
           <BYTE>E3 </BYTE>
         </TokenType>
         <Length>
           <USHORT>0F 00 </USHORT>
         </Length>
         <EnvChangeData>
           <BYTES>01 06 6D 61 73 74 65 72 06 6D 61 73 74 65 72 </BYTES>
         </EnvChangeData>
       </ENVCHANGE>
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
       <ENVCHANGE>
         <TokenType>
           <BYTE>E3 </BYTE>
         </TokenType>
         <Length>
           <USHORT>0D 00 </USHORT>
         </Length>
         <EnvChangeData>
           <BYTES ascii="..us_english">02 0A 75 73 5F 65 6E 67 6C 69 73 68 00 </BYTES>
         </EnvChangeData>
       </ENVCHANGE>
       <INFO>
         <TokenType>
           <BYTE>AB </BYTE>
         </TokenType>
         <Length>
           <USHORT>39 00 </USHORT>
         </Length>
         <Number>
           <LONG>47 16 00 00 </LONG>
         </Number>
         <State>
           <BYTE>01 </BYTE>
         </State>
         <Class>
           <BYTE>00 </BYTE>
         </Class>
         <MsgText>
           <US_VARCHAR>
             <USHORT>27 00 </USHORT>
             <BYTES ascii="Changed language setting to 
 us_english.">43 68 61 6E 67 65 64 20 6C 61 6E 67 75 61 
 67 65 20 73 65 74 74 69 6E 67 20 74 6F 20 75 73 5F 65 6E 
 67 6C 69 73 68 2E </BYTES>
           </US_VARCHAR>
         </MsgText>
         <ServerName>
           <B_VARCHAR>
             <BYTE>06 </BYTE>
             <BYTES ascii="OUMP-D">4f 55 4d 50 2d 44 </BYTES>
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
       <ENVCHANGE>
         <TokenType>
           <BYTE>E3 </BYTE>
         </TokenType>
         <Length>
           <USHORT>09 00 </USHORT>
         </Length>
         <EnvChangeData>
           <BYTES>03 05 63 70 39 33 36 01 00 </BYTES> // "cp936"
         </EnvChangeData>
       </ENVCHANGE>
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
       <ENVCHANGE>
         <TokenType>
           <BYTE>E3 </BYTE>
         </TokenType>
         <Length>
           <USHORT>09 00 </USHORT>
         </Length>
         <EnvChangeData>
           <BYTES>04 04 34 30 39 36 03 35 31 32</BYTES> // "4096","512"
         </EnvChangeData>
       </ENVCHANGE>
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
     </TableResponse>
   </PacketData>