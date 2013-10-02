# -*- coding: binary -*-
module Rex
module Post
module Meterpreter
module Extensions
module Stdapi
module Railgun
module Def

class Def_wininet
	#
	# These definitions were initially created automatically by tools/rip_msdn_to_railgun
	#   but some have been manually corrected.
	# Since many of these function are very rarely used, we comment many of them out
	#  Those commented out have not been checked for accuracy
	# @todo fix variable names that have retained their prefixes (like , lp etc)

	# @see InternetErrorCodes http://msdn.microsoft.com/en-us/library/windows/desktop/aa385465(v=vs.85).aspx
	# @see http://msdn.microsoft.com/en-us/library/windows/desktop/aa385132(v=vs.85).aspx
	INTERNET_BUFFERS = [
  	[:Header, :LPCTSTR],
    [:HeadersLength, :DWORD],
    [:HeadersTotal, :DWORD],
    [:Buffer, :LPVOID],
    [:BufferLength, :DWORD],
    [:BufferTotal, :DWORD],
    [:OffsetLow, :DWORD],
    [:OffsetHight, :DWORD]
	]
	def self.create_dll(dll_path = 'wininet')
		dll = DLL.new(dll_path, ApiConstants.manager)

		# dll.add_function('CleanupCredentialCache', 'BOOL', [
		# ])

		# dll.add_function('CommitUrlCacheEntryA', 'BOOL', [
		# 	['PDWORD', 'UrlName', 'in'],
		# 	['PDWORD', 'LocalFileName', 'in'],
		# 	['QWORD', 'ExpireTime', 'in'],
		# 	['QWORD', 'LastModifiedTime', 'in'],
		# 	['DWORD', 'CacheEntryType', 'in'],
		# 	['PDWORD', 'HeaderInfo', 'in'],
		# 	['DWORD', 'HeaderInfo', 'in'],
		# 	['PDWORD', 'FileExtension', 'in'],
		# 	['PDWORD', 'OriginalUrl', 'in']
  #   ])

		# dll.add_function('CommitUrlCacheEntryW', 'BOOL', [
		# 	['PDWORD', 'UrlName', 'in'],
		# 	['PDWORD', 'LocalFileName', 'in'],
		# 	['QWORD', 'ExpireTime', 'in'],
		# 	['QWORD', 'LastModifiedTime', 'in'],
		# 	['DWORD', 'CacheEntryType', 'in'],
		# 	['PDWORD', 'HeaderInfo', 'in'],
		# 	['DWORD', 'HeaderInfo', 'in'],
		# 	['PDWORD', 'FileExtension', 'in'],
		# 	['PDWORD', 'OriginalUrl', 'in']
  #   ])

		# dll.add_function('CreateMD5SSOHash', 'BOOL', [
		# 	['PWCHAR', 'ChallengeInfo', 'in'],
		# 	['PWCHAR', 'Realm', 'in'],
		# 	['PWCHAR', 'Target', 'in'],
		# 	['PBLOB', 'HexHash', 'out']
  #   ])

		# dll.add_function('CreateUrlCacheEntry', 'BOOL', [
		# 	['PDWORD', 'UrlName', 'in'],
		# 	['DWORD', 'ExpectedFileSize', 'in'],
		# 	['PDWORD', 'FileExtension', 'in'],
		# 	['DWORD', 'FileName', 'out'],
		# 	['DWORD', 'Reserved', 'in']
  #   ])

		# dll.add_function('CreateUrlCacheGroup', 'UNK', [
		# 	['DWORD', 'Flags', 'in'],
		# 	['PDWORD', 'Reserved', 'in']
  #   ])

		# dll.add_function('DeleteUrlCacheEntry', 'BOOL', [
		# 	['PDWORD', 'UrlName', 'in']
  #   ])

		# dll.add_function('DeleteUrlCacheGroup', 'BOOL', [
		# 	['UNK', 'GroupId', 'in'],
		# 	['DWORD', 'Flags', 'in'],
		# 	['PDWORD', 'Reserved', 'in']
  #   ])

		# dll.add_function('DetectAutoProxyUrl', 'BOOL', [
		# 	['PDWORD', 'AutoProxyUrl', 'inout'],
		# 	['DWORD', 'AutoProxyUrlLength', 'in'],
		# 	['DWORD', 'DetectFlags', 'in']
  #   ])

		# dll.add_function('FindCloseUrlCache', 'BOOL', [
		# 	['DWORD', 'EnumHandle', 'in']
  #   ])

		# dll.add_function('FindFirstUrlCacheEntry', 'DWORD', [
		# 	['PDWORD', 'UrlSearchPattern', 'in'],
		# 	['UNK', 'FirstCacheEntryInfo', 'out'],
		# 	['PDWORD', 'CacheEntryInfo', 'inout']
  #   ])

		# dll.add_function('FindFirstUrlCacheEntryEx', 'DWORD', [
		# 	['PDWORD', 'UrlSearchPattern', 'in'],
		# 	['DWORD', 'Flags', 'in'],
		# 	['DWORD', 'Filter', 'in'],
		# 	['UNK', 'GroupId', 'in'],
		# 	['UNK', 'FirstCacheEntryInfo', 'out'],
		# 	['PDWORD', 'EntryInfo', 'inout'],
		# 	['PDWORD', 'GroupAttributes', 'in'],
		# 	['PDWORD', 'GroupAttributes', 'in'],
		# 	['PDWORD', 'Reserved', 'in']
  #   ])

		# dll.add_function('FindFirstUrlCacheGroup', 'DWORD', [
		# 	['DWORD', 'Flags', 'in'],
		# 	['DWORD', 'Filter', 'in'],
		# 	['PDWORD', 'SearchCondition', 'in'],
		# 	['DWORD', 'SearchCondition', 'in'],
		# 	['PBLOB', 'GroupId', 'out'],
		# 	['PDWORD', 'Reserved', 'in']
  #   ])

		# dll.add_function('FindNextUrlCacheEntry', 'BOOL', [
		# 	['DWORD', 'EnumHandle', 'in'],
		# 	['UNK', 'NextCacheEntryInfo', 'out'],
		# 	['PDWORD', 'CacheEntryInfo', 'inout']
  #   ])

		# dll.add_function('FindNextUrlCacheEntryEx', 'BOOL', [
		# 	['DWORD', 'EnumHandle', 'in'],
		# 	['PDWORD', 'NextCacheEntryInfo', 'inout'],
		# 	['PDWORD', 'EntryInfo', 'inout'],
		# 	['PDWORD', 'GroupAttributes', 'in'],
		# 	['PDWORD', 'GroupAttributes', 'in'],
		# 	['PDWORD', 'Reserved', 'in']
  #   ])

		# dll.add_function('FindNextUrlCacheGroup', 'BOOL', [
		# 	['DWORD', 'Find', 'in'],
		# 	['PBLOB', 'GroupId', 'out'],
		# 	['PDWORD', 'Reserved', 'in']
  #   ])

		# dll.add_function('FtpCommand', 'BOOL', [
		# 	['HANDLE', 'Connect', 'in'],
		# 	['UNK', 'ExpectResponse', 'in'],
		# 	['DWORD', 'Flags', 'in'],
		# 	['PDWORD', 'Command', 'in'],
		# 	['PDWORD', 'Context', 'in'],
		# 	['PBLOB', 'FtpCommand', 'out']
  #   ])

		# dll.add_function('FtpCreateDirectory', 'BOOL', [
		# 	['HANDLE', 'Connect', 'in'],
		# 	['PDWORD', 'Directory', 'in']
  #   ])

		# dll.add_function('FtpDeleteFile', 'BOOL', [
		# 	['HANDLE', 'Connect', 'in'],
		# 	['PDWORD', 'FileName', 'in']
  #   ])

		# dll.add_function('FtpFindFirstFile', 'DWORD', [
		# 	['HANDLE', 'Connect', 'in'],
		# 	['PDWORD', 'SearchFile', 'in'],
		# 	['UNK', 'FindFileData', 'out'],
		# 	['DWORD', 'Flags', 'in'],
		# 	['PDWORD', 'Context', 'in']
  #   ])

		# dll.add_function('FtpGetCurrentDirectory', 'BOOL', [
		# 	['HANDLE', 'Connect', 'in'],
		# 	['DWORD', 'CurrentDirectory', 'out'],
		# 	['PDWORD', 'CurrentDirectory', 'inout']
  #   ])

		# dll.add_function('FtpGetFile', 'BOOL', [
		# 	['HANDLE', 'Connect', 'in'],
		# 	['PDWORD', 'RemoteFile', 'in'],
		# 	['PDWORD', 'NewFile', 'in'],
		# 	['UNK', 'FailIfExists', 'in'],
		# 	['DWORD', 'FlagsAndAttributes', 'in'],
		# 	['DWORD', 'Flags', 'in'],
		# 	['PDWORD', 'Context', 'in']
  #   ])

		# dll.add_function('FtpGetFileSize', 'UNK', [
		# 	['HANDLE', 'File', 'in'],
		# 	['PBLOB', 'FileSizeHigh', 'out']
  #   ])

		# dll.add_function('FtpOpenFile', 'HANDLE', [
		# 	['HANDLE', 'Connect', 'in'],
		# 	['PDWORD', 'FileName', 'in'],
		# 	['DWORD', 'Access', 'in'],
		# 	['DWORD', 'Flags', 'in'],
		# 	['PDWORD', 'Context', 'in']
  #   ])

		# dll.add_function('FtpPutFile', 'BOOL', [
		# 	['HANDLE', 'Connect', 'in'],
		# 	['PDWORD', 'LocalFile', 'in'],
		# 	['PDWORD', 'NewRemoteFile', 'in'],
		# 	['DWORD', 'Flags', 'in'],
		# 	['PDWORD', 'Context', 'in']
  #   ])

		# dll.add_function('FtpRemoveDirectory', 'BOOL', [
		# 	['HANDLE', 'Connect', 'in'],
		# 	['PDWORD', 'Directory', 'in']
  #   ])

		# dll.add_function('FtpRenameFile', 'BOOL', [
		# 	['HANDLE', 'Connect', 'in'],
		# 	['PDWORD', 'Existing', 'in'],
		# 	['PDWORD', 'New', 'in']
  #   ])

		# dll.add_function('FtpSetCurrentDirectory', 'BOOL', [
		# 	['HANDLE', 'Connect', 'in'],
		# 	['PDWORD', 'Directory', 'in']
  #   ])

		# dll.add_function('GetUrlCacheConfigInfo', 'BOOL', [
		# 	['PDWORD', 'CacheConfigInfo', 'inout'],
		# 	['PDWORD', 'CacheConfigInfo', 'in'],
		# 	['DWORD', 'FieldControl', 'in']
  #   ])

		# dll.add_function('GetUrlCacheEntryInfo', 'BOOL', [
		# 	['PDWORD', 'UrlName', 'in'],
		# 	['UNK', 'CacheEntryInfo', 'out'],
		# 	['PDWORD', 'CacheEntryInfo', 'inout']
  #   ])

		# dll.add_function('GetUrlCacheEntryInfoEx', 'BOOL', [
		# 	['PDWORD', 'Url', 'in'],
		# 	['PDWORD', 'CacheEntryInfo', 'inout'],
		# 	['PDWORD', 'CacheEntryInfo', 'inout'],
		# 	['PDWORD', 'RedirectUrl', 'in'],
		# 	['PDWORD', 'RedirectUrl', 'in'],
		# 	['PDWORD', 'Reserved', 'in'],
		# 	['DWORD', 'Flags', 'in']
  #   ])

		# dll.add_function('GetUrlCacheGroupAttribute', 'BOOL', [
		# 	['UNK', 'gid', 'in'],
		# 	['DWORD', 'Flags', 'in'],
		# 	['DWORD', 'Attributes', 'in'],
		# 	['UNK', 'GroupInfo', 'out'],
		# 	['PDWORD', 'GroupInfo', 'inout'],
		# 	['PDWORD', 'Reserved', 'in']
  #   ])

		# dll.add_function('GopherAttributeEnumerator', 'BOOL', [
		# 	['UNK', 'unknown', 'unk'],
		# 	['UNK', 'unknown', 'unk']
  #   ])

		# dll.add_function('GopherCreateLocator', 'BOOL', [
		# 	['PDWORD', 'Host', 'in'],
		# 	['UNK', 'ServerPort', 'in'],
		# 	['PDWORD', 'DisplayString', 'in'],
		# 	['PDWORD', 'SelectorString', 'in'],
		# 	['DWORD', 'GopherType', 'in'],
		# 	['DWORD', 'Locator', 'out'],
		# 	['PDWORD', 'BufferLength', 'inout']
  #   ])

		# dll.add_function('GopherFindFirstFile', 'DWORD', [
		# 	['HANDLE', 'Connect', 'in'],
		# 	['PDWORD', 'Locator', 'in'],
		# 	['PDWORD', 'SearchString', 'in'],
		# 	['UNK', 'FindData', 'out'],
		# 	['DWORD', 'Flags', 'in'],
		# 	['PDWORD', 'Context', 'in']
  #   ])

		# dll.add_function('GopherGetAttribute', 'BOOL', [
		# 	['HANDLE', 'Connect', 'in'],
		# 	['PDWORD', 'Locator', 'in'],
		# 	['PDWORD', 'AttributeName', 'in'],
		# 	['UNK', 'Buffer', 'out'],
		# 	['DWORD', 'BufferLength', 'in'],
		# 	['PBLOB', 'CharactersReturned', 'out'],
		# 	['UNK', 'Enumerator', 'in'],
		# 	['PDWORD', 'Context', 'in']
  #   ])

		# dll.add_function('GopherGetLocatorType', 'BOOL', [
		# 	['PDWORD', 'Locator', 'in'],
		# 	['PBLOB', 'GopherType', 'out']
  #   ])

		# dll.add_function('GopherOpenFile', 'HANDLE', [
		# 	['HANDLE', 'Connect', 'in'],
		# 	['PDWORD', 'Locator', 'in'],
		# 	['PDWORD', 'View', 'in'],
		# 	['DWORD', 'Flags', 'in'],
		# 	['PDWORD', 'Context', 'in']
  #   ])

		##########################################################
		#
		#                   Http* Functions
		#
		##########################################################

		dll.add_function('HttpAddRequestHeadersA', 'BOOL', [
			['HANDLE', 'Request', 'in'],
			['PCHAR', 'Headers', 'in'],
			['DWORD', 'HeadersLength', 'in'],
			['DWORD', 'Modifiers', 'in']
    ])

		dll.add_function('HttpAddRequestHeadersW', 'BOOL', [
			['HANDLE', 'Request', 'in'],
			['PWCHAR', 'Headers', 'in'],
			['DWORD', 'HeadersLength', 'in'],
			['DWORD', 'Modifiers', 'in']
    ])

		dll.add_function('HttpEndRequestA', 'BOOL', [
			['HANDLE', 'Request', 'in'],
			['PBLOB', 'BuffersOut', 'out'],
			['DWORD', 'Flags', 'in'],
			['PDWORD', 'Context', 'in']
		])

		dll.add_function('HttpEndRequestW', 'BOOL', [
			['HANDLE', 'Request', 'in'],
			['PBLOB', 'BuffersOut', 'out'],
			['DWORD', 'Flags', 'in'],
			['PDWORD', 'Context', 'in']
		])

		dll.add_function('HttpOpenRequestA', 'HANDLE', [
			['HANDLE', 'Connect', 'in'],
			['PCHAR', 'Verb', 'in'],
			['PCHAR', 'ObjectName', 'in'],
			['PCHAR', 'Version', 'in'],
			['PCHAR', 'Referer', 'in'],
			['PBLOB', 'AcceptTypes', 'in'], # LPCTSTR *lplpszAcceptTypes
			['DWORD', 'Flags', 'in'],
			['PDWORD', 'Context', 'in'] # _In_  DWORD_PTR dwContext
    ])

		dll.add_function('HttpOpenRequestW', 'HANDLE', [
			['HANDLE', 'Connect', 'in'],
			['PWCHAR', 'Verb', 'in'],
			['PWCHAR', 'ObjectName', 'in'],
			['PWCHAR', 'Version', 'in'],
			['PWCHAR', 'Referer', 'in'],
			['PBLOB', 'AcceptTypes', 'in'], # LPCTSTR *lplpszAcceptTypes
			['DWORD', 'Flags', 'in'],
			['PDWORD', 'Context', 'in'] # _In_  DWORD_PTR dwContext
    ])

		dll.add_function('HttpQueryInfoA', 'BOOL', [
			['HANDLE', 'Request', 'in'],
			['DWORD', 'InfoLevel', 'in'],
			['LPVOID', 'Buffer', 'inout'], # like WSAIoctl in ws2_32.  Must not be null
			['PDWORD', 'BufferLength', 'inout'], # like WSALookupServiceNextA in ws2_32
			['DWORD', 'Index', 'inout']
		])

		dll.add_function('HttpQueryInfoW', 'BOOL', [
			['HANDLE', 'Request', 'in'],
			['DWORD', 'InfoLevel', 'in'],
			['LPVOID', 'Buffer', 'inout'], # like WSAIoctl in ws2_32.  Must not be null
			['PDWORD', 'BufferLength', 'inout'], # like WSALookupServiceNextA in ws2_32
			['PDWORD', 'Index', 'inout']
		])

		dll.add_function('HttpSendRequestA', 'BOOL', [
			['HANDLE', 'Request', 'in'],
			['PCHAR', 'Headers', 'in'],
			['DWORD', 'HeadersLength', 'in'], # in TCHARs, -1
			['PBLOB', 'Optional', 'in'], # for add'l data like for a POST or PUT, nil
			['DWORD', 'OptionalLength', 'in'] # in bytes, 0 if above is nil
		])

		dll.add_function('HttpSendRequestW', 'BOOL', [
			['HANDLE', 'Request', 'in'],
			['PWCHAR', 'Headers', 'in'],
			['DWORD', 'HeadersLength', 'in'],
			['PBLOB', 'Optional', 'in'],
			['DWORD', 'OptionalLength', 'in']
		])
		# recommend you use HttpSendRequest, not the Ex version, to avoid complex data structs
		dll.add_function('HttpSendRequestExA', 'BOOL', [
			['HANDLE', 'Request', 'in'],
			['PBLOB', 'BuffersIn', 'in'],
			['PBLOB', 'BuffersOut', 'out'],
			['DWORD', 'Flags', 'in'],
			['PDWORD', 'Context', 'in']
		])

		dll.add_function('HttpSendRequestExW', 'BOOL', [
			['HANDLE', 'Request', 'in'],
			['PBLOB', 'BuffersIn', 'in'],
			['PBLOB', 'BuffersOut', 'out'],
			['DWORD', 'Flags', 'in'],
			['PDWORD', 'Context', 'in']
		])

		##########################################################
		#
		#                Internet* Functions
		#
		##########################################################

		# Returns ERROR_SUCCESS or a system error code
		dll.add_function('InternetAttemptConnect', 'HANDLE', [
			['DWORD', 'Reserved', 'in'] # must be 0
    ])

		# dll.add_function('InternetAutodial', 'BOOL', [
		# 	['DWORD', 'Flags', 'in'],
		# 	['DWORD', 'Parent', 'in']
  #   ])

		# dll.add_function('InternetAutodialHangup', 'BOOL', [
		# 	['DWORD', 'Reserved', 'in']
  #   ])

		# dll.add_function('InternetCanonicalizeUrl', 'BOOL', [
		# 	['PDWORD', 'Url', 'in'],
		# 	['DWORD', 'Buffer', 'out'],
		# 	['PDWORD', 'BufferLength', 'inout'],
		# 	['DWORD', 'Flags', 'in']
  #   ])

		dll.add_function('InternetCheckConnection', 'BOOL', [
			['PCHAR', 'Url', 'in'],
			['DWORD', 'Flags', 'in'], # 0 or FLAG_ICC_FORCE_CONNECTION
			['DWORD', 'Reserved', 'in'] # must be 0
    ])

		# dll.add_function('InternetClearAllPerSiteCookieDecisions', 'BOOL', [
		# ])

		dll.add_function('InternetCloseHandle', 'BOOL', [
			['HANDLE', 'Internet', 'in']
    ])

		# dll.add_function('InternetCombineUrl', 'BOOL', [
		# 	['PDWORD', 'BaseUrl', 'in'],
		# 	['PDWORD', 'RelativeUrl', 'in'],
		# 	['DWORD', 'Buffer', 'out'],
		# 	['PDWORD', 'BufferLength', 'inout'],
		# 	['DWORD', 'Flags', 'in']
  #   ])

		# dll.add_function('InternetConfirmZoneCrossing', 'UNK', [
		# 	['DWORD', 'Wnd', 'in'],
		# 	['PDWORD', 'UrlPrev', 'in'],
		# 	['PDWORD', 'UrlNew', 'in'],
		# 	['UNK', 'Post', 'in']
  #   ])

		dll.add_function('InternetConnectA', 'HANDLE', [
			['HANDLE', 'Internet', 'in'],
			['PCHAR', 'ServerName', 'in'],
			['DWORD', 'ServerPort', 'in'], # INTERNET_PORT nServerPort
			['PCHAR', 'Username', 'in'],
			['PCHAR', 'Password', 'in'],
			['DWORD', 'Service', 'in'],
			['DWORD', 'Flags', 'in'],
			['PDWORD', 'Context', 'in']
    ])

		dll.add_function('InternetConnectW', 'HANDLE', [
			['HANDLE', 'Internet', 'in'],
			['PWCHAR', 'ServerName', 'in'],
			['DWORD', 'ServerPort', 'in'], # INTERNET_PORT nServerPort
			['PWCHAR', 'Username', 'in'],
			['PWCHAR', 'Password', 'in'],
			['DWORD', 'Service', 'in'],
			['DWORD', 'Flags', 'in'],
			['PDWORD', 'Context', 'in']
    ])

		# dll.add_function('InternetCrackUrl', 'BOOL', [
		# 	['PDWORD', 'Url', 'in'],
		# 	['DWORD', 'UrlLength', 'in'],
		# 	['DWORD', 'Flags', 'in'],
		# 	['PDWORD', 'UrlComponents', 'inout']
  #   ])

		# dll.add_function('InternetCreateUrl', 'BOOL', [
		# 	['PDWORD', 'UrlComponents', 'in'],
		# 	['DWORD', 'Flags', 'in'],
		# 	['DWORD', 'Url', 'out'],
		# 	['PDWORD', 'UrlLength', 'inout']
  #   ])

		# dll.add_function('InternetDeInitializeAutoProxyDll', 'BOOL', [
		# 	['PDWORD', 'Mime', 'in'],
		# 	['DWORD', 'Reserved', 'in']
  #   ])

		# dll.add_function('InternetDial', 'UNK', [
		# 	['DWORD', 'Parent', 'in'],
		# 	['PDWORD', 'EntryName', 'in'],
		# 	['DWORD', 'Flags', 'in'],
		# 	['PBLOB', 'Connection', 'out'],
		# 	['DWORD', 'Reserved', 'in']
  #   ])

		# dll.add_function('InternetEnumPerSiteCookieDecision', 'BOOL', [
		# 	['DWORD', 'SiteName', 'out'],
		# 	['PDWORD', 'SiteNameSize', 'inout'],
		# 	['PBLOB', 'Decision', 'out'],
		# 	['DWORD', 'Index', 'in']
  #   ])

		# dll.add_function('InternetErrorDlg', 'UNK', [
		# 	['DWORD', 'Wnd', 'in'],
		# 	['HANDLE', 'Request', 'inout'],
		# 	['DWORD', 'Error', 'in'],
		# 	['DWORD', 'Flags', 'in'],
		# 	['PDWORD', 'Data', 'inout']
  #   ])

		# dll.add_function('InternetFindNextFile', 'BOOL', [
		# 	['DWORD', 'Find', 'in'],
		# 	['UNK', 'FindData', 'out']
  #   ])

		dll.add_function('InternetGetConnectedState', 'BOOL', [
			['PDWORD', 'Flags', 'out'],
			['DWORD', 'Reserved', 'in'] # must be 0
    ])

		dll.add_function('InternetGetConnectedStateExA', 'BOOL', [
			['PDWORD', 'Flags', 'out'],
			['PCHAR', 'ConnectionName', 'out'],
			['DWORD', 'NameLen', 'in'],
			['DWORD', 'Reserved', 'in'] # must be null
    ])

    dll.add_function('InternetGetConnectedStateExW', 'BOOL', [
      ['PDWORD', 'Flags', 'out'],
      ['PWCHAR', 'ConnectionName', 'out'],
      ['DWORD', 'NameLen', 'in'],
      ['DWORD', 'Reserved', 'in'] # must be null
    ])

		# dll.add_function('InternetGetCookie', 'BOOL', [
		# 	['PDWORD', 'Url', 'in'],
		# 	['PDWORD', 'CookieName', 'in'],
		# 	['DWORD', 'CookieData', 'out'],
		# 	['PDWORD', 'Size', 'inout']
  #   ])

		# dll.add_function('InternetGetCookieEx', 'BOOL', [
		# 	['PDWORD', 'URL', 'in'],
		# 	['PDWORD', 'CookieName', 'in'],
		# 	['PDWORD', 'CookieData', 'inout'],
		# 	['PDWORD', 'Size', 'inout'],
		# 	['DWORD', 'Flags', 'in'],
		# 	['PDWORD', 'Reserved', 'in']
  #   ])

		dll.add_function('InternetGetLastResponseInfoA', 'BOOL', [
			['PDWORD', 'Error', 'out'],
			['PCHAR', 'Buffer', 'out'],
			['PDWORD', 'BufferLength', 'inout']
    ])

    dll.add_function('InternetGetLastResponseInfoW', 'BOOL', [
      ['PDWORD', 'Error', 'out'],
      ['PWCHAR', 'Buffer', 'out'],
      ['PDWORD', 'BufferLength', 'inout']
    ])

		# dll.add_function('InternetGetPerSiteCookieDecision', 'BOOL', [
		# 	['PDWORD', 'HostName', 'in'],
		# 	['PBLOB', 'Result', 'out']
  #   ])

		# dll.add_function('InternetGetProxyInfo', 'BOOL', [
		# 	['PDWORD', 'Url', 'in'],
		# 	['DWORD', 'UrlLength', 'in'],
		# 	['PDWORD', 'UrlHostName', 'in'],
		# 	['DWORD', 'UrlHostNameLength', 'in'],
		# 	['PBLOB', 'ProxyHostName', 'out'],
		# 	['PBLOB', 'ProxyHostNameLength', 'out']
  #   ])

		# dll.add_function('InternetGoOnline', 'BOOL', [
		# 	['PDWORD', 'URL', 'in'],
		# 	['DWORD', 'Parent', 'in'],
		# 	['DWORD', 'Flags', 'in']
  #   ])

		# dll.add_function('InternetHangUp', 'UNK', [
		# 	['PDWORD', 'Connection', 'in'],
		# 	['DWORD', 'Reserved', 'in']
  #   ])

		# dll.add_function('InternetInitializeAutoProxyDll', 'BOOL', [
		# 	['DWORD', 'Reserved', 'in']
  #   ])

		dll.add_function('InternetLockRequestFile', 'BOOL', [
			['HANDLE', 'Internet', 'in'],
			['HANDLE', 'LockReqHandle', 'out']
    ])

		dll.add_function('InternetOpenA', 'HANDLE', [
			['PCHAR', 'Agent', 'in'],
			['DWORD', 'AccessType', 'in'],
			['PCHAR', 'ProxyName', 'in'],
			['PCHAR', 'ProxyBypass', 'in'],
			['DWORD', 'Flags', 'in']
    ])

 		dll.add_function('InternetOpenW', 'HANDLE', [
			['PWCHAR', 'Agent', 'in'],
			['DWORD', 'AccessType', 'in'],
			['PWCHAR', 'ProxyName', 'in'],
			['PWCHAR', 'ProxyBypass', 'in'],
			['DWORD', 'Flags', 'in']
    ])

		dll.add_function('InternetOpenUrlA', 'HANDLE', [
			['HANDLE', 'Internet', 'in'],
			['PCHAR', 'Url', 'in'],
			['PCHAR', 'Headers', 'in'],
			['DWORD', 'HeadersLength', 'in'],
			['DWORD', 'Flags', 'in'],
			['PDWORD', 'Context', 'in']
    ])

		dll.add_function('InternetOpenUrlW', 'HANDLE', [
			['HANDLE', 'Internet', 'in'],
			['PWCHAR', 'Url', 'in'],
			['PWCHAR', 'Headers', 'in'],
			['DWORD', 'HeadersLength', 'in'],
			['DWORD', 'Flags', 'in'],
			['PDWORD', 'Context', 'in']
    ])

		dll.add_function('InternetQueryDataAvailable', 'BOOL', [
			['HANDLE', 'File', 'in'],
			['PDWORD', 'NumberOfBytesAvailable', 'out'], # may be null
			['DWORD', 'Flags', 'in'], # must be 0
			['PDWORD', 'Context', 'in'] # must be 0
    ])

		dll.add_function('InternetQueryOption', 'BOOL', [
			['HANDLE', 'Internet', 'in'],
			['DWORD', 'Option', 'in'],
			['LPVOID', 'Buffer', 'out'],
			['PDWORD', 'BufferLength', 'inout']
    ])

		dll.add_function('InternetReadFile', 'BOOL', [
			['HANDLE', 'File', 'in'],
			['PBLOB', 'Buffer', 'out'],
			['DWORD', 'NumberOfBytesToRead', 'in'],
			['PDWORD', 'NumberOfBytesRead', 'out']
    ])

		dll.add_function('InternetReadFileExA', 'BOOL', [
			['HANDLE', 'File', 'in'],
			['PBLOB', 'BuffersOut', 'out'],
			['DWORD', 'Flags', 'in'],
			['PDWORD', 'Context', 'in']
    ])

    dll.add_function('InternetReadFileExW', 'BOOL', [
      ['HANDLE', 'File', 'in'],
      ['PBLOB', 'BuffersOut', 'out'],
      ['DWORD', 'Flags', 'in'],
      ['PDWORD', 'Context', 'in']
    ])

		# dll.add_function('InternetSetCookie', 'BOOL', [
		# 	['PDWORD', 'Url', 'in'],
		# 	['PDWORD', 'CookieName', 'in'],
		# 	['PDWORD', 'CookieData', 'in']
  #   ])

		# dll.add_function('InternetSetCookieEx', 'UNK', [
		# 	['PDWORD', 'URL', 'in'],
		# 	['PDWORD', 'CookieName', 'in'],
		# 	['PDWORD', 'CookieData', 'in'],
		# 	['DWORD', 'Flags', 'in'],
		# 	['PDWORD', 'Reserved', 'in']
  #   ])

		dll.add_function('InternetSetFilePointer', 'DWORD', [
			['HANDLE', 'File', 'in'],
			['DWORD', 'DistanceToMove', 'in'], # LONG, low 32bits of signed 64-bit #
			['PDWORD', 'DistanceToMoveHigh', 'inout'], #PLONG, high 32 bits
			['DWORD', 'MoveMethod', 'in'], # 0/FILE_BEGIN, FILE_CURRENT, FILE_END
			['PDWORD', 'Context', 'in'] # must be 0
    ])

		dll.add_function('InternetSetOptionA', 'BOOL', [
			['HANDLE', 'Internet', 'in'],
			['DWORD', 'Option', 'in'],
			['LPVOID', 'Buffer', 'in'],
			['DWORD', 'BufferLength', 'in'] # size in TCHAR if Buffer is a string, else bytes
    ])

    dll.add_function('InternetSetOptionW', 'BOOL', [
      ['HANDLE', 'Internet', 'in'],
      ['DWORD', 'Option', 'in'],
      ['LPVOID', 'Buffer', 'in'],
      ['DWORD', 'BufferLength', 'in'] # size in TCHAR if Buffer is a string, else bytes
    ])

		# dll.add_function('InternetSetPerSiteCookieDecision', 'BOOL', [
		# 	['PDWORD', 'HostName', 'in'],
		# 	['DWORD', 'Decision', 'in']
  #   ])

		# dll.add_function('InternetSetStatusCallback', 'PBLOB', [
		# 	['HANDLE', 'Internet', 'in'],
		# 	['PDWORD', 'InternetCallback', 'in']
  #   ])

		# dll.add_function('InternetStatusCallback', 'PBLOB', [
		# 	['HANDLE', 'Internet', 'in'],
		# 	['PDWORD', 'Context', 'in'],
		# 	['DWORD', 'InternetStatus', 'in'],
		# 	['PDWORD', 'StatusInformation', 'in'],
		# 	['DWORD', 'StatusInformationLength', 'in']
  #   ])

		# dll.add_function('InternetTimeFromSystemTime', 'BOOL', [
		# 	['UNK', 'st', 'in'],
		# 	['DWORD', 'RFC', 'in'],
		# 	['DWORD', 'Time', 'out'],
		# 	['DWORD', 'Time', 'in']
  #   ])

		# dll.add_function('InternetTimeToSystemTime', 'BOOL', [
		# 	['PDWORD', 'Time', 'in'],
		# 	['PBLOB', 'st', 'out'],
		# 	['DWORD', 'Reserved', 'in']
  #   ])

		dll.add_function('InternetUnlockRequestFile', 'BOOL', [
			['HANDLE', 'LockRequestInfo', 'in']
    ])

		dll.add_function('InternetWriteFile', 'BOOL', [
			['HANDLE', 'File', 'in'],
			['LPVOID', 'Buffer', 'in'],
			['DWORD', 'NumberOfBytesToWrite', 'in'],
			['PDWORD', 'NumberOfBytesWritten', 'out']
    ])

		# dll.add_function('PrivacyGetZonePreferenceW', 'UNK', [
		# 	['DWORD', 'Zone', 'in'],
		# 	['DWORD', 'Type', 'in'],
		# 	['PBLOB', 'Template', 'out'],
		# 	['PBLOB', 'Buffer', 'out'],
		# 	['PDWORD', 'BufferLength', 'inout']
  #   ])

		# dll.add_function('PrivacySetZonePreferenceW', 'UNK', [
		# 	['DWORD', 'Zone', 'in'],
		# 	['DWORD', 'Type', 'in'],
		# 	['DWORD', 'Template', 'in'],
		# 	['PDWORD', 'Preference', 'in']
  #   ])

		# dll.add_function('ReadUrlCacheEntryStream', 'BOOL', [
		# 	['DWORD', 'UrlCacheStream', 'in'],
		# 	['DWORD', 'Location', 'in'],
		# 	['PDWORD', 'Buffer', 'inout'],
		# 	['PDWORD', 'Len', 'inout'],
		# 	['DWORD', 'Reserved', 'in']
  #   ])

		# dll.add_function('ResumeSuspendedDownload', 'BOOL', [
		# 	['HANDLE', 'Request', 'in'],
		# 	['DWORD', 'ResultCode', 'in']
  #   ])

		# dll.add_function('RetrieveUrlCacheEntryFile', 'BOOL', [
		# 	['PDWORD', 'UrlName', 'in'],
		# 	['UNK', 'CacheEntryInfo', 'out'],
		# 	['PDWORD', 'CacheEntryInfo', 'inout'],
		# 	['DWORD', 'Reserved', 'in']
  #   ])

		# dll.add_function('RetrieveUrlCacheEntryStream', 'DWORD', [
		# 	['PDWORD', 'UrlName', 'in'],
		# 	['UNK', 'CacheEntryInfo', 'out'],
		# 	['PDWORD', 'CacheEntryInfo', 'inout'],
		# 	['UNK', 'RandomRead', 'in'],
		# 	['DWORD', 'Reserved', 'in']
  #   ])

		# dll.add_function('SetUrlCacheEntryGroup', 'BOOL', [
		# 	['PDWORD', 'UrlName', 'in'],
		# 	['DWORD', 'Flags', 'in'],
		# 	['UNK', 'GroupId', 'in'],
		# 	['PDWORD', 'GroupAttributes', 'in'],
		# 	['DWORD', 'GroupAttributes', 'in'],
		# 	['PDWORD', 'Reserved', 'in']
  #   ])

		# dll.add_function('SetUrlCacheEntryInfo', 'BOOL', [
		# 	['PDWORD', 'UrlName', 'in'],
		# 	['PDWORD', 'CacheEntryInfo', 'in'],
		# 	['DWORD', 'FieldControl', 'in']
  #   ])

		# dll.add_function('SetUrlCacheGroupAttribute', 'BOOL', [
		# 	['UNK', 'gid', 'in'],
		# 	['DWORD', 'Flags', 'in'],
		# 	['DWORD', 'Attributes', 'in'],
		# 	['PDWORD', 'GroupInfo', 'in'],
		# 	['PDWORD', 'Reserved', 'inout']
  #   ])

		# dll.add_function('UnlockUrlCacheEntryFile', 'BOOL', [
		# 	['PDWORD', 'UrlName', 'in'],
		# 	['DWORD', 'Reserved', 'in']
  #   ])

		# dll.add_function('UnlockUrlCacheEntryStream', 'BOOL', [
		# 	['DWORD', 'UrlCacheStream', 'in'],
		# 	['DWORD', 'Reserved', 'in']
  #   ])

		return dll
	end # end create_dll
end # end class

end; end; end; end; end; end; end
