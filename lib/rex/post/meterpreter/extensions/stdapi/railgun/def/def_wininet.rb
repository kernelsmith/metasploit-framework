# -*- coding: binary -*-
module Rex
module Post
module Meterpreter
module Extensions
module Stdapi
module Railgun
module Def

class Def_wininet

	def self.create_dll(dll_path = 'wininet')
		dll = DLL.new(dll_path, ApiConstants.manager)

		dll.add_function('InternetCheckConnection', 'BOOL',[
			["PCHAR","lpszUrl","in"], # LPCTSTR, can be "null"
			["DWORD","dwFlags","in"], # Options. FLAG_ICC_FORCE_CONNECTION is the only flag currently available. 
			# If this flag is set, it forces a connection. A sockets connection is attempted in the following order:
			# If lpszUrl is non-NULL, the host value is extracted from it and used to ping that specific host.
			# If lpszUrl is NULL and there is an entry in the internal server database for the nearest server,
			# the host value is extracted from the entry and used to ping that server.
			["DWORD","dwReserved","in"] # must be 0
			])

		dll.add_function('InternetOpen', 'DWORD', [
			['PCHAR', 'lpszAgent', 'in'],
			['DWORD', 'dwAccessType', 'in'],
			['PCHAR', 'lpszProxyName', 'in'],
			['PCHAR', 'lpszProxyBypass', 'in'],
			['DWORD', 'dwFlags', 'in'],
		])

		dll.add_function('InternetOpenUrl', 'DWORD', [
			['DWORD', 'hInternet', 'in'],
			['PCHAR', 'lpszUrl', 'in'],
			['PCHAR', 'lpszHeaders', 'in'],
			['DWORD', 'dwHeadersLength', 'in'],
			['DWORD', 'dwFlags', 'in'],
			['PDWORD', 'dwContext', 'in']
		])

		dll.add_function('InternetConnect', 'DWORD', [ # HINTERNET handle
			['DWORD', 'hInternet', 'in'], # returned by InternetOpen
			['PCHAR','lpszServerName','in'],
			['DWORD','nServerPort','in'],
			['PCHAR','lpszUsername','in'],
			['PCHAR','lpszPassword','in'],
			['DWORD','dwService','in'],
			['DWORD','dwFlags','in'],
			['PDWORD','dwContext','in']
			])

		dll.add_function('HttpOpenRequest', 'DWORD', [
			['DWORD', 'hConnect', 'in'],
			['PCHAR', 'lpszVerb', 'in'],
			['PCHAR', 'lpszObjectName', 'in'],
			['PCHAR', 'lpszVersion', 'in'],
			['PCHAR', 'lpszReferer', 'in'],
			['PCHAR', '*lplpszAcceptTypes', 'in'],
			['DWORD', 'dwFlags', 'in'],
			['PDWORD', 'dwContext', 'in']
		])

		dll.add_function('HttpAddRequestHeaders', 'BOOL', [
			['DWORD', 'hRequest', 'in'],
			['PCHAR', 'lpszHeaders', 'in'],
			['DWORD', 'dwHeadersLength', 'in'],
			['DWORD', 'dwModifiers', 'in']
		])

		dll.add_function('HttpSendRequest', 'BOOL', [
			['DWORD', 'hRequest', 'in'],
			['PCHAR', 'lpszHeaders', 'in'],
			['DWORD', 'dwHeadersLength', 'in'],
			['PBLOB', 'lpOptional', 'in'],
			['DWORD', 'dwOptionalLength', 'in'],
		])

		dll.add_function('HttpSendRequestEx', 'BOOL', [
			['DWORD', 'hRequest', 'in'], # The handle returned by HttpOpenRequest.
			['PDWORD', 'lpBuffersIn', 'in'], # Optional. A pointer to an INTERNET_BUFFERS structure.
			['DWORD', 'lpBuffersOut', 'out'], # Reserved. Must be NULL
			['DWORD', 'dwFlags', 'in'], # Reserved. Must be zero.
			['PDWORD', 'dwContext', 'in'], # Application-defined context value, if a status callback function has been registered.
		])

		return dll
	end

end

end; end; end; end; end; end; end


