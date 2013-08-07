# -*- coding: binary -*-

module Msf
class Post
module Windows

module Browser
	# API for browser manipulation, automation, and control etc

	# methods starting with "_" are public by design, but not normally needed by most callers

	# @TODO:  if nec, enact a lazy load since most people won't use this mixin
	# @TODO:  Address line 242 in services.rb]
	# @TODO:  YARD & lookup error values
	# @TODO:  Add all _methods first, then convenience methods

	#
	# Template description
	#
	# @param str1 [String] The str to blah
	# @param num1 [Fixnum] The base number to blah
	# @param pid  [Fixnum] The process ID to fondle
	# @option opt [String] :opt_name The option to describe when option is given in a hash
	# 	SC_MANAGER_* constants (see
	#   {http://msdn.microsoft.com/en-us/library/windows/desktop/ms685981(v=vs.85).aspx})
	#
	# @return [Boolean] True if successful, otherwise false
	#

	#
	# Get default browser
	#
	# @return [String] The name of the default browser as stored in the registry
	#
	def default_browser
		# @TODO actually write this

		# serviceskey = "HKLM\\SYSTEM\\CurrentControlSet\\Services"
		# a =[]
		# services = []
		# keys = registry_enumkeys(serviceskey)

		return default_browser_name
	end
	alias :get_default_browser :default_browser

	#
	# Check internet connection using wininet.dll!InternetCheckConnection
	#
	# @param url [String] URL to check for connectivity, may be hostname, IP address, or nil.
	# @param flags [Fixnum] Control flags, may be 0 or FLAG_ICC_FORCE_CONNECTION which forces a connection. 
	#   A sockets connection is attempted in the following order:
	#   If +url+ is non-nil, the host value is extracted from it and used to ping that specific host.
	#   If +url+ is nil and there is an entry in the internal server database for the nearest server,
	#   the host value is extracted from the entry and used to ping that server.
	# @return [true,false] true if a socket connection to url, or 'nearest server', is successful, else false
	# @raise [RuntimeError] if InternetCheckConnection returns an error
	#
	def internet_check_connection(url = nil, flags = FLAG_ICC_FORCE_CONNECTION)
		# BOOL
		# ["PCHAR","lpszUrl","in"], # LPCTSTR, can be "null"
		# ["DWORD","dwFlags","in"], # Options. 
		# ["DWORD","dwReserved","in"] # must be 0
		ret = run_dll_function(:InternetCheckConnection, url, flags, 0)
	end
	alias :check_internet_connection :internet_check_connection

	#
	# Initialize an Internet connection in preparation for sending http/ftp etc traffic.  Despite the WinAPI function
	#   name (InternetOpenUrl), this method does not send data
	#
	# @param hInternet [Fixnum] Internet handle as returned by internet_open
	# @param url [String] URL to use as destination of traffic, may be hostname, IP address.
	# @option opts [String] :headers Request headers
	# @option opts [Fixnum] :headers_length Length of request headers, if nil provided the length is determined from +headers+
	# @option opts [Fixnum] :flags INTERNET_FLAG_* connection flag constants (see
	#   {http://msdn.microsoft.com/en-us/library/windows/desktop/msXXXXXX(v=vs.85).aspx}) @TODO:  update url ref
	# @option opts [Fixnum] :context @TODO update this descript and value type
	# @return [Fixnum] Opaque Windows handle HINTERNET as returned by InternetOpen
	def _initialize_internet(hInternet, url, opts = {})
		# DWORD (HANDLE)
		# ['PCHAR', 'lpszAgent', 'in'],
		# ['DWORD', 'dwAccessType', 'in'],
		# ['PCHAR', 'lpszProxyName', 'in'],
		# ['PCHAR', 'lpszProxyBypass', 'in'],
		# ['DWORD', 'dwFlags', 'in'],
		defaults = {
					:ua => "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)", # ghetto, detect it
					:access => INTERNET_OPEN_TYPE_PRECONFIG,
					:proxy_name => nil,
					:proxy_bypass => nil,
					:flags => INTERNET_FLAG_ASYNC,
				}
		opts = defaults.merge(opts)
		# determine length of headers if the value isn't provided
		opts[:headers_length] = opts[:headers].length unless opts[:headers_length]
		ret = run_dll_function(:InternetOpenA, hInternet, url, 
			opts[:headers], # @TODO: empty string or nil/null expected here when none provided?  Length?
			opts[:headers_length],
			opts[:flags],
			opts[:context])
		end
	end
	alias :internet_open_url :_initialize_internet

	#
	# Make a simple internet connection.  Use other methods if advanced options are required
	#
	# @param hInternet [Fixnum] Internet handle as returned by internet_open
	# @param url [String] URL to use as destination of traffic, may be hostname, IP address.
	# @option opts [String] :headers Request headers
	# @option opts [Fixnum] :headers_length Length of request headers, if nil provided the length is determined from +headers+
	# @option opts [Fixnum] :flags INTERNET_FLAG_* connection flag constants (see
	#   {http://msdn.microsoft.com/en-us/library/windows/desktop/msXXXXXX(v=vs.85).aspx}) @TODO:  update url ref
	# @option opts [Fixnum] :context @TODO update this descript and value type
	# @return [Fixnum] Opaque Windows handle HINTERNET as returned by InternetOpen
	def open_url_simple(hInternet, url, opts = {}) # InternetOpenUrl requires a call to InternetOpen first for handle
		# DWORD (HANDLE)
		# ['DWORD', 'hInternet', 'in'],
		# ['PCHAR', 'lpszUrl', 'in'],
		# ['PCHAR', 'lpszHeaders', 'in'],
		# ['DWORD', 'dwHeadersLength', 'in'],
		# ['DWORD', 'dwFlags', 'in'],
		# ['PDWORD', 'dwContext', 'in']
		defaults = {
					:headers => '',
					:headers_length => nil,
					:flags => INTERNET_FLAG_HYPERLINK && \
								INTERNET_FLAG_IGNORE_REDIRECT_TO_HTTPS && \
								INTERNET_FLAG_NO_CACHE_WRITE && \
								INTERNET_FLAG_NO_UI && \
								INTERNET_FLAG_PRAGMA_NOCACHE,
					:context => nil # @TODO:  is this right?  it's a PDWORD, could we use it for port in firebind?
				}
		opts = defaults.merge(opts)
		# @todo:  prepend ftp:, http:, or https: if not present
		res = session.railgun.wininet.InternetOpenUrlA(opts[:ua],opts[:access],opts[:proxy_name],opts[:proxy_bypass],opts[:flags])
		if not res["GetLastError"] == 0
			raise RuntimeError.new("Unable to initialize wininet dll, GetLastError: #{res["GetLastError"]}")
			# @todo:  add error code lookup?
		else
			return res["return"]
		end
		# use InternetReadFile to read the returned data from the handle
	end

	# @example run_dll_function(:wininet, :InternetOpen, nil, "my ua string", "INTERNET_OPEN_TYPE_DIRECT", nil, nil, 0)
	def run_dll_function(dll_as_sym = :wininet, function_name_as_sym, custom_error_msg = nil, *function_args)
		args = [function_name_as_sym]
		args += function_args
		results = session.railgun.send(dll_as_sym).send(args * ",") # use this array format to avoid extra comma when args initially empty
		err = results["GetLastError"]
		if not err == 0
			err_code = results['GetLastError']
			error_msg = custom_error_msg || "Error running #{dll_as_sym.to_s}.dll function.  #{function_name_as_sym.to_s} error code: #{err_code}\n"
			error_msg += "This WinAPI error may mean:  #{lookup_error(err_code, /^ERROR_/)}"
			# @TODO; see if we can add to this error regex, look at msdn for wininet fxns, might be ERROR_INTERNET_* etc
			raise RuntimeError.new(error_msg)
		else
			results["return"]
		end
	end
	private :run_dll_function

	# All connections: InternetCheckConnection -> InternetOpen => HINTERNET
	# 	Basic URL connections: -> InternetOpenUrl(HINTERNET) -> InternetReadFile(HINTERNET)
	# 	Advanced HTTP: -> InternetConnect(HINTERNET) -> HttpOpenRequest
	#  		Optional: HttpAddRequestHeaders
	#  		-> HttpSendRequestEx(single buffer & also auto reads) & Optional InternetWriteFile (if data remains to send)
	#  			OR
	#  		-> HttpSendRequest (can send extra data before read) as below
	# 		The function also lets the client specify optional data to send to the HTTP server immediately following the request headers.
	#  		This feature is generally used for "write" operations such as PUT and POST.
	# 	HttpEndRequest if opened by HttpSendRequestEx
	# 	Optional: InternetReadFile
	# All connections: -> InternetCloseHandle

	module Ie
		# API for Internet Explorer manipulation, automation, and control etc via Railgun

		# Typical sequence:  InternetAttemptConnection -> InternetOpen -> InternetOpenUrl -> InternetReadFile? -> InternetCloseHandle

		# should we use a class instead?
		# The class object could have the HINTERNET handle as it's primary attribute

		#
		# Template description
		#
		# @param str1 [String] The str to blah
		# @param num1 [Fixnum] The base number to blah
		# @param pid  [Fixnum] The process ID to fondle
		# @param [Array<String, Symbol>] arg takes an Array of Strings or Symbols
		#
		# @return [Boolean] True if successful, otherwise false
		#

		#
		# _internet_open is the first WinINet function called by an application. It tells the Internet DLL
		#   to initialize internal data structures and prepare for future calls from the application. When
		#   the application finishes using the Internet functions, it should call InternetCloseHandle.
		#
		# @param user_agent_str [String] The user agent string to use during network communications
		# @param access_type [Fixnum] Type of access required. This parameter can be one of the following values:
		#   INTERNET_OPEN_TYPE_DIRECT                       Resolves all host names locally.
		#   INTERNET_OPEN_TYPE_PRECONFIG                    Retrieves the proxy or direct configuration from the registry.
		#   INTERNET_OPEN_TYPE_PRECONFIG_WITH_NO_AUTOPROXY  Retrieves the proxy or direct configuration from the registry
		#                                and prevents the use of a startup Microsoft JScript or Internet Setup (INS) file.
		#   INTERNET_OPEN_TYPE_PROXY                        Passes requests to the proxy unless a proxy bypass list is
		#                                supplied and the name to be resolved bypasses the proxy. In this case, the
		#                                function uses INTERNET_OPEN_TYPE_DIRECT.
		# @param proxy_name  [String] Specifies the name of the proxy server(s) to use when proxy access is specified by
		#   setting dwAccessType to INTERNET_OPEN_TYPE_PROXY. Do not use an empty string.  CERN type proxies (HTTP only),
		#   TIS FTP gateway (FTP only). If IE installed, these functions also support SOCKS proxies. If +access_type+ is not
		#   set to INTERNET_OPEN_TYPE_PROXY, this parameter is ignored and should be NULL.
		# @param proxy_bypass [String] Specifies an optional list of host names or IP addresses, or both, that should not be
		#   routed through the proxy when +access_type+ is set to INTERNET_OPEN_TYPE_PROXY. The list can contain wildcards.
		#   Do not use an empty string.
		# @param flags [Fixnum] Control flags
		#   INTERNET_FLAG_ASYNC       Makes only asynchronous requests on handles descended from the one returned from _internet_open
		#   INTERNET_FLAG_FROM_CACHE  Does not make network requests. All entities are returned from the cache. If the requested item is not in the cache, a suitable error, such as ERROR_FILE_NOT_FOUND, is returned.
		#   INTERNET_FLAG_OFFLINE     Identical to INTERNET_FLAG_FROM_CACHE. Does not make network requests. All entities are
		#                             returned from the cache. If the requested item is not in the cache, a suitable error,
		#                             such as ERROR_FILE_NOT_FOUND, is returned.
		# @return [Fixnum] Returns a valid DWORD handle that the application passes to subsequent WinINet functions.
		# @return [nil] Returns nil if InternetOpen fails
		#

		# dll.add_function('InternetOpen', 'DWORD', [
		# 	['PCHAR', 'lpszAgent', 'in'],
		# 	['DWORD', 'dwAccessType', 'in'],
		# 	['PCHAR', 'lpszProxyName', 'in'],
		# 	['PCHAR', 'lpszProxyBypass', 'in'],
		# 	['DWORD', 'dwFlags', 'in'],
		# ])
		def _internet_open(user_agent_str = nil, access_type = , proxy_name = , proxy_bypass = , flags = 0)


			handle = run_dll_function(:InternetOpen, nil, user_agent_str, access_type, proxy_name, proxy_bypass, flags)
		end

		# dll.add_function('InternetConnect', 'DWORD', [ # HINTERNET handle
		# 	['DWORD', 'hInternet', 'in'], # returned by InternetOpen
		# 	['PCHAR','lpszServerName','in'],
		# 	['DWORD','nServerPort','in'],
		# 	['PCHAR','lpszUsername','in'],
		# 	['PCHAR','lpszPassword','in'],
		# 	['DWORD','dwService','in'],
		# 	['DWORD','dwFlags','in'],
		# 	['PDWORD','dwContext','in']
		# 	])
		def _internet_connect(hInternet, svr_name, svr_port, username, password, service, flags, context)

		end

		# dll.add_function('InternetOpenUrl', 'DWORD', [
		# 	['DWORD', 'hInternet', 'in'],
		# 	['PCHAR', 'lpszUrl', 'in'],
		# 	['PCHAR', 'lpszHeaders', 'in'],
		# 	['DWORD', 'dwHeadersLength', 'in'],
		# 	['DWORD', 'dwFlags', 'in'],
		# 	['PDWORD', 'dwContext', 'in']
		# ])
		def _internet_open_urlA(hInternet, url, opts={})
			defaults = {
						:headers => '',
						:headers_length => nil,
						:flags => INTERNET_FLAG_HYPERLINK && \
									INTERNET_FLAG_IGNORE_REDIRECT_TO_HTTPS && \
									INTERNET_FLAG_NO_CACHE_WRITE && \
									INTERNET_FLAG_NO_UI && \
									INTERNET_FLAG_PRAGMA_NOCACHE,
						:context => nil # @TODO:  is this right?  it's a PDWORD, could we use it for port in firebind?
					}
			opts = defaults.merge(opts)
		end
		alias :_internet_open_url :_internet_open_urlA

		def _internet_open_urlW(hInternet, url, opts={})
			# @TODO:  How to implement the "W" versions?
			defaults = {
						:headers => '',
						:headers_length => nil,
						:flags => INTERNET_FLAG_HYPERLINK && \
									INTERNET_FLAG_IGNORE_REDIRECT_TO_HTTPS && \
									INTERNET_FLAG_NO_CACHE_WRITE && \
									INTERNET_FLAG_NO_UI && \
									INTERNET_FLAG_PRAGMA_NOCACHE,
						:context => nil # @TODO:  is this right?  it's a PDWORD, could we use it for port in firebind?
					}
			opts = defaults.merge(opts)
		end

		# dll.add_function('InternetConnect', 'DWORD', [ # HINTERNET handle
		# 	['DWORD', 'hInternet', 'in'], # returned by InternetOpen
		# 	['PCHAR','lpszServerName','in'],
		# 	['DWORD','nServerPort','in'],
		# 	['PCHAR','lpszUsername','in'],
		# 	['PCHAR','lpszPassword','in'],
		# 	['DWORD','dwService','in'],
		# 	['DWORD','dwFlags','in'],
		# 	['PDWORD','dwContext','in']
		# 	])
		def _internet_connect(hInternet. svr_name, svr_port)
			defaults = {
						:username => nil,
						:password => nil,
						:service  => 0, # @TODO:  ??
						:flags => INTERNET_FLAG_HYPERLINK && \
									INTERNET_FLAG_IGNORE_REDIRECT_TO_HTTPS # @TODO:  default flags
						:context => nil # @TODO:  is this right?  it's a PDWORD, could we use it for port in firebind?
					}
			opts = defaults.merge(opts)
		end

		# dll.add_function('InternetReadFile', 'BOOL', [
		# 	['DWORD', 'hFile', 'in'], # Handle returned from a previous call to InternetOpenUrl, FtpOpenFile, or HttpOpenRequest.
		# 	['PBLOB', 'lpBuffer', 'out'],
		# 	['DWORD', 'dwNumberOfBytesToRead', 'in'],
		# 	['PBLOB', 'lpdwNumberOfBytesRead', 'out'],
		# ])
		def _internet_read_file(hFile, bytes = -1)
			# read all bytes if bytes == -1

			out_buffer, bytes_read
		end

		# dll.add_function('InternetReadFileEx', 'BOOL', [
		# 	['DWORD', 'hFile', 'in'], # Handle returned by the InternetOpenUrl or HttpOpenRequest function.
		# 	['PBLOB', 'lpBuffersOut', 'out'],
		# 	['DWORD', 'dwFlags', 'in'],
		# 	['PDWORD', 'dwContext', 'in'],
		# ])
		def _internet_read_file_ex(hFile, flags, context) # @TODO:  default arg vals

			out_buffer
		end

		# dll.add_function('HttpOpenRequest', 'DWORD', [
		# 	['DWORD', 'hConnect', 'in'],
		# 	['PCHAR', 'lpszVerb', 'in'],
		# 	['PCHAR', 'lpszObjectName', 'in'],
		# 	['PCHAR', 'lpszVersion', 'in'],
		# 	['PCHAR', 'lpszReferer', 'in'],
		# 	['PCHAR', '*lplpszAcceptTypes', 'in'],
		# 	['DWORD', 'dwFlags', 'in'],
		# 	['PDWORD', 'dwContext', 'in']
		# ])
		def _http_open_request(hConnect, verb = "GET", opts = {})
			# @TODO:  opts and defaults opts

		end

		# dll.add_function('HttpAddRequestHeaders', 'BOOL', [
		# 	['DWORD', 'hRequest', 'in'],
		# 	['PCHAR', 'lpszHeaders', 'in'],
		# 	['DWORD', 'dwHeadersLength', 'in'],
		# 	['DWORD', 'dwModifiers', 'in']
		# ])
		def _http_add_request_headers(hRequest, headers, headers_length = nil, modifiers = 0) # @TODO:  defaults for modifiers etc
			headers_length ||= headers.length

		end

		# dll.add_function('HttpSendRequest', 'BOOL', [
		# 	['DWORD', 'hRequest', 'in'],
		# 	['PCHAR', 'lpszHeaders', 'in'],
		# 	['DWORD', 'dwHeadersLength', 'in'],
		# 	['PBLOB', 'lpOptional', 'in'],
		# 	['DWORD', 'dwOptionalLength', 'in'],
		# ])
		def _http_send_request(hRequest, headers, headers_length, opts = {})
			headers_length ||= headers.length
			default_options = {}
			opts = default_options.blah # @TODO:  opts and default opts

		end

		# dll.add_function('HttpSendRequestEx', 'BOOL', [
		# 	['DWORD', 'hRequest', 'in'], # The handle returned by HttpOpenRequest.
		# 	['PDWORD', 'lpBuffersIn', 'in'], # Optional. A pointer to an INTERNET_BUFFERS structure.
		# 	['DWORD', 'lpBuffersOut', 'out'], # Reserved. Must be NULL
		# 	['DWORD', 'dwFlags', 'in'], # Reserved. Must be zero.
		# 	['PDWORD', 'dwContext', 'in'], # Application-defined context value, if a status callback function has been registered.
		# ])
		def _http_send_request_ex(hRequest, buffers, context)
			flags = 0 # must be 0

		end

	end # Ie

end # Browser
end # Windows
end # Post
end # Msf
