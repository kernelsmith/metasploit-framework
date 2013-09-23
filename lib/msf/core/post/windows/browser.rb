# -*- coding: binary -*-

module Msf
class Post
module Windows

module Browser
	# API for browser manipulation, automation, and control etc
	# methods starting with "_" are public by design, but not normally needed by most callers

	# @TODO:  if nec, enact a lazy load since most people won't use this mixin
	# @TODO:  Address line 242 in services.rb]
	# @TODO:  lookup error values

	# Some class constants
	UA_IE8_BASIC = 'Mozilla/5.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; ' +
									'.NET CLR 1.1.4322; .NET CLR 2.0.50727)'
	UA_IE9_BASIC = 'Mozilla/5.0 (Windows; U; MSIE 9.0; Windows NT 9.0; en-US)'
	UA_IE10_BASIC = 'Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; Trident/6.0)'
	UA_IE10_BASIC_64 = 'Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; WOW64; Trident/6.0)'

	# @see http://www.useragentstring.com/pages/useragentstring.php for a nice list of
	# various user agent strings

	# Some Railgun reminders:
	# When passing values to a method:
	# If you want to pass a pointer to DWORD 13, pass in 13.  Simple.
	# If you want to pass a Null pointer, pass nil.
	# If you want to pass an empty buffer of size 123, pass 123
	# You can use Windows constants, just pass the string instead, like this
	# "GENERIC_READ" or even "GENERIC_READ | GENERIC_READ"
	# When defining data types:
	# Use DWORD for anything that vaguely resembles a DWORD.  In Ruby, use a Fixnum/Bignum
	# Use a Fixnum for bytes and words, they will be truncated modulo 256/65536 as needed
	# For a pointer to DWORD (PDWORD), pass the content of the DWORD as a Fixnumm, e.g.:
	# from MSDN:  BOOL WINAPI ReadFile(
	#   _In_         HANDLE hFile,
	#   _Out_        LPVOID lpBuffer,
	#   _In_         DWORD nNumberOfBytesToRead,
	#   _Out_opt_    LPDWORD lpNumberOfBytesRead,
	#   _Inout_opt_  LPOVERLAPPED lpOverlapped
	# );
	# railgun.add_function( 'kernel32', 'ReadFile', 'BOOL',[
	# 	["HANDLE","hFile","in"],
	#  	["PBLOB","lpBuffer","out"],
	# 	["DWORD","nNumberOfBytesToRead","in"],
	# 	["PDWORD","lpNumberOfBytesRead","out"],
	# 	["PBLOB","lpOverlapped","inout"],
	# ])
	# >> fh = some_file_handle # which is a fixnum (aka DWORD)
	# >> client.railgun.kernel32.ReadFile(fh,10,10,4,nil)
  # => {"GetLastError" => 0, "return" => true, "lpBuffer" => "blablablab", "lpNum...Read" => 10}

  # This is a great example
  #
  # Open the service manager with advapi32.dll!OpenSCManagerA on the
  # given host or the local machine if :host option is nil. If called
  # with a block, yields the manager and closes it when the block
  # returns.
  #
  # @param opts [Hash]
  # @option opts [String] :host (nil) The host on which to open the
  #   service manager. May be a hostname or IP address.
  # @option opts [Fixnum] :access (0xF003F) Bitwise-or of the
  #   SC_MANAGER_* constants (see
  #   {http://msdn.microsoft.com/en-us/library/windows/desktop/ms685981(v=vs.85).aspx})
  #
  # @return [Fixnum] Opaque Windows handle SC_HANDLE as returned by
  #   OpenSCManagerA()
  # @yield [manager] Gives the block a manager handle as returned by
  #   advapi32.dll!OpenSCManagerA. When the block returns, the handle
  #   will be closed with {#close_sc_manager}.
  # @raise [RuntimeError] if OpenSCManagerA returns a NULL handle
  #
  def open_sc_manager(opts={})
    host = opts[:host] || nil
    access = opts[:access] || 0xF003F
    machine_str = host ? "\\\\#{host}" : nil

    # SC_HANDLE WINAPI OpenSCManager(
    #   _In_opt_  LPCTSTR lpMachineName,
    #   _In_opt_  LPCTSTR lpDatabaseName,
    #   _In_      DWORD dwDesiredAccess
    # );
    manag = session.railgun.advapi32.OpenSCManagerA(machine_str,nil,access)
    if (manag["return"] == 0)
      raise RuntimeError.new("Unable to open service manager, GetLastError: #{manag["GetLastError"]}")
    end

    if (block_given?)
      begin
        yield manag["return"]
      ensure
        close_sc_manager(manag["return"])
      end
    else
      return manag["return"]
    end
  end

	#
	# This private method helps DRY out our code and provides basic error handling and messaging.
	# It only returns the "return" part of the hash returned by railgun, unless there is an error
	# @example run_dll_function(:wininet, :InternetOpen, nil, "my ua string", "INTERNET_OPEN_TYPE_DIRECT", nil, nil, 0)
	# @param [Symbol] DLL name as a Symbol
	# @param [Symbol] C Function name as a Symbol
	# @param [String, nil] Custom error message to use instead of dyanmically generated message
	# @todo finish this yard doc
	# @param Variable number of additional args as needed
	# @return varies depending on the C-function that is called
	def run_dll_function(dll_as_sym, function_name_as_sym, custom_error_msg = nil, *function_args)
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

	#
	# Get default browser
	#
	# @return [String] The name of the default browser as stored in the registry
	#
	def default_browser
		# @TODO actually write this
		raise NotImplementedError "default_browser is not yet implemented."

		# serviceskey = "HKLM\\SYSTEM\\CurrentControlSet\\Services"
		# a =[]
		# services = []
		# keys = registry_enumkeys(serviceskey)

		return default_browser_name
	end
	alias :get_default_browser :default_browser

	#
	# Allows an application to check if a connection to the Internet can be established.
	#   A sockets connection is attempted in the following order:
	#   If +url+ is non-nil, the host value is extracted from it and used to ping that host.
	#   If +url+ is nil and there is an entry in the internal server database for the nearest
	#     server, the host value is extracted from the entry and used to ping that server.
	# @see http://msdn.microsoft.com/en-us/library/windows/desktop/aa384346(v=vs.85).aspx
	#   InternetCheckConnection

	# @return [Boolean] Returns true if a connection is made successfully, otherwise false
	# @param [String] url a string specifying the URL to use to check the connection.
	#   May be hostname, IP address, or nil.
	# @param [Fixnum] flags Control flags which may be 0 or FLAG_ICC_FORCE_CONNECTION which
	#   forces a connection
	# @param [Fixnum] reserved This parameter is reserved and must be 0
	# @return [Boolean] true if a socket connection is successful, else false
	# @raise [RuntimeError] if Windows returns an error
	#
	def internet_check_connection(url, flags, reserved = 0)
		# Force reserved to be 0.  We leave it in the API in case it ever becomes un-reserved, then
		#   our API won't change and we can just remove the line below
		reserved = 0
		run_dll_function(:wininet, :InternetCheckConnection, url, flags, reserved)
	end
	alias :check_internet_connection :internet_check_connection

	module Ie
		# API for Internet Explorer manipulation, automation, and control etc

		# Basic Process:
		#                                  +- InternetQueryDataAvailable
		# InternetOpen -> InternetOpenUrl -+- InternetReadFile
		#                                  +- InternetSetFilePointer

		# Advanced Process:                                   +- HttpAddRequestHeaders
		#                                                     +- HttpQueryInfo
		# InternetOpen -> InternetConnect -> HttpOpenRequest -+- HttpSenRequest
		#                                                     +- HttpSendRequestEx
		#                                                     +- InternetErrorDlg


	  # Do Stuff.  If called with a block, yields the manager and closes it when the block
	  # returns.
	  #
	  # @param url
	  # @param headers
	  # @param agent
	  # @param opts [Hash]
	  # @option opts [String] :host (nil) Whatever
	  # @option opts [Fixnum] :access Whatever
	  # @return [Fixnum] HINTERNET handle to URL as returned by InternetOpenUrl
	  # @yield [hinternet] Gives the block a hinternet handle as returned by
	  #   wininet.dll!InternetOpenUrl. When the block returns, the handle
	  #   will be closed with {#internet_close_handle}.
	  # @raise [RuntimeError] if InternetOpenUrl returns a NULL handle
	  #
	  def send_simple_http_request(url, headers = [], agent = UA_IE9_BASIC, opts={})
	  	agent ||= "agent"
	    opt = opts[:opt] || "opt"

	    # SC_HANDLE WINAPI OpenSCManager(
	    #   _In_opt_  LPCTSTR lpMachineName,
	    #   _In_opt_  LPCTSTR lpDatabaseName,
	    #   _In_      DWORD dwDesiredAccess
	    # );
	    manag = session.railgun.advapi32.OpenSCManagerA(machine_str,nil,access)
	    if (manag["return"] == 0)
	      raise RuntimeError.new("Unable to open service manager, GetLastError: #{manag["GetLastError"]}")
	    end

	    if (block_given?)
	      begin
	        yield manag["return"]
	      ensure
	        close_sc_manager(manag["return"])
	      end
	    else
	      return manag["return"]
	    end
	  end

		#
		# Initializes an application's use of the WinINet functions.
		# @see http://msdn.microsoft.com/en-us/library/windows/desktop/aa385096(v=vs.85).aspx
    #   InternetOpen

		# @return [Fixnum] Returns a handle to be passed to subsequent WinINet methods
		# @param [Fixnum] lpsz_agent String user agent string
		# @param [Fixnum] dw_access_type Type of access required:
    #   INTERNET_OPEN_TYPE_DIRECT - Resolves all host names locally.
    #   INTERNET_OPEN_TYPE_PRECONFIG - Get proxy or direct config from registry
    #   INTERNET_OPEN_TYPE_PRECONFIG_WITH_NO_AUTOPROXY - Retrieve proxy or
    #   direct config from registry and prevent the use of a startup JScript or
    #   Internet Setup (INS) file.
    #   INTERNET_OPEN_TYPE_PROXY - Passes requests to the proxy unless a proxy
    #   bypass list is supplied and name to be resolved bypasses the proxy. In
    #   that case use INTERNET_OPEN_TYPE_DIRECT.
		# @param [Fixnum] lpsz_proxy_name String which specifies the name of the
    #   proxy server(s) to use when dwAccessType is INTERNET_OPEN_TYPE_PROXY,
    #   otherwise this parameter is ignored and should be nil
		# @param [Fixnum] lpsz_proxy_bypass String which specifies an optional list
    #   of host names or IP addresses, or both, that should not be routed
    #   through the proxy when dwAccessType is set to INTERNET_OPEN_TYPE_PROXY.
    #   The list can contain wildcards but do NOT use an empty string
    #   INTERNET_OPEN_TYPE_PROXY.  See ref above for more info, also note that
    #   this param is ignored and should be nil if dwAccessType is not set to
    #   INTERNET_OPEN_TYPE_PROXY
		# @param [Fixnum] dw_flags Options is any combo of the following:
    #   INTERNET_FLAG_ASYNC - Makes only asynchronous requests on handles
    #   descendant from the handle returned from this function.
    #   INTERNET_FLAG_FROM_CACHE - Does not make network requests. All entities
    #   are returned from the cache. If the requested item is not in the cache,
    #   an error (such as ERROR_FILE_NOT_FOUND) is returned.
    #   INTERNET_FLAG_OFFLINE - Identical to INTERNET_FLAG_FROM_CACHE
		#
		def _internet_open(agent, opts = {})
			defaults = {  # defaults for args in opts hash
        :access_type  => "INTERNET_OPEN_TYPE_PRECONFIG",
        :proxy_name   => nil,
				:proxy_bypass => nil,
				:flags => 'INTERNET_FLAG_ASYNC | INTERNET_FLAG_FROM_CACHE'
			}

			# Merge in defaults. This approach allows caller to safely pass in a nil
			opts = defaults.merge(opts)

			# Any arg validation can go here

			ret = run_dll_function(:wininet, :InternetOpen, agent,
                              opts[access_type],
                              opts[proxy_name],
                      				opts[proxy_bypass],
                      				opts[flags]
			)

			# Additional code goes here

		end

		#
		# Opens a resource specified by a complete FTP or HTTP URL.
		# @see http://msdn.microsoft.com/en-us/library/windows/desktop/aa385098(v=vs.85).aspx
    #   InternetOpenUrl

		# @return [Fixnum] Returns a valid handle to the URL if the connection is
    #   successfully established otherwise nil
		# @param [Handle] h_internet The handle to the current Internet session
		# @param [Fixnum] lpsz_url A String variable
    #   which specifies the URL to begin reading
		# @param [Fixnum] lpsz_headers A String which
    #   specifies the headers to be sent to the HTTP server
		# @param [Fixnum] dw_headers_length The size of the additional headers in TCHARs
		# @param [Fixnum] dw_flags This parameter can be one of the following values
    #   see the reference above for more info:
    #   INTERNET_FLAG_EXISTING_CONNECT,INTERNET_FLAG_HYPERLINK,
    #   INTERNET_FLAG_IGNORE_CERT_CN_INVALID,INTERNET_FLAG_IGNORE_CERT_DATE_INVALID,
    #   INTERNET_FLAG_IGNORE_REDIRECT_TO_HTTP,INTERNET_FLAG_IGNORE_REDIRECT_TO_HTTPS,
    #   INTERNET_FLAG_KEEP_CONNECTION,INTERNET_FLAG_NEED_FILE,INTERNET_FLAG_NO_AUTH,
    #   INTERNET_FLAG_NO_AUTO_REDIRECT,INTERNET_FLAG_NO_CACHE_WRITE,
    #   INTERNET_FLAG_NO_COOKIES,INTERNET_FLAG_NO_UI,INTERNET_FLAG_PASSIVE,
    #   INTERNET_FLAG_PRAGMA_NOCACHE,INTERNET_FLAG_RAW_DATA,INTERNET_FLAG_RELOAD,
    #   INTERNET_FLAG_RESYNCHRONIZE,INTERNET_FLAG_SECURE
		# @param [Fixnum] dw_context A pointer to a variable specifying the
    #   application-defined value that is passed, along with the returned handle,
    #   to any callback functions
		#
		# There are quite a few arguments so an opts hash was added.  To clean
		# up the API, you should review it and adjust as needed.  You may want
		# to consider regrouping args for: clarity, so args that are usually
		# left at default values, or are optional, or always a specific value,
		# etc, are put in the opts hash.  Or, you may want to get rid of the
		# opts hash entirely.
		def _internet_open_url(internet, url, headers, opts = {})
			defaults = {  # defaults for args in opts hash
				:headers_length => headers_length_default,
				:flags => flags_default,
				:context => context_default
			}

			# Merge in defaults. This approach allows caller to safely pass in a nil
			opts = defaults.merge(opts)

			# Any arg validation can go here

			ret = run_dll_function(:wininet, :InternetOpenUrl, internet, url, headers,
				opts[headers_length],
				opts[flags],
				opts[context],
			)

			# Additional code goes here

		end

		#
		# Adds one or more HTTP request headers to the HTTP request handle.
		# @see http://msdn.microsoft.com/en-us/library/windows/desktop/aa384227(v=vs.85).aspx
		#   HttpAddRequestHeaders

		# @return [Boolean] Returns true if successful, or false otherwise
		# @param [Handle] request Handle returned by a call to the HttpOpenRequest function
		# @param [String] headers String containing the headers to append to the request
		# @param [Fixnum] headers_length Size of headers, in TCHARs
		# @param [Fixnum] modifiers Controls the semantics of this method, see msdn url, but
		#   can be a combination of the following: HTTP_ADDREQ_FLAG_ADD, HTTP_ADDREQ_FLAG_ADD_IF_NEW,
		#   HTTP_ADDREQ_FLAG_COALESCE, HTTP_ADDREQ_FLAG_COALESCE_WITH_COMMA,
		#  	HTTP_ADDREQ_FLAG_COALESCE_WITH_SEMICOLON, HTTP_ADDREQ_FLAG_REPLACE
		# @raise [RuntimeError] if Windows returns err, such as when using HTTP_ADDREQ_FLAG_ADD_IF_NEW
		#
		def _http_add_request_headers(request, headers, modifiers = nil, headers_length = nil)
			modifiers ||= "HTTP_ADDREQ_FLAG_ADD" # add header if not already exist (don't raise err)
			headers_length ||= headers.length # @todo, do anything special for TCHARs?

			# Any arg validation can go here

			run_dll_function(:wininet, :HttpAddRequestHeaders,
									request,
									headers,
									opts[:headers_length],
									opts[:modifiers]
			)
		end

		#
		# Ends an HTTP request that was initiated by HttpSendRequestEx.
		# @see http://msdn.microsoft.com/en-us/library/windows/desktop/aa384230(v=vs.85).aspx
		#   HttpEndRequest
		# @return [Boolean] true on success, otherwise false
		# @param [Handle] request Handle returned by HttpOpenRequest and sent by HttpSendRequestEx
		# @param [Nil] buffers_out Parameter is reserved and must be NULL
		# @param [Fixnum] flags Parameter is reserved and must be set to 0
		# @param [Fixnum] context Parameter is reserved and must be set to 0
		# @raise [RuntimeError] if Windows returns an error
		#
		def _http_end_request(request, opts = {})
			defaults = {  # defaults for args in opts hash
				:buffers_out => nil, # reserved
				:flags       => 0,   # reserved
				:context     => 0,   # reserved
			}

			# Normally, we use the following to merge in defaults cuz it allows caller to pass in a nil:
			#   opts = defaults.merge(opts)
			#   However, in this case, they shouldn't be allowed to do so as all the possibilities
			#   are currently reserved, so we reverse the merge call to enforce the reserved values.
			opts = opts.merge(defaults)
			run_dll_function(:wininet, :HttpEndRequest, request,
									opts[:buffers_out],
									opts[:flags],
									opts[:context]
			)
		end

		#
		# Creates an HTTP request handle.
		# @see http://msdn.microsoft.com/en-us/library/windows/desktop/aa384233(v=vs.85).aspx
		#   HttpOpenRequest
		# @return [Handle] Returns an HTTP request handle if successful otherwise nil
		# @param [Handle] connect handle to an HTTP session returned by InternetConnect
		# @param [String] verb Contains the HTTP verb to use in the request.  If anything other than
		#   "GET" or "POST" is specified, HttpOpenRequest automatically sets
		#   INTERNET_FLAG_NO_CACHE_WRITE and INTERNET_FLAG_RELOAD for the request.
		# @param [String] object_name Name of the target object to be retrieved, generally a file
		#   name, an executable module, or search specifier.
		# @param [String] version The HTTP version to use in the request.  IE will override
		# @param [String] referer Specifies the URL of the document from which
		#   the URL in the request (+object_name+) was obtained
		# @param [String] accept_types Indicates media types accepted by the client @todo Array
		# @param [Fixnum] flags Options controlling the request, see msdn url
		# @param [Fixnum] context A pointer to a variable that contains the application-defined value
		#   that associates this operation with any application data @todo
		# @raise [RuntimeError] if Windows returns an error
		#
		def _http_open_request(connect, object_name, verb = "GET", opts = {})
			flags_default = "INTERNET_FLAG_HYPERLINK | INTERNET_FLAG_IGNORE_CERT_CN_INVALID"
			flags_default << " | INTERNET_FLAG_IGNORE_CERT_DATE_INVALID"
			flags_default << " | INTERNET_FLAG_IGNORE_REDIRECT_TO_HTTPS"
			flags_default << " | INTERNET_FLAG_NO_CACHE_WRITE"
			flags_default << " | INTERNET_FLAG_NO_COOKIES"
			flags_default << " | INTERNET_FLAG_NO_UI"
			flags_default << " | INTERNET_FLAG_PRAGMA_NOCACHE"
			flags_default << " | INTERNET_FLAG_RELOAD"
			defaults = {  # defaults for args in opts hash
				:version => nil, # IE will override the value anyways
				:referer => nil,
				# by default we just accept nearly anything
				:accept_types => ["application/*", "text/*", "image/*", "audio/*", "video/*"],
				:flags => flags_default,
				:context => 0
			}
			# array must have a null terminator, we can't detect one easily, so we add it no matter what
			defaults[:accept_types].push(nil)

			# Merge in defaults. This approach allows caller to safely pass in a nil
			opts = defaults.merge(opts)

			# Any more arg validation can go here

			ret = run_dll_function(:wininet, :HttpOpenRequest, connect, verb, object_name,
				opts[version],
				opts[referer],
				opts[lplpsz_accept_types],
				opts[flags],
				opts[context]
			)

			# Additional code goes here

		end

		#
		# Retrieves header information associated with an HTTP request.  Header info can be
		#   strings (default), SYSTEMTIME (for dates), DWORD (for STATUS_CODE, CONTENT_LENGTH,
		#   and so on, if HTTP_QUERY_FLAG_NUMBER has been used).  To retrieve data as a type other
		#   than a string, the appropriate modifier w/the attribute passed to dwInfoLevel must be
		#   included
		# @see http://msdn.microsoft.com/en-us/library/windows/desktop/aa384238(v=vs.85).aspx
		#  HttpQueryInfo
		# @see http://msdn.microsoft.com/en-us/library/windows/desktop/aa385351(v=vs.85).aspx
		#  Query Info Flags

		# @return [Boolean] Returns true if successful, or false otherwise
		# @param [Handle] request Handle returned by HttpOpenRequest or InternetOpenUrl
		# @param [Fixnum] info_level Combination of an attribute to be retrieved and flags that
		#   modify the request
		# @param [String] buffer Buffer (PBLOB) to receive the requested information
		# @param [Fixnum] buffer_length The size in bytes of buffer
		# @param [Fixnum] index Zero-based header index used to enumerate multiple headers w/same name
		# @raise [RuntimeError] if Windows returns an error (ERROR_INSUFFICIENT_BUFFER)
		#
		def _http_query_info(request, buffer, index = 0, info_level = nil, buffer_length = nil)
			info_level ||= 'HTTP_QUERY_RAW_HEADERS_CRLF' # all headers returned by the server
			buffer_length ||= buffer.length
			raise RuntimeError.new "In _http_query_info, buffer parameter cannot be nil per MSDN"

			# Any arg validation can go here

			ret = run_dll_function(:wininet, :HttpQueryInfo, request, info_level, buffer,
				buffer_length, index
			)

			# Additional code goes here

		end

		#
		# Sends the specified request to the HTTP server, allowing callers to send extra data beyond what is normally passed to HttpSendRequestEx.
		# @see http://msdn.microsoft.com/en-us/library/windows/desktop/aa384247(v=vs.85).aspx HttpSendRequest

		# @return [Boolean] Returns true if successful, or false otherwise
		# @param [Handle] h_request Handle returned by HttpOpenRequest
		# @param [Fixnum] lpsz_headers String that contains the additional headers to be appended to the request
		# @param [Fixnum] dw_headers_length Size of the additional headers, in TCHARs
		# @param [Fixnum] lp_optional Pointer to a buffer containing any optional data to be sent immediately after the request headers
		# @param [Fixnum] dw_optional_length Size of the optional data, in bytes
		#
		# There are quite a few arguments so an opts hash was added.  To clean
		# up the API, you should review it and adjust as needed.  You may want
		# to consider regrouping args for: clarity, so args that are usually
		# left at default values, or are optional, or always a specific value,
		# etc, are put in the opts hash.  Or, you may want to get rid of the
		# opts hash entirely.
		def _http_send_request(request, headers, headers_length, opts = {})
			defaults = {  # defaults for args in opts hash
				:optional => optional_default,
				:optional_length => optional_length_default
			}

			# Merge in defaults. This approach allows caller to safely pass in a nil
			opts = defaults.merge(opts)

			# Any arg validation can go here

			ret = run_dll_function(:wininet, :HttpSendRequest, request, headers, headers_length,
				opts[optional],
				opts[optional_length],
			)

			# Additional code goes here

		end

		#
		# Sends the specified request to the HTTP server.  Recommend against
		# this method as it entails parsing complex data structs.  Use
		# http_send_request instead
		# @see http://msdn.microsoft.com/en-us/library/windows/desktop/aa384318(v=vs.85).aspx HttpSendRequestEx

		# @return [Boolean] If the function succeeds, the function returns true
		# @param [Handle] h_request The handle returned by HttpOpenRequest
		# @param [Fixnum] lp_buffers_in Optional
		# @param [Unknown] lp_buffers_out Reserved
		# @param [Fixnum] dw_flags Reserved
		# @param [Fixnum] dw_context Application-defined context value, if a status callback function has been registered
		#
		# There are quite a few arguments so an opts hash was added.  To clean
		# up the API, you should review it and adjust as needed.  You may want
		# to consider regrouping args for: clarity, so args that are usually
		# left at default values, or are optional, or always a specific value,
		# etc, are put in the opts hash.  Or, you may want to get rid of the
		# opts hash entirely.
		def _http_send_request_ex(request, buffers_in, buffers_out, opts = {})
			defaults = {  # defaults for args in opts hash
				:flags => flags_default,
				:context => context_default
			}

			# Merge in defaults. This approach allows caller to safely pass in a nil
			opts = defaults.merge(opts)

			# Any arg validation can go here

			ret = run_dll_function(:wininet, :HttpSendRequestEx, request, buffers_in, buffers_out,
				opts[flags],
				opts[context],
			)

			# Additional code goes here

		end

		#
		# Attempts to make a connection to the Internet.
		# @see http://msdn.microsoft.com/en-us/library/windows/desktop/aa384331(v=vs.85).aspx
		#   InternetAttemptConnect

		# @return [Unknown] Returns ERROR_SUCCESS if successful, otherwise error code
		# @param [Fixnum] dw_reserved This parameter is reserved and must be 0
		#
		def _internet_attempt_connect(reserved)

			# Any arg validation can go here

			ret = run_dll_function(:wininet, :InternetAttemptConnect, reserved)

			# Additional code goes here

		end

		#
		# Closes a single Internet handle.
		# @see http://msdn.microsoft.com/en-us/library/windows/desktop/aa384350(v=vs.85).aspx InternetCloseHandle

		# @return [Boolean] Returns true if the handle is successfully closed, or false otherwise
		# @param [Handle] h_internet Handle to be closed
		#
		def _internet_close_handle(internet)

			# Any arg validation can go here

			ret = run_dll_function(:wininet, :InternetCloseHandle, internet)

			# Additional code goes here

		end

		#
		# Opens an File Transfer Protocol (FTP) or HTTP session for a given site.
		# @see http://msdn.microsoft.com/en-us/library/windows/desktop/aa384363(v=vs.85).aspx InternetConnect

		# @return [Fixnum] Returns a valid handle to the session if the connection is successful, or NULL otherwise
		# @param [Handle] h_internet Handle returned by a previous call to InternetOpen
		# @param [Fixnum] lpsz_server_name String specifying the host name of an Internet server
		# @param [Unknown] n_server_port Transmission Control Protocol/Internet Protocol (TCP/IP) port on the server
		# @param [Fixnum] lpsz_username String specifying the name of the user to log on
		# @param [Fixnum] lpsz_password String that contains the password to use to log on
		# @param [Fixnum] dw_service Type of service to access
		# @param [Fixnum] dw_flags Options specific to the service used
		# @param [Fixnum] dw_context Pointer to a variable that contains an application-defined value that is used to identify the application context for the returned handle in callbacks
		#
		# There are quite a few arguments so an opts hash was added.  To clean
		# up the API, you should review it and adjust as needed.  You may want
		# to consider regrouping args for: clarity, so args that are usually
		# left at default values, or are optional, or always a specific value,
		# etc, are put in the opts hash.  Or, you may want to get rid of the
		# opts hash entirely.
		def _internet_connect(internet, server_name, server_port, opts = {})
			defaults = {  # defaults for args in opts hash
				:username => username_default,
				:password => password_default,
				:service => service_default,
				:flags => flags_default,
				:context => context_default
			}

			# Merge in defaults. This approach allows caller to safely pass in a nil
			opts = defaults.merge(opts)

			# Any arg validation can go here

			ret = run_dll_function(:wininet, :InternetConnect, internet, server_name, server_port,
				opts[username],
				opts[password],
				opts[service],
				opts[flags],
				opts[context],
			)

			# Additional code goes here

		end

		#
		# Retrieves the connected state of the local system.
		# @see http://msdn.microsoft.com/en-us/library/windows/desktop/aa384702(v=vs.85).aspx InternetGetConnectedState

		# @return [Boolean] Returns true if there is an active modem or a LAN Internet connection, or false if there is no Internet connection, or if all possible Internet connections are not currently active
		# @param [Fixnum] lpdw_flags Pointer to a variable that receives  the connection description
		# @param [Fixnum] dw_reserved This parameter is reserved and must be 0
		#
		def _internet_get_connected_state(flags, reserved)

			# Any arg validation can go here

			ret = run_dll_function(:wininet, :InternetGetConnectedState, flags, reserved)

			# Additional code goes here

		end

		#
		# Retrieves the connected state of the specified Internet connection.
		# @see http://msdn.microsoft.com/en-us/library/windows/desktop/aa384705(v=vs.85).aspx
    #   InternetGetConnectedStateEx

		# @return [Boolean] Returns true if there is an available connection otherwise false
		# @param [Fixnum] lpdw_flags Pointer to a variable that receives the connection description
		# @param [Fixnum] lpsz_connection_name String value that receives the connection name
		# @param [Fixnum] dw_name_len Size of the lpszConnectionName string, in TCHARs
		# @param [Fixnum] dw_reserved This parameter is reserved and must be NULL
		#
		# There are quite a few arguments so an opts hash was added.  To clean
		# up the API, you should review it and adjust as needed.  You may want
		# to consider regrouping args for: clarity, so args that are usually
		# left at default values, or are optional, or always a specific value,
		# etc, are put in the opts hash.  Or, you may want to get rid of the
		# opts hash entirely.
		def _internet_get_connected_state_ex(flags, connection_name, name_len, opts = {})
			defaults = {  # defaults for args in opts hash
				:reserved => reserved_default
			}

			# Merge in defaults. This approach allows caller to safely pass in a nil
			opts = defaults.merge(opts)

			# Any arg validation can go here

			ret = run_dll_function(:wininet, :InternetGetConnectedStateEx, flags, connection_name, name_len,
				opts[reserved],
			)

			# Additional code goes here

		end

		#
		# Retrieves the last error description or server response on the thread
    #   calling this function.
		# @see http://msdn.microsoft.com/en-us/library/windows/desktop/aa384717(v=vs.85).aspx
    #   InternetGetLastResponseInfo

		# @return [Boolean] Returns true if error text was successfully written to
    #   the buffer, otherwise false
		# @param [Fixnum] lpdw_error Pointer to a variable that receives an error
    #   message pertaining to the operation that failed
		# @param [String] lpsz_buffer the error text
		# @param [Fixnum] lpdw_buffer_length the size of the error text, in TCHARs
		#
		def _internet_get_last_response_info(error, buffer, buffer_length)

			# Any arg validation can go here

			ret = run_dll_function(:wininet, :InternetGetLastResponseInfo, error, buffer, buffer_length)

			# Additional code goes here

		end

		#
		# Queries the server to determine the amount of data available.
		# @see http://msdn.microsoft.com/en-us/library/windows/desktop/aa385100(v=vs.85).aspx
    #   InternetQueryDataAvailable

		# @return [Boolean] Returns True on success
		# @param [Handle] h_file Handle returned by InternetOpenUrl,
    #   FtpOpenFile, GopherOpenFile, or HttpOpenRequest
		# @param [Fixnum] lpdw_number_of_bytes_available Pointer to a variable to
    #   receive the number of available bytes
		# @param [Fixnum] dw_flags This parameter is reserved and must be 0
		# @param [Fixnum] dw_context This parameter is reserved and must be 0
		#
		# There are quite a few arguments so an opts hash was added.  To clean
		# up the API, you should review it and adjust as needed.  You may want
		# to consider regrouping args for: clarity, so args that are usually
		# left at default values, or are optional, or always a specific value,
		# etc, are put in the opts hash.  Or, you may want to get rid of the
		# opts hash entirely.
		def _internet_query_data_available(file, number_of_bytes_available, flags=0, context=0)
      # hardcode these values since they are reserved, delete these lines if
      # they ever become un-reserved
      flags = 0
      context = 0

			# Any arg validation can go here

			ret = run_dll_function(:wininet, :InternetQueryDataAvailable,
                              file,
                              number_of_bytes_available,
                              flags,
				                      context
			)

			# Additional code goes here

		end

		#
		# Queries an Internet option on the specified handle.
		# @see http://msdn.microsoft.com/en-us/library/windows/desktop/aa385101(v=vs.85).aspx
    #   InternetQueryOption

		# @return [Boolean] Returns true if successful, or false otherwise
		# @param [Handle] h_internet Handle on which to query information
		# @param [Fixnum] dw_option Internet option to be queried
		# @param [Unknown] lp_buffer Pointer to a buffer to receive option setting
		# @param [Fixnum] lpdw_buffer_length Pointer to a variable that contains the
    #   size of lpBuffer, in bytes
		#
		# There are quite a few arguments so an opts hash was added.  To clean
		# up the API, you should review it and adjust as needed.  You may want
		# to consider regrouping args for: clarity, so args that are usually
		# left at default values, or are optional, or always a specific value,
		# etc, are put in the opts hash.  Or, you may want to get rid of the
		# opts hash entirely.
		def _internet_query_option(internet, option, buffer, opts = {})
			defaults = {  # defaults for args in opts hash
				:buffer_length => buffer_length_default
			}

			# Merge in defaults. This approach allows caller to safely pass in a nil
			opts = defaults.merge(opts)

			# Any arg validation can go here

			ret = run_dll_function(:wininet, :InternetQueryOption, internet, option, buffer,
				opts[buffer_length],
			)

			# Additional code goes here

		end

		#
		# Reads data from a handle opened by InternetOpenUrl, FtpOpenFile, or
    #   HttpOpenRequest
		# @see http://msdn.microsoft.com/en-us/library/windows/desktop/aa385103(v=vs.85).aspx
    #   InternetReadFile

		# @return [Boolean] Returns true if successful otherwise false
		# @param [Handle] h_file Handle returned from a previous call to
    #   InternetOpenUrl, FtpOpenFile, or HttpOpenRequest
		# @param [Unknown] lp_buffer Pointer to a buffer to receive the data
		# @param [Fixnum] dw_number_of_bytes_to_read Number of bytes to be read
		# @param [Fixnum] lpdw_number_of_bytes_read Pointer to a variable to receive
    #   the number of bytes read
		#
		# There are quite a few arguments so an opts hash was added.  To clean
		# up the API, you should review it and adjust as needed.  You may want
		# to consider regrouping args for: clarity, so args that are usually
		# left at default values, or are optional, or always a specific value,
		# etc, are put in the opts hash.  Or, you may want to get rid of the
		# opts hash entirely.
		def _internet_read_file(file, buffer, number_of_bytes_to_read, opts = {})
			defaults = {  # defaults for args in opts hash
				:number_of_bytes_read => number_of_bytes_read_default
			}

			# Merge in defaults. This approach allows caller to safely pass in a nil
			opts = defaults.merge(opts)

			# Any arg validation can go here

			ret = run_dll_function(:wininet, :InternetReadFile, file, buffer, number_of_bytes_to_read,
				opts[number_of_bytes_read],
			)

			# Additional code goes here

		end

		#
		# Reads data from a handle opened by InternetOpenUrl or HttpOpenRequest
		# @see http://msdn.microsoft.com/en-us/library/windows/desktop/aa385105(v=vs.85).aspx
    #   InternetReadFileEx

		# @return [Boolean] Returns true if successful otherwise false
		# @param [Handle] h_file Handle returned by InternetOpenUrl/HttpOpenRequest
		# @param [Unknown] lp_buffers_out Pointer to an INTERNET_BUFFERS structure
    #   to receive the data downloaded
		# @param [Fixnum] dw_flags This parameter can be one of the following values
    #   IRF_ASYNC - Identical to WININET_API_FLAG_ASYNC
    #   IRF_SYNC - Identical to WININET_API_FLAG_SYNC
    #   IRF_USE_CONTEXT - Identical to WININET_API_FLAG_USE_CONTEXT
    #   IREF_NO_WAIT - Do not wait for data. If no data available, return either
    #   amount of data requested or amount of data available (whichever smaller)
		# @param [Fixnum] dw_context A caller supplied context value used for async operations
		#
		def _internet_read_file_ex(file, buffers_out, flags, opts = {})
			defaults = {  # defaults for args in opts hash
				:context => context_default
			}

			# Merge in defaults. This approach allows caller to safely pass in a nil
			opts = defaults.merge(opts)

			# Any arg validation can go here

			ret = run_dll_function(:wininet, :InternetReadFileEx, file, buffers_out, flags,
				opts[context],
			)

			# Additional code goes here

		end

		#
		# Creates a cookie associated with the specified URL.
		# @see http://msdn.microsoft.com/en-us/library/windows/desktop/aa385107(v=vs.85).aspx
    #   InternetSetCookie

		# @return [Boolean] Returns true if successful, or false otherwise
		# @param [String] lpsz_url String specifying the URL for which the cookie should be set
		# @param [String] lpsz_cookie_name String specifying the name for the cookie data
		# @param [String] lpsz_cookie_data ptr to the data to associate with the URL
    # @todo should lpsz_cookie_data be a String?
		#
		def _internet_set_cookie(url, cookie_name, cookie_data)

			# Any arg validation can go here

			ret = run_dll_function(:wininet, :InternetSetCookie, url, cookie_name, cookie_data)

			# Additional code goes here

		end

		#
		# Sets a file position for InternetReadFile. This is a synchronous call but
    #   subsequent calls to InternetReadFile might block or return pending if
    #   the data is not available from the cache and the server does not support
    #   random access.
		# @see http://msdn.microsoft.com/en-us/library/windows/desktop/aa385113(v=vs.85).aspx
    #   InternetSetFilePointer

		# @return [Fixnum] If successful, returns the current file position
    # @todo otherwise false?
		# @param [Handle] h_file Handle returned from a previous call to
    #   InternetOpenUrl (on an HTTP or HTTPS URL) or HttpOpenRequest (using the
    #   GET or HEAD HTTP verb & passed to HttpSendRequest or HttpSendRequestEx)
		# @param [Fixnum] l_distance_to_move low 32-bits of signed 64-bit number of bytes to move the
    #   file pointer
		# @param [Fixnum] lp_distance_to_move_high high 32-bits of signed 64-bit distance to move
		# @param [Fixnum] dw_move_method Starting point for the file pointer move
		# @param [Fixnum] dw_context This parameter is reserved and must be 0
		#
		def _internet_set_file_pointer(file, distance_to_move, distance_to_move_high = 0, opts = {})
			defaults = {  # defaults for args in opts hash
				:move_method => 0,
				:context => 0
			}
			# Merge in defaults. This approach allows caller to safely pass in a nil
			opts = defaults.merge(opts)

			# Any arg validation can go here, such as the low/high bit stuff

			ret = run_dll_function(:wininet, :InternetSetFilePointer, file, distance_to_move, distance_to_move_high,
				opts[move_method],
				opts[context]
			)

			# Additional code goes here
      ret
		end

		#
		# Sets an Internet option.
		# @see http://msdn.microsoft.com/en-us/library/windows/desktop/aa385114(v=vs.85).aspx InternetSetOption

		# @return [Boolean] Returns true if successful, or false otherwise
		# @param [Handle] h_internet Handle on which to set information
		# @param [Fixnum] dw_option Internet option to be set
    # @todo what should lp_buffer type be?
		# @param [Fixnum] lp_buffer Pointer to a buffer that contains the option setting
		# @param [Fixnum] dw_buffer_length Size of the lpBuffer buffer
		#
		def _internet_set_option(handle, option, buffer, buffer_length = nil)
      buffer_length ||= buffer.length

			# Any arg validation can go here

			ret = run_dll_function(:wininet, :InternetSetOption, handle, option, buffer, buffer_length)

			# Additional code goes here

		end

		#
		# Unlocks a file that was locked using InternetLockRequestFile.
		# @see http://msdn.microsoft.com/en-us/library/windows/desktop/aa385126(v=vs.85).aspx
    #   InternetUnlockRequestFile

		# @return [Boolean] Returns true if successful, or false otherwise
		# @param [Handle] h_lock_request_info Handle to a lock request that was
    #   returned by InternetLockRequestFile
		#
		def _internet_unlock_request_file(lock_request_info)

			# Any arg validation can go here

			ret = run_dll_function(:wininet, :InternetUnlockRequestFile, lock_request_info)

			# Additional code goes here

		end

		#
		# Writes data to an open Internet file.
		# @see http://msdn.microsoft.com/en-us/library/windows/desktop/aa385128(v=vs.85).aspx
    #   InternetWriteFile

		# @return [Boolean] Returns true if the function succeeds, or false otherwise
		# @param [Handle] h_file Handle returned from a previous call to FtpOpenFile
    #   or an HINTERNET handle sent by HttpSendRequestEx
    # @todo what should lp_buffer type be?
		# @param [Fixnum] lp_buffer Pointer to a buffer that contains the data to be written
		# @param [Fixnum] dw_number_of_bytes_to_write Number of bytes to be written
    #   to the file
		# @param [Fixnum] lpdw_number_of_bytes_written Pointer to a variable that
    #   receives the number of bytes written to the file
		#
		# There are quite a few arguments so an opts hash was added.  To clean
		# up the API, you should review it and adjust as needed.  You may want
		# to consider regrouping args for: clarity, so args that are usually
		# left at default values, or are optional, or always a specific value,
		# etc, are put in the opts hash.  Or, you may want to get rid of the
		# opts hash entirely.
		def _internet_write_file(file, buffer, number_of_bytes_to_write, opts = {})
			defaults = {  # defaults for args in opts hash
				:number_of_bytes_written => number_of_bytes_written_default
			}

			# Merge in defaults. This approach allows caller to safely pass in a nil
			opts = defaults.merge(opts)

			# Any arg validation can go here

			ret = run_dll_function(:wininet, :InternetWriteFile,
                              file,
                              buffer,
                              number_of_bytes_to_write,
				                      opts[number_of_bytes_written],
			)

			# Additional code goes here

		end

		#
		# The ResumeSuspendedDownload function resumes a request that is suspended
    #   by a user interface dialog box.
		# @see http://msdn.microsoft.com/en-us/library/windows/desktop/aa385357(v=vs.85).aspx
    #   ResumeSuspendedDownload

		# @return [Boolean] Returns true if successful; otherwise  false
		# @param [Handle] h_request Handle of the request that is suspended by a
    #   user interface dialog box
		# @param [Fixnum] dw_result_code The error result returned from
    #   InternetErrorDlg, or zero if a different dialog  is  invoked
		#
		def _resume_suspended_download(request, result_code)

			# Any arg validation can go here

			ret = run_dll_function(:wininet, :ResumeSuspendedDownload,
                             request,
                             result_code)

			# Additional code goes here

		end
	end # Ie
end # Browser
end # Windows
end # Post
end # Msf
