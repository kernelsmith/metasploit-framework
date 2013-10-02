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

	#
	# This private method helps DRY out our code and provides basic error handling and messaging.
	# It only returns the "return" part of the hash returned by railgun, unless there is an error
	# @example session.railgun.wininet.send(:InternetOpen, nil, "my ua string", "INTERNET_OPEN_TYPE_DIRECT", nil, nil, 0)
	# @param [Symbol] DLL name as a Symbol
	# @param [Symbol] C Function name as a Symbol
	# @param [String, nil] Custom error message to use instead of dyanmically generated message
	# @todo finish this yard doc
	# @param Variable number of additional args as needed
	# @return varies depending on the C-function that is called
	# def run_dll_function(args)
	# 	dll_as_sym = args.delete_at(0)
	# 	#args += function_args.map {|arg| arg ? "\'#{arg}\'" : nil}
	# 	puts "Session is #{session.to_s}"
	# 	puts "Calling:  session.railgun.send(#{dll_as_sym.to_s}).send(#{args.join(',')})"
	# 	#client.railgun.send(:wininet).send(:InternetGetConnectedState, 4, 0)
	# 	results = session.railgun.send(dll_as_sym).send(args.join(",")) # use this array format to avoid extra comma when args initially empty
	# 	err = results["GetLastError"]
	# 	if not err == 0
	# 		err_code = results['GetLastError']
	# 		error_msg = "Error running #{dll_as_sym.to_s}.dll function.  #{function_name_as_sym.to_s} error code: #{err_code}\n"
	# 		error_msg += "This WinAPI error may mean:  #{lookup_error(err_code, /^ERROR_/)}"
	# 		# @todo subclass ? RuntimeError so we can return err msg plus the stuff from railgun?
	# 		# @todo use railgun error lookups, errors will be ERROR_INTERNET and just ERROR_
	# 		raise RuntimeError.new(error_msg)
	# 	else
	# 		results # ["return"]
	# 	end
	# end

	def pointer
		session.railgun.util.pointer_size
	end

	def handle_railgun_hash(results, function, dll = "WinINet")
    function = function.to_s # in case we get it as symbol
    dll = dll.to_s.sub(/\.dll$/,'') # in case we get it as a symbol and/or .dll included
    # we received
    puts "Railgun returned #{results.inspect} for #{dll}!#{function}"
		err = results['GetLastError']
		if not err == 0
      puts "Error code was not 0"
			err_code = results['GetLastError']
			error_msg = "Error running #{dll}.dll function.  #{function} error code: #{err_code}\n"
			#error_msg += "This WinAPI error may mean:  #{lookup_error(err_code, /^ERROR_/)}"
      puts error_msg
			# @todo subclass ? RuntimeError so we can return err msg plus the stuff from railgun?
			# @todo use railgun error lookups, errors will be ERROR_INTERNET and just ERROR_
			raise RuntimeError.new(error_msg)
		else
			results # ["return"]
		end
	end

	#
	# Get default browser
	#
	# @return [String] The name of the default browser as stored in the registry
	#
	# def default_browser
	# 	# @TODO actually write this
	# 	raise NotImplementedError "default_browser is not yet implemented."

	# 	# serviceskey = "HKLM\\SYSTEM\\CurrentControlSet\\Services"
	# 	# a =[]
	# 	# services = []
	# 	# keys = registry_enumkeys(serviceskey)
	# 	default_browser_name = "IE"
	# 	return default_browser_name
	# end
	# alias :get_default_browser :default_browser

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
		res = session.railgun.wininet.send(:InternetCheckConnectionA, url, flags, reserved)
		handle_railgun_hash(res)
		res["results"]
	end
	alias :check_internet_connection :internet_check_connection

	#module Ie
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


	  # Do Stuff.  If called with a block, yields the http_request_handle for your pleasure and
	  #   closes it, and all the associate "internet" handles when the block returns.
	  #
	  # @param [String] :server
	  # @param [String] :resource
	  # @param [String] :verb
	  # @param [String] :agent
	  # @option [Array<String>, String] :headers
	  # @return [Array<String><Fixnum>, nil] Array consisting of the String body of the
	  #   http response, if any, and the Fixnum HTTP code (200, 404 etc), or nil otherwise
	  # @yield [http_request_handle] Gives the block an http request handle as returned by
	  #   wininet.dll!HttpOpenRequest. When the block returns, the handle will be closed with
	  #   {#internet_close_handle}, along with the other associated internet handles
	  # @raise [RuntimeError] if InternetOpenUrl returns a NULL handle
	  #
	  def send_simple_http_request(server, resource, opts = {})
	  	puts "The host's pointer size is #{pointer}"
			defaults = {  # defaults for args in opts hash
				:verb => "GET",
				# by default we just accept nearly anything
				# but we haven't tested the array thing yet, so we're just gonna do text
				:accept_types => "text/*",
				# we'll need to figure this out tho, as we need application/json etc
				#:accept_types => ["application/*", "text/*", "image/*", "audio/*", "video/*"],
				:agent => UA_IE9_BASIC,
				:headers => []
			}
			# Merge in defaults. This approach allows caller to safely pass in a nil
			opts = defaults.merge(opts)
      puts "after adding defaults, send_simple_http_request has"
      puts "#{opts[:headers].length.to_s} headers which are:#{opts[:headers].inspect}"
	  	# we've only tested w/one header so far, need to see how to format
	  	# multiple since it's supposed to be a Windows array, nil-terminated
	  	# for now we concat w/nils and make sure one get's appended to the end
	  	#win_hdrs = arrayify(headers) # @todo, I'm not sure they have to be arrayified as such
	  	opts[:headers] = opts[:headers].join("\r\n") + "\r\n" # join won't add one to the end
	  	# since HttpSendRequest says:  Pointer to a null-terminated string that contains the
	  	# additional headers to be appended to the request. This parameter can be NULL if there
	  	# are no additional headers to be appended.

			internet_handle = _internet_open(opts[:agent]) 							# InternetOpenA
      puts "InternetOpen returned #{internet_handle.to_s} (handle)"
			session_handle = _internet_connect(internet_handle, server) # InternetConnectA
      puts "InternetConnect returned #{session_handle.to_s} (handle)"
			# accept types can be added manually as a header or via the actual mechanism
			http_request_handle = _http_open_request(session_handle, resource, opts) # HttpOpenRequest
      puts "HttpOpenRequest returned #{http_request_handle.to_s} (handle)"
	    if (block_given?)
	      begin
	        yield http_request_handle
	      ensure
	        _http_end_request(http_request_handle) if http_request_handle
	        _internet_close_handle(session_handle) if session_handle
	        _internet_close_handle(internet_handle) if internet_handle
	      end
	    else
        # user passes opts[:data] to pass in PUT/POST data, so we pass this on if nec, but
        # it needs to be opts[:optional] and needs a length
        if opts[:data]
          opts[:optional] = opts[:data]
          opts[:optional_length] = opts[:optional].length
        end

				err_code = _http_send_request(http_request_handle, opts) # HttpSendRequest
        puts "HttpSendRequest returned #{err_code.to_s} (false on success, else err_code)"
				if err_code
          false
        else
          # successful comms, let's check/read the response
					# FYI, http_open_request_ex might actually be easier depending on how you read.
					#
					# After the request is sent, the status code and response headers from the HTTP
					# server are read. These headers are maintained internally and are available to client
					# applications through the HttpQueryInfo function or QueryInfo
					#
					# InternetQueryDataAvailable(http_request_handle)
					# InternetReadFile(http_request_handle)
					# _http_query_info(http_request_handle, query)
					#   where query can be all sorts, incl: HTTP_QUERY_STATUS_CODE
					#   HTTP_QUERY_RAW_HEADERS_CRLF,
					#
					# An application can use the same HTTP request handle in multiple calls to
					# HttpSendRequest, but the application must read all data returned from the previous
					# call before calling the function again.

          # simple for now
          body = get_http_body(http_request_handle)
          puts "Returning the body:#{body} from send_simple_http_request"
          body || true
				end
        # @todo: register open handles in an array and use a method to close them all etc
        _internet_close_handle(http_request_handle) if http_request_handle
        _internet_close_handle(session_handle) if session_handle
        _internet_close_handle(internet_handle) if internet_handle
			end
	  end

		#
		# Initializes an application's use of the WinINet functions.
		# @see http://msdn.microsoft.com/en-us/library/windows/desktop/aa385096(v=vs.85).aspx
    #   InternetOpen

		# @return [Fixnum, nil] Returns a handle to be passed to subsequent WinINet methods
		# @param [String] :agent String user agent string
	  # @param [Hash] :opts
	  # @option opts [String, Fixnum] :access_type ("INTERNET_OPEN_TYPE_PRECONFIG") type of
	  #   access required which can be the String name of, or the Fixnum value of, the
	  #   following Windows constants:
    #   INTERNET_OPEN_TYPE_DIRECT - Resolves all host names locally.
    #   INTERNET_OPEN_TYPE_PRECONFIG - Get proxy or direct config from registry
    #   INTERNET_OPEN_TYPE_PRECONFIG_WITH_NO_AUTOPROXY - Retrieve proxy or
    #   direct config from registry and prevent the use of a startup JScript or
    #   Internet Setup (INS) file.
    #   INTERNET_OPEN_TYPE_PROXY - Passes requests to the proxy unless a proxy
    #   bypass list is supplied and name to be resolved bypasses the proxy. In
    #   that case use INTERNET_OPEN_TYPE_DIRECT.
		# @option opts [String, nil] :proxy_name (nil) String which specifies the name of the
    #   proxy server(s) to use when dwAccessType (+access_type+) is
    #   INTERNET_OPEN_TYPE_PROXY, otherwise this parameter is ignored and should be nil
		# @option opts [String, nil] :proxy_bypass (nil) String which specifies an optional list
    #   of host names or IP addresses, or both, that should not be routed
    #   through the proxy when dwAccessType is set to INTERNET_OPEN_TYPE_PROXY.
    #   The list can contain wildcards but do NOT use an empty string.  This
    #   param is ignored and should be nil if dwAccessType is not set to
    #   INTERNET_OPEN_TYPE_PROXY.  See ref above for more info.
		# @option opts [String, Fixnum] :flags ('INTERNET_FLAG_ASYNC | INTERNET_FLAG_FROM_CACHE')
		#   any combo of the following:
    #   INTERNET_FLAG_ASYNC - Makes only asynchronous requests on handles
    #   descendant from the handle returned from this function.
    #   INTERNET_FLAG_FROM_CACHE - Does not make network requests. All entities
    #   are returned from the cache. If the requested item is not in the cache,
    #   an error (such as ERROR_FILE_NOT_FOUND) is returned.
    #   INTERNET_FLAG_OFFLINE - Identical to INTERNET_FLAG_FROM_CACHE

		def _internet_open(agent, opts = {})
      func = :InternetOpenA
			puts "internet_open received: #{agent} and opts:#{opts.inspect}"
			defaults = {  # defaults for args in opts hash
        :access_type  => 0, # was 0, # was INTERNET_OPEN_TYPE_PRECONFIG
        :proxy_name   => nil,
				:proxy_bypass => nil,
				:flags => 0 # was 'INTERNET_FLAG_ASYNC | INTERNET_FLAG_FROM_CACHE'
			}

			# Merge in defaults. This approach allows caller to safely pass in a nil
			opts = defaults.merge(opts)
			puts "after adding defaults:  #{agent} and opts:#{opts.inspect}"
			#args = [:wininet, :InternetOpenA, agent,opts[:access_type],opts[:proxy_name],
			#				opts[:proxy_bypass],opts[:flags]]
			# Any arg validation can go here
			# @todo determine how/when to send W version of this function
			# puts "Passing this to run_dll_function:#{args}"
			ret = session.railgun.wininet.send(func, agent,
  	 	                          		opts[:access_type],
  	 	                          		opts[:proxy_name],
   		                   						opts[:proxy_bypass],
  	 	                   						opts[:flags]
																		)
      handle_railgun_hash(ret, func)
			# ret = session.railgun.send(:wininet).send(:InternetOpenA, agent,
  	 	#                           opts[:access_type],
  	 	#                           opts[:proxy_name],
   		#                    				opts[:proxy_bypass],
  	 	#                    				opts[:flags]
			# )
			if ret
				ret["return"]
			else
				false
			end
		end

		#
		# Opens an File Transfer Protocol (FTP) or HTTP session for a given site.
		# @see http://msdn.microsoft.com/en-us/library/windows/desktop/aa384363(v=vs.85).aspx
		#   InternetConnect

		# @return [Fixnum, nil] Returns a valid handle to the session or NULL otherwise
		# @param [Fixnum] :internet Handle returned by a previous call to InternetOpen
		# @param [String] :server String specifying the host name or IP of server
		# @param [String, Fixnum] :port Flag specifying port to use, passed as a Windows
		#   constant (the value or the String representation), not an arbitrary port number

	  # @param [Hash] :opts
	  # @option opts [String, nil] :username (nil) String specifying the name of the user to log on
		# @option opts [String, nil] :password (nil) String that contains the password to use to log on
		# @option opts [String, Fixnum] :service ('INTERNET_SERVICE_HTTP') Type of service to
		#   access (Windows constant as a Fixnum value or String representing the constant)
		# @option opts [Fixnum] :flags (0) Options specific to the service used
		# @option opts [Fixnum] :context (+pointer+) pointer to application-defined value used to identify app context
		#
		def _internet_connect(internet, server, port = 'INTERNET_INVALID_PORT_NUMBER', opts = {})
			# NOTE:  see msdn for port values, you can't just pass 80 or 8080 etc, also
      # INTERNET_INVALID_PORT_NUMBER (0x0) will get translated to default port for given service
			# might need WinHTTP.dll functions to call arbitrary tcp/ip ports
      # @see http://msdn.microsoft.com/en-us/library/windows/desktop/aa384091(v=vs.85).aspx
      defaults = {  # defaults for args in opts hash
				:username => nil, # generally only useful w/FTP
				:password => nil, # generally only useful w/FTP
				:service => 'INTERNET_SERVICE_HTTP',
				:flags => 0, # should always be 0 unless FTP passive mode desired
				:context => pointer # 4 for 32b, 8 for 64
			}
			# @todo determine arch of meterp and send 8 for context if required
			# @todo determine how/when to send W version of this function, all A/W fxns really

			# Merge in defaults. This approach allows caller to safely pass in a nil
			opts = defaults.merge(opts)

			# remove any prepended protocol (like http://)
			# @todo should normalize '/' and '\' if any
			server = server.strip.split(/^[a-z]{3,}:\/\//i).last

			ret = session.railgun.wininet.send(:InternetConnectA, internet, server, port,
				opts[:username],
				opts[:password],
				opts[:service],
				opts[:flags],
				opts[:context],
			)
			if ret
				ret["return"]
			else
				false
			end
		end

		#
		# Creates an HTTP request handle.
		# @see http://msdn.microsoft.com/en-us/library/windows/desktop/aa384233(v=vs.85).aspx
		#   HttpOpenRequest
		# @return [Fixnum] Returns an HTTP request handle if successful otherwise nil
		# @param [Fixnum] :connect handle to an internet session returned by InternetConnect
		# @param [String] :object_name Name of the target object to be retrieved, generally a file
		#   name, an executable module, or search specifier.
		# @param [String] :verb The HTTP verb to use in the request.  If anything other than
		#   "GET" or "POST" is specified, HttpOpenRequest automatically sets
		#   INTERNET_FLAG_NO_CACHE_WRITE and INTERNET_FLAG_RELOAD for the request.
		# @param [Hash] :opts
		# @options opts [String,nil] :version (nil) HTTP version to use in request. IE will override
		# @options opts [String,nil] :referer (nil) URL from which the request was made
		# @options opts [Array<String>, String] :accept_types ("text/*") Indicates media types accepted
		# @options opts [Fixnum] :flags Options controlling the request, see msdn url
		# @options opts [Fixnum] :context (0) application-defined & -specific context
		# @raise [RuntimeError] if Windows returns an error
		#
		def _http_open_request(connect, object_name, opts = {})
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
				# but we haven't tested the array thing yet, so we're just gonna do text
				:accept_types => "text/*",
				# we'll need to figure this out tho, as we need application/json etc
				#:accept_types => ["application/*", "text/*", "image/*", "audio/*", "video/*"],
				:flags => flags_default,
				:context => pointer
			}

			# Merge in defaults. This approach allows caller to safely pass in a nil
			opts = defaults.merge(opts)
			# convert array to obedient windows array flattened to a string
			opts[:accept_types] = arrayify(opts[:accept_types])

			ret = session.railgun.wininet.send(:HttpOpenRequestA, connect, opts[:verb], object_name,
				opts[:version],
				opts[:referer],
				opts[:accept_types],
				opts[:flags],
				opts[:context]
			)
			if ret
        puts "ret is #{ret.inspect} (hash)"
				ret["return"]
			else
				false
			end
		end

		#
		# Sends the specified request to the HTTP server, allowing callers to send extra data beyond
		#   what is normally passed to HttpSendRequestEx.
		# @see http://msdn.microsoft.com/en-us/library/windows/desktop/aa384247(v=vs.85).aspx
		#   HttpSendRequest

		# @return [Boolean] Returns true if successful, or false otherwise
		# @param [Handle] :request Handle returned by HttpOpenRequest
		# @param [String, nil] :headers String that containing additional headers to be added,
		#   CRLF separated
		# @param [Fixnum, -1] :headers_length Size, in TCHARs, of the additional headers.  -1
		#   causes the length to be calculated if :headers is not nil
		# @param [Hash] :opts
		# @options opts [String, nil] :optional (nil) String buffer containing any optional
		#   data to be sent immediately after the request headers, useful for PUT/POST etc
		# @options opts [Fixnum, 0] :optional_length Size of the optional data, in bytes
		#
		def _http_send_request(request, opts = {})
			defaults = {  # defaults for args in opts hash
				:headers => nil, # @todo should it be nil or "\x00" or what?
				:headers_length => -1,
				:optional => nil,
				:optional_length => 0
			}

			# Merge in defaults. This approach allows caller to safely pass in a nil
			opts = defaults.merge(opts)

			# calculate length in TCHARs if needed here.  .length * 2 + 1 right?

			ret = session.railgun.wininet.send(:HttpSendRequestA, request,
				opts[:headers],
				opts[:headers_length],
				opts[:optional],
				opts[:optional_length]
			)
      puts "HttpSendRequest return hash:#{ret.inspect}"
			if ret
        err_code = ret['GetLastError']
				unless err_code == 0
          puts "Error code from HttpSendRequest via rails is:#{err_code}"
          puts "The error text may be #{lookup_error(err_code)}"
          ret err_code
        end
			end
      return false # false is success here
		end

    #
    # Retrieves the last error description or server response on the thread
    #   calling this function.
    # @see http://msdn.microsoft.com/en-us/library/windows/desktop/aa384717(v=vs.85).aspx
    #   InternetGetLastResponseInfo

    # @return [Boolean] Returns true if error text was successfully written to
    #   the buffer, otherwise false
    # @param [Fixnum] :error Pointer to a variable that receives an error
    #   message pertaining to the operation that failed
    # @param [String] buffer the error text
    # @param [Fixnum] buffer_length the size of the error text, in TCHARs
    #
    def _internet_get_last_response_info(buffer, buffer_length = -1, error = pointer)

      # Any arg validation can go here

      ret = session.railgun.wininet.send(:InternetGetLastResponseInfoA,
              error,
              buffer,
              buffer_length
              )

      # Additional code goes here

    end

    #
    # Reads data from a handle opened by InternetOpenUrl, FtpOpenFile, or
    #   HttpOpenRequest
    # @see http://msdn.microsoft.com/en-us/library/windows/desktop/aa385103(v=vs.85).aspx
    #   InternetReadFile

    # @return [Boolean] Returns true if successful otherwise false
    # @param [Handle] :file Handle returned from a previous call to
    #   InternetOpenUrl, FtpOpenFile, or HttpOpenRequest
    # @param [Fixnum] :buffer Pointer to a buffer to receive the data (pass pointer size)
    # @param [Fixnum] :number_of_bytes_to_read Number of bytes to be read
    # @param [Fixnum] :number_of_bytes_read Pointer to a variable to receive
    #   the number of bytes read
    #
    def _internet_read_file(file, number_of_bytes_to_read, opts = {})
      defaults = {  # defaults for args in opts hash
        :buffer => number_of_bytes_to_read, #pointer,
        :number_of_bytes_read => pointer
      }

      # Merge in defaults. This approach allows caller to safely pass in a nil
      opts = defaults.merge(opts)

      # Any arg validation can go here

      ret = session.railgun.wininet.send(:InternetReadFile, file,
        opts[:buffer],
        number_of_bytes_to_read,
        opts[:number_of_bytes_read]
      )

      # Additional code goes here

    end

    def get_http_body(file_handle, number_of_bytes_to_read = 256)
      # @todo, handle reading more bytes if nec, insufficient buffer etc
      # @see http://msdn.microsoft.com/en-us/library/windows/desktop/aa385103(v=vs.85).aspx
      res = _internet_query_data_available(file_handle, 4, 0, 0)
      bytes_avail = res["NumberOfBytesAvailable"]
      if (bytes_avail and not bytes_avail == 0)
        res = _internet_read_file(file_handle, bytes_avail)
        puts "_internet_read_file returns #{res} with body being #{res["Buffer"]}"
      else
        puts "There are no bytes available for reading"
        return nil
      end
      if res["GetLastError"] == 0
        res["Buffer"]
      else
        nil
      end
    end

    #
    # Queries an Internet option on the specified handle.
    # @see http://msdn.microsoft.com/en-us/library/windows/desktop/aa385101(v=vs.85).aspx
    #   InternetQueryOption

    # @return [Boolean] Returns true if successful, or false otherwise
    # @param [Handle] :internet Handle on which to query information
    # @param [Fixnum] :option Internet option to be queried
    # @param [Unknown] :buffer Pointer to a buffer to receive option setting
    # @param [Fixnum] :buffer_length Pointer to a variable that contains the
    #   size of lpBuffer, in bytes
    #
    # There are quite a few arguments so an opts hash was added.  To clean
    # up the API, you should review it and adjust as needed.  You may want
    # to consider regrouping args for: clarity, so args that are usually
    # left at default values, or are optional, or always a specific value,
    # etc, are put in the opts hash.  Or, you may want to get rid of the
    # opts hash entirely.
    def _internet_query_option(internet, option, buffer = pointer, opts = {})
      defaults = {  # defaults for args in opts hash
        :buffer_length => -1 # @todo, is this valid?
      }

      # Merge in defaults. This approach allows caller to safely pass in a nil
      opts = defaults.merge(opts)

      # Any arg validation can go here

      ret = session.railgun.wininet.send(:InternetQueryOptionA, internet, option, buffer,
        opts[:buffer_length],
      )

      # Additional code goes here

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
      reserved = {  # defaults for args in opts hash
        :buffers_out => nil, # reserved, must be nil
        :flags       => 0,   # reserved, must be 0
        :context     => 0,   # reserved, must be 0
      }

      # Normally, we use the following to merge in defaults cuz it allows caller to pass in a nil:
      #   opts = defaults.merge(opts)
      #   However, in this case, they shouldn't be allowed to do so as all the possibilities
      #   are currently reserved, so we reverse the merge call to enforce the reserved values.
      opts = opts.merge(reserved)
      session.railgun.wininet.send(:HttpEndRequestA, request,
                  opts[:buffers_out],
                  opts[:flags],
                  opts[:context]
      )
    end

    # ----------------------------------------------------------------- #
    # ################################################################# #
    # ----------------------------------------------------------------- #
    #
    #                                                    Other Methods
    #
    # ----------------------------------------------------------------- #
    # ################################################################# #
    # ----------------------------------------------------------------- #


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
		# @param [Fixnum] context A pointer to a variable specifying the
    #   application-defined value that is passed, along with the returned handle,
    #   to any callback functions.  Pass the pointer size (4 for 32b)
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
				:flags => flags_default, # @todo
				:context => pointer
			}

			# Merge in defaults. This approach allows caller to safely pass in a nil
			opts = defaults.merge(opts)

			# url must start with ftp:, http:, or https:
			url.strip!
			unless url =~ /^(ftp:\/\/|http:\/\/|https:\/\/)/i
				# default to http if you're not going to specify
				url = 'http://' + url
			end

			ret = session.railgun.wininet.send(:InternetOpenUrlA, internet, url, headers,
				opts[:headers_length],
				opts[:flags],
				opts[:context],
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

      ret = session.railgun.wininet.send(:InternetReadFileExA, file, buffers_out, flags,
        opts[:context],
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
			# headers_length can -1L (not sure what that means) and headers are assumed to be
			#  0-terminated (asciiz) and the length will be computed.
			#  @todo, need to test a -1 fixnum, "-1L" and computing it myself
			headers_length ||= (headers.length * 2 + 1) # in TCHARs, so *2 +1 for ascii?ß

			# Any arg validation can go here

			session.railgun.wininet.send(:HttpAddRequestHeadersA,
									request,
									headers,
									opts[:headers_length],
									opts[:modifiers]
			)
		end

		#
		# Retrieves header information associated with an HTTP request.  Header info can be
		#   strings (default), SYSTEMTIME (for dates), DWORD (for STATUS_CODE, CONTENT_LENGTH,
		#   and so on, if HTTP_QUERY_FLAG_NUMBER has been used).  To retrieve data as a type other
		#   than a string, the appropriate modifier w/the attribute passed to InfoLevel must be
		#   included
		# @see http://msdn.microsoft.com/en-us/library/windows/desktop/aa384238(v=vs.85).aspx
		#  HttpQueryInfo
		# @see http://msdn.microsoft.com/en-us/library/windows/desktop/aa385351(v=vs.85).aspx
		#  Query Info Flags for +info_level+

		# @return [Boolean] Returns true if successful, or false otherwise
		# @param [Handle] request Handle returned by HttpOpenRequest or InternetOpenUrl
		# @param [Fixnum] info_level Combination of an attribute to be retrieved and flags that
		#   modify the request @see http://msdn.microsoft.com/en-us/library/windows/desktop/aa385351(v=vs.85).aspx
		# @param [Fixnum] buffer Pointer to buffer (PDWORD) to receive the requested information
		# @param [Fixnum] buffer_length Pointer to he size in bytes of buffer
		# @param [Fixnum] index Pointer to zero-based header index used to enumerate multiple headers w/same name
		# @raise [RuntimeError] if Windows returns an error (ERROR_INSUFFICIENT_BUFFER)
		#
		def _http_query_info(request, opts = {})
      defaults = {  # defaults for args in opts hash
        :info_level     => 'HTTP_QUERY_STATUS_CODE', # just the query status
        # :info_level     => 'HTTP_QUERY_RAW_HEADERS_CRLF', # all headers returned by the server
        :buffer         => pointer,
        :buffer_length  => pointer, # 256 using rsmudge raven ref
        :index          => nil # null using rsmudge raven ref
      }
      opts = defaults.merge(opts)

			# unless buffer
      #   raise RuntimeError.new "In _http_query_info, buffer parameter cannot be nil per MSDN"
      # end
			# Any arg validation can go here

			ret = session.railgun.wininet.send(:HttpQueryInfoA, request,
        opts[:info_level],
        opts[:buffer],
				opts[:buffer_length],
        opts[:index]
			)

			# Additional code goes here

		end

    def http_query_all_headers(request_handle)
      _http_query_info(request_handle, pointer, pointer, 'HTTP_QUERY_RAW_HEADERS_CRLF', pointer)
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
		# @param [Fixnum] :context Application-defined context value, if a status callback function has been registered
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
				:context => pointer
			}

			# Merge in defaults. This approach allows caller to safely pass in a nil
			opts = defaults.merge(opts)

			# Any arg validation can go here

			ret = session.railgun.wininet.send(:HttpSendRequestExA, request, buffers_in, buffers_out,
				opts[:flags],
				opts[:context],
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

			ret = session.railgun.wininet.send(:InternetAttemptConnect, reserved)

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

			ret = session.railgun.wininet.send(:InternetCloseHandle, internet)

			# Additional code goes here

		end

		#
		# Retrieves the connected state of the local system.
		# @see http://msdn.microsoft.com/en-us/library/windows/desktop/aa384702(v=vs.85).aspx
		#   InternetGetConnectedState

		# @return [Fixnum, false] Returns a Fixnum representing the flags returned by the winapi
		#   function call if successful (an active modem or a LAN Internet connection) or false if
		#   there is no Internet connection or all possible Internet connections are not active
		# @param [Fixnum] :flags PDWORD to a variable that receives the connection description.
		#   Should be 4 on 32-bit systems.
		# @param [Fixnum] :reserved This parameter is reserved and must be 0
		#
		def _internet_get_connected_state(flags = pointer , reserved = 0)
      func = :InternetGetConnectedState
			# Any arg validation can go here
			# @todo, should flags be set to 8 when x64?  it's a pdword, not dword
			ret = session.railgun.wininet.send(func, flags, reserved)
			handle_railgun_hash(res, func)
			if res["results"]
				res["flags"]
			else
				false
			end
		end

		#
		# Retrieves the connected state of the specified Internet connection.
		# @see http://msdn.microsoft.com/en-us/library/windows/desktop/aa384705(v=vs.85).aspx
    #   InternetGetConnectedStateEx

		# @return [Boolean] Returns true if there is an available connection otherwise false
		# @param [Fixnum] :flags(+pointer+) Pointer to a variable that receives the
		#   connection description
		# @param [String] :connection_name String value that receives the connection name
		# @param [Fixnum] :name_len Size of the lpszConnectionName string, in TCHARs
		# @param [Fixnum] :reserved(nil) This parameter is reserved and must be NULL
		#
		# There are quite a few arguments so an opts hash was added.  To clean
		# up the API, you should review it and adjust as needed.  You may want
		# to consider regrouping args for: clarity, so args that are usually
		# left at default values, or are optional, or always a specific value,
		# etc, are put in the opts hash.  Or, you may want to get rid of the
		# opts hash entirely.
		def _internet_get_connected_state_ex(connection_name, name_len = -1, opts = {})
			defaults = {  # defaults for args in opts hash
				:flags => pointer,
				:reserved => nil
			}

			# Merge in defaults. This approach allows caller to safely pass in a nil
			opts = defaults.merge(opts)

			# Any arg validation can go here

			ret = session.railgun.wininet.send(:InternetGetConnectedStateExA, opts[:flags], connection_name,
				name_len,
				opts[:reserved]
			)

			# Additional code goes here

		end

		#
		# Queries the server to determine the amount of data available.
		# @see http://msdn.microsoft.com/en-us/library/windows/desktop/aa385100(v=vs.85).aspx
    #   InternetQueryDataAvailable

		# @return [Boolean] Returns True on success
		# @param [Handle] :file Handle returned by InternetOpenUrl,
    #   FtpOpenFile, GopherOpenFile, or HttpOpenRequest
		# @param [Fixnum] :number_of_bytes_available Pointer to a variable to
    #   receive the number of available bytes
		# @param [Fixnum] :flags This parameter is reserved and must be 0
		# @param [Fixnum] :context This parameter is reserved and must be 0
		#
		# There are quite a few arguments so an opts hash was added.  To clean
		# up the API, you should review it and adjust as needed.  You may want
		# to consider regrouping args for: clarity, so args that are usually
		# left at default values, or are optional, or always a specific value,
		# etc, are put in the opts hash.  Or, you may want to get rid of the
		# opts hash entirely.
		def _internet_query_data_available(file, number_of_bytes_available=pointer, flags=0, context=0)
      # hardcode these values since they are reserved, delete these lines if
      # they ever become un-reserved
      flags = 0
      context = 0

			# Any arg validation can go here

			ret = session.railgun.wininet.send(:InternetQueryDataAvailable,
                              file,
                              number_of_bytes_available,
                              flags,
				                      context
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

			ret = session.railgun.wininet.send(:InternetSetCookie, url, cookie_name, cookie_data)

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

			ret = session.railgun.wininet.send(:InternetSetFilePointer, file, distance_to_move, distance_to_move_high,
				opts[:move_method],
				opts[:context]
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

			ret = session.railgun.wininet.send(:InternetSetOption, handle, option, buffer, buffer_length)

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

			ret = session.railgun.wininet.send(:InternetUnlockRequestFile, lock_request_info)

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

			ret = session.railgun.wininet.send(:InternetWriteFile,
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

			ret = session.railgun.wininet.send(:ResumeSuspendedDownload,
                             request,
                             result_code)

			# Additional code goes here

		end

		# turn a list of args into a good windows-in memory array, null terminated
		def arrayify(*args)
			# for now we return nil when args is empty, most win fxns don't want an empty string
			args.empty? ? nil : args.join("\x00") #+ "\x00"
		end

	#end # Ie

end # Browser
end # Windows
end # Post
end # Msf
