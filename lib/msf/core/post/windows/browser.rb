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
	# Allows an application to check if a connection to the Internet can be
	#   established.
	# @see http://msdn.microsoft.com/en-us/library/windows/desktop/aa384346(v=vs.85).aspx
	#   InternetCheckConnection

	# @return [Boolean] Returns true if a connection is made successfully, or
	#   false otherwise
	# @param [String] url a null-terminated string specifying the URL to use
	#   to check the connection.  May be hostname, IP address, or nil.
	# @param [Fixnum] flags Control flags which may be 0 or
	#   FLAG_ICC_FORCE_CONNECTION which forces a connection.
	#   A sockets connection is attempted in the following order:
	#   If +url+ is non-nil, the host value is extracted from it and used to
	#     ping that specific host.
	#   If +url+ is nil and there is an entry in the internal server database
	#     for the nearest server,
	#   the host value is extracted from the entry and used to ping that server.
	# @param [Fixnum] reserved This parameter is reserved and must be 0
	# @return [Boolean] true if a socket connection to url, or 'nearest
	#   server', is successful, else false
	# @raise [RuntimeError] if InternetCheckConnection returns an error
	def internet_check_connection(url, flags, reserved = 0)

		# Force reserved to be 0 in case it was changed.
		# We leave it in in case it ever becomes un-reserved, then our API won't
		# change and we can just remove the line below
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

		#
		# Adds one or more HTTP request headers to the HTTP request handle.
		# @see http://msdn.microsoft.com/en-us/library/windows/desktop/aa384227(v=vs.85).aspx
		#   HttpAddRequestHeaders

		# @return [Boolean] Returns true if successful, or false otherwise
		# @param [Fixnum] request Handle returned by a call to the
		#   HttpOpenRequest function
		# @param [String] headers String variable containing the
		#   headers to append to the request
		# @param [Fixnum] headers_length Size of lpszHeaders, in TCHARs
		# @param [Fixnum] modifiers Controls the semantics of this function
		#
		def _http_add_request_headers(request, headers, opts = {})
			defaults = {  # defaults for args in opts hash
				:headers_length => (headers.length*2) # @todo is this right?
				:modifiers => modifiers_default # @todo: what is this? see msdn
			}

			# # Merge in defaults. This approach allows caller to safely pass in a nil
			opts = defaults.merge(opts)

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
		# @return [Boolean] If the function succeeds, the function returns true
		# @param [Fixnum] request Handle returned by HttpOpenRequest and sent by
		#   HttpSendRequestEx
		# @param [Nil] buffers_out Parameter is reserved and must be NULL
		# @param [Fixnum] flags Parameter is reserved and must be set to 0
		# @param [Fixnum] context Parameter is reserved and must be set to 0
		#
		def _http_end_request(request, opts = {})
			defaults = {  # defaults for args in opts hash
				:buffers_out => nil, # reserved
				:flags       => 0,   # reserved
				:context     => 0,   # reserved
			}

			# # Merge in defaults. Normally, we use
			#   opts = defaults.merge(opts)
			#   Because this approach allows caller to safely pass in a nil
			# However, in this case, they shouldn't be allowed to do so as all
			#   the possibilities are currently reserved, so we reverse it below
			# Enforce the reserved values.
			opts = opts.# Merge(defaults)
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
		# @return [Fixnum] Returns an HTTP request handle if successful, or NULL
		#   otherwise
		# @param [Fixnum] connect handle to an HTTP session returned by
		#   InternetConnect
		# @param [String] verb Contains the HTTP verb to use in the request
		# @param [String] object_name Name of the target object to be retrieved.
		#   Ggenerally a file name, an executable module, or search specifier.
		# @param [String] version The HTTP version to use in the request
		# @param [String] referer Specifies the URL of the document from which
		#   the URL in the request (+object_name+) was obtained
		# @param [String] accept_types Indicates media types accepted by the
		#   client @todo Array
		# @param [Fixnum] flags Internet options
		# @param [Fixnum] context A pointer to a variable that contains the
		#   application-defined value that associates this operation with any
		#   application data @todo
		#
		def _http_open_request(connect, verb, object_name, opts = {})
			defaults = {  # defaults for args in opts hash
				:version => "1.1", # @todo or 1.0?
				:referer => referer_default, # @todo
				:accept_types => accept_types_default, # @todo
				:flags => flags_default, # @todo
				:context => context_default # @todo
			}

			# # Merge in defaults. This approach allows caller to safely pass in a nil
			opts = defaults.merge(opts)

			# Any arg validation can go here

			ret = run_dll_function(:wininet, :HttpOpenRequest, connect, verb, object_name,
				opts[version],
				opts[referer],
				opts[lplpsz_accept_types],
				opts[flags],
				opts[context],
			)

			# Additional code goes here

		end

		#
		# Retrieves header information associated with an HTTP request.
		# @see http://msdn.microsoft.com/en-us/library/windows/desktop/aa384238(v=vs.85).aspx HttpQueryInfo

		# @return [Boolean] Returns true if successful, or false otherwise
		# @param [Fixnum] h_request Handle returned by HttpOpenRequest or InternetOpenUrl
		# @param [Fixnum] dw_info_level Combination of an attribute to be retrieved and flags that modify the request
		# @param [Fixnum] lpv_buffer Pointer to a buffer to receive the requested information
		# @param [Fixnum] lpdw_buffer_length Pointer to a variable that contains, on entry, the size in bytes of the buffer pointed to by lpvBuffer
		# @param [Fixnum] lpdw_index Pointer to a zero-based header index used to enumerate multiple headers with the same name
		#
		# There are quite a few arguments so an opts hash was added.  To clean
		# up the API, you should review it and adjust as needed.  You may want
		# to consider regrouping args for: clarity, so args that are usually
		# left at default values, or are optional, or always a specific value,
		# etc, are put in the opts hash.  Or, you may want to get rid of the
		# opts hash entirely.
		def _http_query_info(request, info_level, buffer, opts = {})
			defaults = {  # defaults for args in opts hash
				:buffer_length => buffer_length_default,
				:index => index_default
			}

			# Merge in defaults. This approach allows caller to safely pass in a nil
			opts = defaults.merge(opts)

			# Any arg validation can go here

			ret = run_dll_function(:wininet, :HttpQueryInfo, request, info_level, buffer,
				opts[buffer_length],
				opts[index],
			)

			# Additional code goes here

		end

		#
		# Sends the specified request to the HTTP server, allowing callers to send extra data beyond what is normally passed to HttpSendRequestEx.
		# @see http://msdn.microsoft.com/en-us/library/windows/desktop/aa384247(v=vs.85).aspx HttpSendRequest

		# @return [Boolean] Returns true if successful, or false otherwise
		# @param [Fixnum] h_request Handle returned by HttpOpenRequest
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
		# @param [Fixnum] h_request The 						handle returned by HttpOpenRequest
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
# Everything below here, down to the JAS comment, needs fixing
#
		#
		# Stores data in the specified file in the Internet cache and associates it with the specified URL.
		# @see http://msdn.microsoft.com/en-us/library/windows/desktop/ff384269(v=vs.85).aspx CommitUrlCacheEntryA

		# @return [Boolean] Returns true if successful, or false otherwise
		# @param [Fixnum] lpsz_url_name String variable that contains the source name of the cache entry
		# @param [Fixnum] lpsz_local_file_name String variable that contains the name of the local file that is being cached
		# @param [Fixnum] expire_time FILETIME structure that contains the expire date and time (in Greenwich mean time) of the file that is being cached
		# @param [Fixnum] last_modified_time FILETIME structure that contains the last modified date and time (in Greenwich mean time) of the URL that is being cached
		# @param [Fixnum] cache_entry_type A bitmask indicating the type of cache entry and its properties
		# @param [Fixnum] lp_header_info Pointer to the buffer that contains the header information
		# @param [Fixnum] cch_header_info Size of the header information, in TCHARs
		# @param [Fixnum] lpsz_file_extension This parameter is reserved and must be NULL
		# @param [Fixnum] lpsz_original_url String that contains the original URL, if redirection has occurred
		#
		# There are quite a few arguments so an opts hash was added.  To clean
		# up the API, you should review it and adjust as needed.  You may want
		# to consider regrouping args for: clarity, so args that are usually
		# left at default values, or are optional, or always a specific value,
		# etc, are put in the opts hash.  Or, you may want to get rid of the
		# opts hash entirely.
		def _commit_url_cache_entry_a(url_name, local_file_name, expire_time, opts = {})
			defaults = {  # defaults for args in opts hash
				:last_modified_time => last_modified_time_default,
				:cache_entry_type => cache_entry_type_default,
				:header_info => header_info_default,
				:header_info => header_info_default,
				:file_extension => file_extension_default,
				:original_url => original_url_default
			}

			# Merge in defaults. This approach allows caller to safely pass in a nil
			opts = defaults.merge(opts)

			# Any arg validation can go here

			ret = run_dll_function(:wininet, :CommitUrlCacheEntryA, url_name, local_file_name, expire_time,
				opts[last_modified_time],
				opts[cache_entry_type],
				opts[header_info],
				opts[header_info],
				opts[file_extension],
				opts[original_url],
			)

			# Additional code goes here

		end

		#
		# Stores data in the specified file in the Internet cache and associates it with the specified URL.
		# @see http://msdn.microsoft.com/en-us/library/windows/desktop/ff384270(v=vs.85).aspx CommitUrlCacheEntryW

		# @return [Boolean] Returns true if successful, or false otherwise
		# @param [Fixnum] lpsz_url_name String variable that contains the source name of the cache entry
		# @param [Fixnum] lpsz_local_file_name String variable that contains the name of the local file that is being cached
		# @param [Fixnum] expire_time FILETIME structure that contains the expire date and time (in Greenwich mean time) of the file that is being cached
		# @param [Fixnum] last_modified_time FILETIME structure that contains the last modified date and time (in Greenwich mean time) of the URL that is being cached
		# @param [Fixnum] cache_entry_type A bitmask indicating the type of cache entry and its properties
		# @param [Fixnum] lp_header_info Pointer to the buffer that contains the header information
		# @param [Fixnum] cch_header_info Size of the header information, in TCHARs
		# @param [Fixnum] lpsz_file_extension This parameter is reserved and must be NULL
		# @param [Fixnum] lpsz_original_url String that contains the original URL, if redirection has occurred
		#
		# There are quite a few arguments so an opts hash was added.  To clean
		# up the API, you should review it and adjust as needed.  You may want
		# to consider regrouping args for: clarity, so args that are usually
		# left at default values, or are optional, or always a specific value,
		# etc, are put in the opts hash.  Or, you may want to get rid of the
		# opts hash entirely.
		def _commit_url_cache_entry_w(url_name, local_file_name, expire_time, opts = {})
			defaults = {  # defaults for args in opts hash
				:last_modified_time => last_modified_time_default,
				:cache_entry_type => cache_entry_type_default,
				:header_info => header_info_default,
				:header_info => header_info_default,
				:file_extension => file_extension_default,
				:original_url => original_url_default
			}

			# Merge in defaults. This approach allows caller to safely pass in a nil
			opts = defaults.merge(opts)

			# Any arg validation can go here

			ret = run_dll_function(:wininet, :CommitUrlCacheEntryW, url_name, local_file_name, expire_time,
				opts[last_modified_time],
				opts[cache_entry_type],
				opts[header_info],
				opts[header_info],
				opts[file_extension],
				opts[original_url],
			)

			# Additional code goes here

		end

		#
		# The CreateMD5SSOHash function obtains the default Microsoft Passport password for a specified account or realm, creates an MD5 hash from it using a specified wide-character challenge string, and returns the result as a string of hexadecimal digit bytes.
		# @see http://msdn.microsoft.com/en-us/library/windows/desktop/aa383962(v=vs.85).aspx CreateMD5SSOHash

		# @return [Boolean] Returns true if successful, or false otherwise
		# @param [Fixnum] psz_challenge_info Pointer to the wide-character challenge string to use for the MD5 hash
		# @param [Fixnum] pwsz_realm String that names a realm for which to obtain the password
		# @param [Fixnum] pwsz_target String that names an account for which to obtain the password
		# @param [Unknown] pb_hex_hash Pointer to an output buffer into which the MD5 hash is returned in hex string format
		#
		# There are quite a few arguments so an opts hash was added.  To clean
		# up the API, you should review it and adjust as needed.  You may want
		# to consider regrouping args for: clarity, so args that are usually
		# left at default values, or are optional, or always a specific value,
		# etc, are put in the opts hash.  Or, you may want to get rid of the
		# opts hash entirely.
		def _create_md5_sso_hash(challenge_info, realm, target, opts = {})
			defaults = {  # defaults for args in opts hash
				:hex_hash => hex_hash_default
			}

			# Merge in defaults. This approach allows caller to safely pass in a nil
			opts = defaults.merge(opts)

			# Any arg validation can go here

			ret = run_dll_function(:wininet, :CreateMD5SSOHash, challenge_info, realm, target,
				opts[hex_hash],
			)

			# Additional code goes here

		end

		#
		# Attempts to determine the location of a WPAD autoproxy script.
		# @see http://msdn.microsoft.com/en-us/library/windows/desktop/aa383993(v=vs.85).aspx
    #  DetectAutoProxyUrl

		# @return [Boolean] Returns true if successful, or false otherwise
		# @param [Fixnum] lpsz_auto_proxy_url Pointer to a buffer to receive the URL from which a WPAD autoproxy script can be downloaded
		# @param [Fixnum] dw_auto_proxy_url_length Size of the buffer pointed to by lpszAutoProxyUrl, in bytes
		# @param [Fixnum] dw_detect_flags Automation detection type
		#
		def _detect_auto_proxy_url(auto_proxy_url, auto_proxy_url_length, detect_flags)

			# Any arg validation can go here

			ret = run_dll_function(:wininet, :DetectAutoProxyUrl, auto_proxy_url, auto_proxy_url_length, detect_flags)

			# Additional code goes here

		end

		#
		# The FtpCommand function sends commands directly to an FTP server.
		# @see http://msdn.microsoft.com/en-us/library/windows/desktop/aa384133(v=vs.85).aspx FtpCommand

		# @return [Boolean] Returns true if successful, or false otherwise
		# @param [Fixnum] h_connect A handle returned from a call to InternetConnect
		# @param [Unknown] f_expect_response A Boolean value that indicates whether the application expects a data connection to be established by the FTP server
		# @param [Fixnum] dw_flags A parameter that can be set to one of the following values
		# @param [Fixnum] lpsz_command A String that contains the command to send to the FTP server
		# @param [Fixnum] dw_context A pointer to a variable that contains an application-defined value used to identify the application context in callback operations
		# @param [Fixnum] ph_ftp_command A pointer to a handle that is created if a valid data socket is opened
		#
		# There are quite a few arguments so an opts hash was added.  To clean
		# up the API, you should review it and adjust as needed.  You may want
		# to consider regrouping args for: clarity, so args that are usually
		# left at default values, or are optional, or always a specific value,
		# etc, are put in the opts hash.  Or, you may want to get rid of the
		# opts hash entirely.
    #
    # @todo, move all the ftp stuff somewhere?
    #
		def _ftp_command(connect, expect_response, flags, opts = {})
			defaults = {  # defaults for args in opts hash
				:command => command_default,
				:context => context_default,
				:ph_ftp_command => ph_ftp_command_default
			}

			# Merge in defaults. This approach allows caller to safely pass in a nil
			opts = defaults.merge(opts)

			# Any arg validation can go here

			ret = run_dll_function(:wininet, :FtpCommand, connect, expect_response, flags,
				opts[command],
				opts[context],
				opts[ph_ftp_command],
			)

			# Additional code goes here

		end

		#
		# Creates a new directory on the FTP server.
		# @see http://msdn.microsoft.com/en-us/library/windows/desktop/aa384136(v=vs.85).aspx FtpCreateDirectory

		# @return [Boolean] Returns true if successful, or false otherwise
		# @param [Fixnum] h_connect Handle returned by a previous call to InternetConnect using INTERNET_SERVICE_FTP
		# @param [Fixnum] lpsz_directory String that contains the name of the directory to be created
		#
		def _ftp_create_directory(connect, directory)

			# Any arg validation can go here

			ret = run_dll_function(:wininet, :FtpCreateDirectory, connect, directory)

			# Additional code goes here

		end

		#
		# Deletes a file stored on the FTP server.
		# @see http://msdn.microsoft.com/en-us/library/windows/desktop/aa384142(v=vs.85).aspx FtpDeleteFile

		# @return [Boolean] Returns true if successful, or false otherwise
		# @param [Fixnum] h_connect Handle returned by a previous call to InternetConnect using INTERNET_SERVICE_FTP
		# @param [Fixnum] lpsz_file_name String that contains the name of the file to be deleted
		#
		def _ftp_delete_file(connect, file_name)

			# Any arg validation can go here

			ret = run_dll_function(:wininet, :FtpDeleteFile, connect, file_name)

			# Additional code goes here

		end

		#
		# Searches the specified directory of the given FTP session. File and directory entries are returned to the application in the WIN32_FIND_DATA structure.
		# @see http://msdn.microsoft.com/en-us/library/windows/desktop/aa384146(v=vs.85).aspx FtpFindFirstFile

		# @return [Fixnum] Returns a valid handle for the request if the directory enumeration was started successfully, or returns NULL otherwise
		# @param [Fixnum] h_connect Handle to an FTP session returned from InternetConnect
		# @param [Fixnum] lpsz_search_file String specifying a valid directory path or file name for the FTP server's file system
		# @param [Unknown] lp_find_file_data Pointer to a WIN32_FIND_DATA structure that receives information about the found file or directory
		# @param [Fixnum] dw_flags Controls the behavior of this function
		# @param [Fixnum] dw_context Pointer to a variable specifying the application-defined value that associates this search with any application data
		#
		# There are quite a few arguments so an opts hash was added.  To clean
		# up the API, you should review it and adjust as needed.  You may want
		# to consider regrouping args for: clarity, so args that are usually
		# left at default values, or are optional, or always a specific value,
		# etc, are put in the opts hash.  Or, you may want to get rid of the
		# opts hash entirely.
		def _ftp_find_first_file(connect, search_file, find_file_data, opts = {})
			defaults = {  # defaults for args in opts hash
				:flags => flags_default,
				:context => context_default
			}

			# Merge in defaults. This approach allows caller to safely pass in a nil
			opts = defaults.merge(opts)

			# Any arg validation can go here

			ret = run_dll_function(:wininet, :FtpFindFirstFile, connect, search_file, find_file_data,
				opts[flags],
				opts[context],
			)

			# Additional code goes here

		end

		#
		# Retrieves the current directory for the specified FTP session.
		# @see http://msdn.microsoft.com/en-us/library/windows/desktop/aa384153(v=vs.85).aspx FtpGetCurrentDirectory

		# @return [Boolean] Returns true if successful, or false otherwise
		# @param [Fixnum] h_connect Handle to an FTP session
		# @param [Fixnum] lpsz_current_directory String that receives the absolute path of the current directory
		# @param [Fixnum] lpdw_current_directory Pointer to a variable specifying the length of the buffer, in TCHARs
		#
		def _ftp_get_current_directory(connect, current_directory, current_directory)

			# Any arg validation can go here

			ret = run_dll_function(:wininet, :FtpGetCurrentDirectory, connect, current_directory, current_directory)

			# Additional code goes here

		end

		#
		# Retrieves a file from the FTP server and stores it under the specified file name, creating a new local file in the process.
		# @see http://msdn.microsoft.com/en-us/library/windows/desktop/aa384157(v=vs.85).aspx FtpGetFile

		# @return [Boolean] Returns true if successful, or false otherwise
		# @param [Fixnum] h_connect Handle to an FTP session
		# @param [Fixnum] lpsz_remote_file String that contains the name of the file to be retrieved
		# @param [Fixnum] lpsz_new_file String that contains the name of the file to be created on the local system
		# @param [Unknown] f_fail_if_exists Indicates whether the function should proceed if a local file of the specified name already exists
		# @param [Fixnum] dw_flags_and_attributes File attributes for the new file
		# @param [Fixnum] dw_flags Controls how the function will handle the file download
		# @param [Fixnum] dw_context Pointer to a variable that contains the application-defined value that associates this search with any application data
		#
		# There are quite a few arguments so an opts hash was added.  To clean
		# up the API, you should review it and adjust as needed.  You may want
		# to consider regrouping args for: clarity, so args that are usually
		# left at default values, or are optional, or always a specific value,
		# etc, are put in the opts hash.  Or, you may want to get rid of the
		# opts hash entirely.
		def _ftp_get_file(connect, remote_file, new_file, opts = {})
			defaults = {  # defaults for args in opts hash
				:fail_if_exists => fail_if_exists_default,
				:flags_and_attributes => flags_and_attributes_default,
				:flags => flags_default,
				:context => context_default
			}

			# Merge in defaults. This approach allows caller to safely pass in a nil
			opts = defaults.merge(opts)

			# Any arg validation can go here

			ret = run_dll_function(:wininet, :FtpGetFile, connect, remote_file, new_file,
				opts[fail_if_exists],
				opts[flags_and_attributes],
				opts[flags],
				opts[context],
			)

			# Additional code goes here

		end

		#
		# Retrieves the file size of the requested FTP resource.
		# @see http://msdn.microsoft.com/en-us/library/windows/desktop/aa384159(v=vs.85).aspx FtpGetFileSize

		# @return [Unknown] Returns the low-order unsigned long integer of the file size of the requested FTP resource
		# @param [Fixnum] h_file Handle returned from a call to FtpOpenFile
		# @param [Fixnum] lpdw_file_size_high Pointer to the high-order unsigned long integer of the file size of the requested FTP resource
		#
		def _ftp_get_file_size(file, file_size_high)

			# Any arg validation can go here

			ret = run_dll_function(:wininet, :FtpGetFileSize, file, file_size_high)

			# Additional code goes here

		end

		#
		# Initiates access to a remote file on an FTP server for reading or writing.
		# @see http://msdn.microsoft.com/en-us/library/windows/desktop/aa384166(v=vs.85).aspx FtpOpenFile

		# @return [Fixnum] Returns a handle if successful, or NULL otherwise
		# @param [Fixnum] h_connect Handle to an FTP session
		# @param [Fixnum] lpsz_file_name String that contains the name of the file to be accessed
		# @param [Fixnum] dw_access File  access
		# @param [Fixnum] dw_flags Conditions under which the transfers occur
		# @param [Fixnum] dw_context Pointer to a variable that contains the application-defined value that associates this search with any application data
		#
		# There are quite a few arguments so an opts hash was added.  To clean
		# up the API, you should review it and adjust as needed.  You may want
		# to consider regrouping args for: clarity, so args that are usually
		# left at default values, or are optional, or always a specific value,
		# etc, are put in the opts hash.  Or, you may want to get rid of the
		# opts hash entirely.
		def _ftp_open_file(connect, file_name, access, opts = {})
			defaults = {  # defaults for args in opts hash
				:flags => flags_default,
				:context => context_default
			}

			# Merge in defaults. This approach allows caller to safely pass in a nil
			opts = defaults.merge(opts)

			# Any arg validation can go here

			ret = run_dll_function(:wininet, :FtpOpenFile, connect, file_name, access,
				opts[flags],
				opts[context],
			)

			# Additional code goes here

		end

		#
		# Stores a file on the FTP server.
		# @see http://msdn.microsoft.com/en-us/library/windows/desktop/aa384170(v=vs.85).aspx FtpPutFile

		# @return [Boolean] Returns true if successful, or false otherwise
		# @param [Fixnum] h_connect Handle to an FTP session
		# @param [Fixnum] lpsz_local_file String that contains the name of the file to be sent from the local system
		# @param [Fixnum] lpsz_new_remote_file String that contains the name of the file to be created on the remote system
		# @param [Fixnum] dw_flags Conditions under which the transfers occur
		# @param [Fixnum] dw_context Pointer to a variable that contains the application-defined value that associates this search with any application data
		#
		# There are quite a few arguments so an opts hash was added.  To clean
		# up the API, you should review it and adjust as needed.  You may want
		# to consider regrouping args for: clarity, so args that are usually
		# left at default values, or are optional, or always a specific value,
		# etc, are put in the opts hash.  Or, you may want to get rid of the
		# opts hash entirely.
		def _ftp_put_file(connect, local_file, new_remote_file, opts = {})
			defaults = {  # defaults for args in opts hash
				:flags => flags_default,
				:context => context_default
			}

			# Merge in defaults. This approach allows caller to safely pass in a nil
			opts = defaults.merge(opts)

			# Any arg validation can go here

			ret = run_dll_function(:wininet, :FtpPutFile, connect, local_file, new_remote_file,
				opts[flags],
				opts[context],
			)

			# Additional code goes here

		end

		#
		# Removes the specified directory on the FTP server.
		# @see http://msdn.microsoft.com/en-us/library/windows/desktop/aa384172(v=vs.85).aspx FtpRemoveDirectory

		# @return [Boolean] Returns true if successful, or false otherwise
		# @param [Fixnum] h_connect Handle to an FTP session
		# @param [Fixnum] lpsz_directory String that contains the name of the directory to be removed
		#
		def _ftp_remove_directory(connect, directory)

			# Any arg validation can go here

			ret = run_dll_function(:wininet, :FtpRemoveDirectory, connect, directory)

			# Additional code goes here

		end

		#
		# Renames a file stored on the FTP server.
		# @see http://msdn.microsoft.com/en-us/library/windows/desktop/aa384175(v=vs.85).aspx FtpRenameFile

		# @return [Boolean] Returns true if successful, or false otherwise
		# @param [Fixnum] h_connect Handle to an FTP session
		# @param [Fixnum] lpsz_existing String that contains the name of the file to be renamed
		# @param [Fixnum] lpsz_new String that contains the new name for the remote file
		#
		def _ftp_rename_file(connect, existing, new)

			# Any arg validation can go here

			ret = run_dll_function(:wininet, :FtpRenameFile, connect, existing, new)

			# Additional code goes here

		end

		#
		# Changes to a different working directory on the FTP server.
		# @see http://msdn.microsoft.com/en-us/library/windows/desktop/aa384178(v=vs.85).aspx FtpSetCurrentDirectory

		# @return [Boolean] Returns true if successful, or false otherwise
		# @param [Fixnum] h_connect Handle to an FTP session
		# @param [Fixnum] lpsz_directory String that contains the name of the directory to become the current working directory
		#
		def _ftp_set_current_directory(connect, directory)

			# Any arg validation can go here

			ret = run_dll_function(:wininet, :FtpSetCurrentDirectory, connect, directory)

			# Additional code goes here

		end

		#
		# Attempts to make a connection to the Internet.
		# @see http://msdn.microsoft.com/en-us/library/windows/desktop/aa384331(v=vs.85).aspx InternetAttemptConnect

		# @return [Unknown] Returns ERROR_SUCCESS if successful, otherwise error code
		# @param [Fixnum] dw_reserved This parameter is reserved and must be 0
		#
		def _internet_attempt_connect(reserved)

			# Any arg validation can go here

			ret = run_dll_function(:wininet, :InternetAttemptConnect, reserved)

			# Additional code goes here

		end

		#
		# Canonicalizes a URL, which includes converting unsafe characters and spaces into escape sequences.
		# @see http://msdn.microsoft.com/en-us/library/windows/desktop/aa384342(v=vs.85).aspx InternetCanonicalizeUrl

		# @return [Boolean] Returns true if successful, or false otherwise
		# @param [Fixnum] lpsz_url A pointer to the string that contains the URL to canonicalize
		# @param [Fixnum] lpsz_buffer A pointer to the buffer that receives the resulting canonicalized URL
		# @param [Fixnum] lpdw_buffer_length A pointer to a variable that contains the size, in characters,  of the lpszBuffer buffer
		# @param [Fixnum] dw_flags Controls canonicalization
		#
		# There are quite a few arguments so an opts hash was added.  To clean
		# up the API, you should review it and adjust as needed.  You may want
		# to consider regrouping args for: clarity, so args that are usually
		# left at default values, or are optional, or always a specific value,
		# etc, are put in the opts hash.  Or, you may want to get rid of the
		# opts hash entirely.
		def _internet_canonicalize_url(url, buffer, buffer_length, opts = {})
			defaults = {  # defaults for args in opts hash
				:flags => flags_default
			}

			# Merge in defaults. This approach allows caller to safely pass in a nil
			opts = defaults.merge(opts)

			# Any arg validation can go here

			ret = run_dll_function(:wininet, :InternetCanonicalizeUrl, url, buffer, buffer_length,
				opts[flags],
			)

			# Additional code goes here

		end

		#
		# Closes a single Internet handle.
		# @see http://msdn.microsoft.com/en-us/library/windows/desktop/aa384350(v=vs.85).aspx InternetCloseHandle

		# @return [Boolean] Returns true if the handle is successfully closed, or false otherwise
		# @param [Fixnum] h_internet Handle to be closed
		#
		def _internet_close_handle(internet)

			# Any arg validation can go here

			ret = run_dll_function(:wininet, :InternetCloseHandle, internet)

			# Additional code goes here

		end

		#
		# Combines a base and relative URL into a single URL. The resultant URL is canonicalized (see InternetCanonicalizeUrl).
		# @see http://msdn.microsoft.com/en-us/library/windows/desktop/aa384355(v=vs.85).aspx InternetCombineUrl

		# @return [Boolean] Returns true if successful, or false otherwise
		# @param [String] lpsz_base_url String that contains the base URL
		# @param [String] lpsz_relative_url String that contains the relative URL
		# @param [String] lpsz_buffer Pointer to a buffer that receives the combined URL
		# @param [Fixnum] lpdw_buffer_length size of the lpszBuffer buffer, in characters
		# @param [Fixnum] dw_flags Controls the operation of the function
		#
		# There are quite a few arguments so an opts hash was added.  To clean
		# up the API, you should review it and adjust as needed.  You may want
		# to consider regrouping args for: clarity, so args that are usually
		# left at default values, or are optional, or always a specific value,
		# etc, are put in the opts hash.  Or, you may want to get rid of the
		# opts hash entirely.
		def _internet_combine_url(base_url, relative_url, buffer, opts = {})
			defaults = {  # defaults for args in opts hash
				:buffer_length => buffer_length_default,
				:flags => flags_default
			}

			# Merge in defaults. This approach allows caller to safely pass in a nil
			opts = defaults.merge(opts)

			# Any arg validation can go here

			ret = run_dll_function(:wininet, :InternetCombineUrl, base_url, relative_url, buffer,
				opts[buffer_length],
				opts[flags],
			)

			# Additional code goes here

		end

		#
		# Checks for changes between secure and nonsecure URLs. Always inform the user when a change
    #   occurs in security between two URLs. Typically, an application should allow the user to
    #   acknowledge the change through interaction with a dialog box.
		# @see http://msdn.microsoft.com/en-us/library/windows/desktop/aa384358(v=vs.85).aspx
    #   InternetConfirmZoneCrossing

		# @return [Unknown] Returns one of the following values
		# @param [Fixnum] h_wnd Handle to the parent window for any required dialog box
		# @param [String] sz_url_prev String specifying the URL viewed before the current request
		# @param [String] sz_url_new String specifying the new URL requested to view
		# @param [Unknown] b_post Not implemented
		#
		# There are quite a few arguments so an opts hash was added.  To clean
		# up the API, you should review it and adjust as needed.  You may want
		# to consider regrouping args for: clarity, so args that are usually
		# left at default values, or are optional, or always a specific value,
		# etc, are put in the opts hash.  Or, you may want to get rid of the
		# opts hash entirely.
		def _internet_confirm_zone_crossing(wnd, url_prev, url_new, opts = {})
			defaults = {  # defaults for args in opts hash
				:post => post_default
			}

			# Merge in defaults. This approach allows caller to safely pass in a nil
			opts = defaults.merge(opts)

			# Any arg validation can go here

			ret = run_dll_function(:wininet, :InternetConfirmZoneCrossing, wnd, url_prev, url_new,
				opts[post],
			)

			# Additional code goes here

		end

		#
		# Opens an File Transfer Protocol (FTP) or HTTP session for a given site.
		# @see http://msdn.microsoft.com/en-us/library/windows/desktop/aa384363(v=vs.85).aspx InternetConnect

		# @return [Fixnum] Returns a valid handle to the session if the connection is successful, or NULL otherwise
		# @param [Fixnum] h_internet Handle returned by a previous call to InternetOpen
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
		# Cracks a URL into its component parts.
		# @see http://msdn.microsoft.com/en-us/library/windows/desktop/aa384376(v=vs.85).aspx InternetCrackUrl

		# @return [Boolean] Returns true if the function succeeds, or false otherwise
		# @param [Fixnum] lpsz_url String that contains the canonical URL to be cracked
		# @param [Fixnum] dw_url_length Size of the lpszUrl string, in TCHARs, or zero if lpszUrl is an ASCIIZ string
		# @param [Fixnum] dw_flags Controls the operation
		# @param [Fixnum] lp_url_components Pointer to a URL_COMPONENTS structure that receives the URL components
		#
		# There are quite a few arguments so an opts hash was added.  To clean
		# up the API, you should review it and adjust as needed.  You may want
		# to consider regrouping args for: clarity, so args that are usually
		# left at default values, or are optional, or always a specific value,
		# etc, are put in the opts hash.  Or, you may want to get rid of the
		# opts hash entirely.
		def _internet_crack_url(url, url_length, flags, opts = {})
			defaults = {  # defaults for args in opts hash
				:url_components => url_components_default
			}

			# Merge in defaults. This approach allows caller to safely pass in a nil
			opts = defaults.merge(opts)

			# Any arg validation can go here

			ret = run_dll_function(:wininet, :InternetCrackUrl, url, url_length, flags,
				opts[url_components],
			)

			# Additional code goes here

		end

		#
		# Creates a URL from its component parts.
		# @see http://msdn.microsoft.com/en-us/library/windows/desktop/aa384473(v=vs.85).aspx InternetCreateUrl

		# @return [Boolean] Returns true if the function succeeds, or false otherwise
		# @param [Fixnum] lp_url_components Pointer to a URL_COMPONENTS structure that contains the components from which to create the URL
		# @param [Fixnum] dw_flags Controls the operation of this function
		# @param [Fixnum] lpsz_url Pointer to a buffer that receives the URL
		# @param [Fixnum] lpdw_url_length Pointer to a variable specifying the size of the URLlpszUrl buffer, in TCHARs
		#
		# There are quite a few arguments so an opts hash was added.  To clean
		# up the API, you should review it and adjust as needed.  You may want
		# to consider regrouping args for: clarity, so args that are usually
		# left at default values, or are optional, or always a specific value,
		# etc, are put in the opts hash.  Or, you may want to get rid of the
		# opts hash entirely.
		def _internet_create_url(url_components, flags, url, opts = {})
			defaults = {  # defaults for args in opts hash
				:url_length => url_length_default
			}

			# Merge in defaults. This approach allows caller to safely pass in a nil
			opts = defaults.merge(opts)

			# Any arg validation can go here

			ret = run_dll_function(:wininet, :InternetCreateUrl, url_components, flags, url,
				opts[url_length],
			)

			# Additional code goes here

		end

		#
		# Continues a file search started as a result of a previous call to FtpFindFirstFile.
		# @see http://msdn.microsoft.com/en-us/library/windows/desktop/aa384698(v=vs.85).aspx InternetFindNextFile

		# @return [Boolean] Returns true if the function succeeds, or false otherwise
		# @param [Fixnum] h_find Handle returned from either FtpFindFirstFile or  InternetOpenUrl (directories only)
		# @param [Unknown] lpv_find_data Pointer to the buffer that receives information about the  file or directory
		#
		def _internet_find_next_file(find, find_data)

			# Any arg validation can go here

			ret = run_dll_function(:wininet, :InternetFindNextFile, find, find_data)

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
				:flags => "INTERNET_FLAG_ASYNC || INTERNET_FLAG_FROM_CACHE" # @todo is this how?
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
		# @param [Fixnum] h_internet The handle to the current Internet session
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
		# Queries the server to determine the amount of data available.
		# @see http://msdn.microsoft.com/en-us/library/windows/desktop/aa385100(v=vs.85).aspx
    #   InternetQueryDataAvailable

		# @return [Boolean] Returns True on success
		# @param [Fixnum] h_file Handle returned by InternetOpenUrl,
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
		# @param [Fixnum] h_internet Handle on which to query information
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
		# @param [Fixnum] h_file Handle returned from a previous call to
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
		# @param [Fixnum] h_file Handle returned by InternetOpenUrl/HttpOpenRequest
		# @param [Unknown] lp_buffers_out Pointer to an INTERNET_BUFFERS structure
    #   to receive the data downloaded
		# @param [Fixnum] dw_flags This parameter can be one of the following values
    #   IRF_ASYNC - Identical to WININET_API_FLAG_ASYNC
    #   IRF_SYNC - Identical to WININET_API_FLAG_SYNC
    #   IRF_USE_CONTEXT - Identical to WININET_API_FLAG_USE_CONTEXT
    #   IREF_NO_WAIT - Do not wait for data. If no data available, return either
    #   amount of data requested or amount of data available (whichever smaller)
		# @param [Fixnum] dw_context A caller supplied context value used for
    #   asynchronous operations
		#
		# There are quite a few arguments so an opts hash was added.  To clean
		# up the API, you should review it and adjust as needed.  You may want
		# to consider regrouping args for: clarity, so args that are usually
		# left at default values, or are optional, or always a specific value,
		# etc, are put in the opts hash.  Or, you may want to get rid of the
		# opts hash entirely.
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
		# @param [Fixnum] lpsz_cookie_name String specifying the name to be associated with the cookie data
		# @param [Fixnum] lpsz_cookie_data ptr to the data to associate with the URL
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

		# @return [Unknown] If successful, it returns the current file position
		# @param [Fixnum] h_file Handle returned from a previous call to
    #   InternetOpenUrl (on an HTTP or HTTPS URL) or HttpOpenRequest (using the
    #   GET or HEAD HTTP verb & passed to HttpSendRequest or HttpSendRequestEx)
		# @param [Unknown] l_distance_to_move The low order 32-bits of a signed
    #   64-bit number of bytes to move the file pointer
		# @param [Unknown] lp_distance_to_move_high A pointer to the high order
    #   32-bits of the signed 64-bit distance to move
		# @param [Fixnum] dw_move_method Starting point for the file pointer move
		# @param [Fixnum] dw_context This parameter is reserved and must be 0
		#
		# There are quite a few arguments so an opts hash was added.  To clean
		# up the API, you should review it and adjust as needed.  You may want
		# to consider regrouping args for: clarity, so args that are usually
		# left at default values, or are optional, or always a specific value,
		# etc, are put in the opts hash.  Or, you may want to get rid of the
		# opts hash entirely.
		def _internet_set_file_pointer(file, distance_to_move, distance_to_move_high, opts = {})
			defaults = {  # defaults for args in opts hash
				:move_method => move_method_default,
				:context => context_default
			}

			# Merge in defaults. This approach allows caller to safely pass in a nil
			opts = defaults.merge(opts)

			# Any arg validation can go here

			ret = run_dll_function(:wininet, :InternetSetFilePointer, file, distance_to_move, distance_to_move_high,
				opts[move_method],
				opts[context],
			)

			# Additional code goes here

		end

		#
		# Sets an Internet option.
		# @see http://msdn.microsoft.com/en-us/library/windows/desktop/aa385114(v=vs.85).aspx InternetSetOption

		# @return [Boolean] Returns true if successful, or false otherwise
		# @param [Fixnum] h_internet Handle on which to set information
		# @param [Fixnum] dw_option Internet option to be set
		# @param [Fixnum] lp_buffer Pointer to a buffer that contains the option setting
		# @param [Fixnum] dw_buffer_length Size of the lpBuffer buffer
		#
		# There are quite a few arguments so an opts hash was added.  To clean
		# up the API, you should review it and adjust as needed.  You may want
		# to consider regrouping args for: clarity, so args that are usually
		# left at default values, or are optional, or always a specific value,
		# etc, are put in the opts hash.  Or, you may want to get rid of the
		# opts hash entirely.
		def _internet_set_option(internet, option, buffer, opts = {})
			defaults = {  # defaults for args in opts hash
				:buffer_length => buffer_length_default
			}

			# Merge in defaults. This approach allows caller to safely pass in a nil
			opts = defaults.merge(opts)

			# Any arg validation can go here

			ret = run_dll_function(:wininet, :InternetSetOption, internet, option, buffer,
				opts[buffer_length],
			)

			# Additional code goes here

		end

		#
		# Formats a date and time according to the HTTP version 1.0 specification.
		# @see http://msdn.microsoft.com/en-us/library/windows/desktop/aa385123(v=vs.85).aspx
    #   InternetTimeFromSystemTime

		# @return [Boolean] Returns true if the function succeeds otherwise false
		# @param [Unknown] pst Pointer to a SYSTEMTIME structure that contains the
    #   date and time to format
		# @param [Fixnum] dw_rfc RFC format used
		# @param [Fixnum] lpsz_time String buffer that receives the
    #   formatted date and time
		# @param [Fixnum] cb_time Size of the lpszTime buffer, in bytes
		#
		# There are quite a few arguments so an opts hash was added.  To clean
		# up the API, you should review it and adjust as needed.  You may want
		# to consider regrouping args for: clarity, so args that are usually
		# left at default values, or are optional, or always a specific value,
		# etc, are put in the opts hash.  Or, you may want to get rid of the
		# opts hash entirely.
		def _internet_time_from_system_time(pst, rfc, time, opts = {})
			defaults = {  # defaults for args in opts hash
				:time => time_default
			}

			# Merge in defaults. This approach allows caller to safely pass in a nil
			opts = defaults.merge(opts)

			# Any arg validation can go here

			ret = run_dll_function(:wininet, :InternetTimeFromSystemTime,
                              pst,
                              rfc,
                              time,
				                      opts[time]
			)

			# Additional code goes here

		end

		#
		# Converts an HTTP time/date string to a SYSTEMTIME structure.
		# @see http://msdn.microsoft.com/en-us/library/windows/desktop/aa385125(v=vs.85).aspx
    #   InternetTimeToSystemTime

		# @return [Boolean] Returns true if the string was converted otherwise false
		# @param [Fixnum] lpsz_time String specifying the date/time to be converted
		# @param [Fixnum] pst Pointer to a SYSTEMTIME structure that receives the
    #   converted time
		# @param [Fixnum] dw_reserved This parameter is reserved and must be 0
		#
		def _internet_time_to_system_time(time, pst, reserved)

			# Any arg validation can go here

			ret = run_dll_function(:wininet, :InternetTimeToSystemTime,
                              time,
                              pst,
                              reserved)

			# Additional code goes here

		end

		#
		# Unlocks a file that was locked using InternetLockRequestFile.
		# @see http://msdn.microsoft.com/en-us/library/windows/desktop/aa385126(v=vs.85).aspx
    #   InternetUnlockRequestFile

		# @return [Boolean] Returns true if successful, or false otherwise
		# @param [Fixnum] h_lock_request_info Handle to a lock request that was
    #   returned by InternetLockRequestFile
		#
		def _internet_unlock_request_file(lock_request_info)

			# Any arg validation can go here

			ret = run_dll_function(:wininet, :InternetUnlockRequestFile,
                              lock_request_info)

			# Additional code goes here

		end

		#
		# Writes data to an open Internet file.
		# @see http://msdn.microsoft.com/en-us/library/windows/desktop/aa385128(v=vs.85).aspx
    #   InternetWriteFile

		# @return [Boolean] Returns true if the function succeeds, or false otherwise
		# @param [Fixnum] h_file Handle returned from a previous call to FtpOpenFile
    #   or an HINTERNET handle sent by HttpSendRequestEx
		# @param [Fixnum] lp_buffer Pointer to a buffer that contains the data to be
    #   written to the file
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
		# @param [Fixnum] h_request Handle of the request that is suspended by a
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
