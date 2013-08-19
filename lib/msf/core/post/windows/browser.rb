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

	# @return [Boolean] Returns TRUE if a connection is made successfully, or
	#   FALSE otherwise
	# @param [String] url a null-terminated string that specifies the URL to use
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
		# We leave it in in case it ever becomes un-reserved, then
		# we can just remove this line
		reserved = 0
		run_dll_function(:wininet, :InternetCheckConnection, url, flags, reserved)
	end
	alias :check_internet_connection :internet_check_connection

	module Ie
		# API for Internet Explorer manipulation, automation, and control etc

		#
		# The CleanupCredentialCache function is implemented by certain Security
		#   Support Providers (SSP) to flush the SSP credential cache.
		# @see http://msdn.microsoft.com/en-us/library/windows/desktop/aa383938(v=vs.85).aspx
		#   CleanupCredentialCache
		# @return [Boolean] TRUE if the function succeeds; otherwise, FALSE
		#
		def _cleanup_credential_cache()
			run_dll_function(:wininet, :CleanupCredentialCache)
		end

		#
		# Adds one or more HTTP request headers to the HTTP request handle.
		# @see http://msdn.microsoft.com/en-us/library/windows/desktop/aa384227(v=vs.85).aspx
		#   HttpAddRequestHeaders

		# @return [Boolean] Returns TRUE if successful, or FALSE otherwise
		# @param [Fixnum] request Handle returned by a call to the 
		#   HttpOpenRequest function
		# @param [String] headers Pointer to a string variable containing the 
		#   headers to append to the request
		# @param [Fixnum] headers_length Size of lpszHeaders, in TCHARs
		# @param [Fixnum] modifiers Controls the semantics of this function
		#
		def _http_add_request_headers(request, headers, opts = {})
			defaults = {  # defaults for args in opts hash
				:headers_length => (headers.length*2) # @todo is this right?
				:modifiers => modifiers_default # @todo: what is this? see msdn
			}

			# Merge in defaults. This approach allows caller to safely pass in a nil
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
		# @return [Boolean] If the function succeeds, the function returns TRUE
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

			# Merge in defaults. Normally, we use
			#   opts = defaults.merge(opts)
			#   Because this approach allows caller to safely pass in a nil
			# However, in this case, they shouldn't be allowed to do so as all
			#   the possibilities are currently reserved, so we reverse it below
			# Enforce the reserved values.
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
		# @return [Fixnum] Returns an HTTP request handle if successful, or NULL
		#   otherwise
		# @param [Fixnum] connect handle to an HTTP session returned by 
		#   InternetConnect
		# @param [String] verb A pointer to a null-terminated string that 
		#   contains the HTTP verb to use in the request
		# @param [String] object_name A pointer to a null-terminated string that
		#   contains the name of the target object of the specified HTTP verb
		# @param [String] version A pointer to a null-terminated string that 
		#   contains the HTTP version to use in the request
		# @param [String] referer A pointer to a null-terminated string that 
		#   specifies the URL of the document from which the URL in the request 
		#   (lpszObjectName) was obtained
		# @param [String] accept_types A pointer to a null-terminated array of 
		#   strings that indicates media types accepted by the client @todo Array
		# @param [Fixnum] flags Internet options
		# @param [Fixnum] context A pointer to a variable that contains the 
		#   application-defined value that associates this operation with any 
		#   application data @todo
		#
		def _http_open_request(connect, verb = "GET", object_name, opts = {})
			defaults = {  # defaults for args in opts hash
				:version => "1.1" # @todo or 1.0?
				:referer => referer_default # @todo
				:accept_types => accept_types_default # @todo
				:flags => flags_default # @todo
				:context => context_default # @todo
			}

			# Merge in defaults. This approach allows caller to safely pass in a nil
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

		# @return [Boolean] Returns TRUE if successful, or FALSE otherwise
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
				:buffer_length => buffer_length_default
				:index => index_default
			}

			Merge in defaults. This approach allows caller to safely pass in a nil
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

		# @return [Boolean] Returns TRUE if successful, or FALSE otherwise
		# @param [Fixnum] h_request Handle returned by HttpOpenRequest
		# @param [Fixnum] lpsz_headers Pointer to a null-terminated string  that contains the additional headers to be appended to the request
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
				:optional => optional_default
				:optional_length => optional_length_default
			}

			Merge in defaults. This approach allows caller to safely pass in a nil
			opts = defaults.merge(opts)

			# Any arg validation can go here

			ret = run_dll_function(:wininet, :HttpSendRequest, request, headers, headers_length,
				opts[optional],
				opts[optional_length],
			)

			# Additional code goes here

		end

		#
		# Sends the specified request to the HTTP server.
		# @see http://msdn.microsoft.com/en-us/library/windows/desktop/aa384318(v=vs.85).aspx HttpSendRequestEx

		# @return [Boolean] If the function succeeds, the function returns TRUE
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
				:flags => flags_default
				:context => context_default
			}

			Merge in defaults. This approach allows caller to safely pass in a nil
			opts = defaults.merge(opts)

			# Any arg validation can go here

			ret = run_dll_function(:wininet, :HttpSendRequestEx, request, buffers_in, buffers_out,
				opts[flags],
				opts[context],
			)

			# Additional code goes here

		end

#
# Everything below here needs fixing
#
		#
		# Stores data in the specified file in the Internet cache and associates it with the specified URL.
		# @see http://msdn.microsoft.com/en-us/library/windows/desktop/ff384269(v=vs.85).aspx CommitUrlCacheEntryA

		# @return [Boolean] Returns TRUE if successful, or FALSE otherwise
		# @param [Fixnum] lpsz_url_name Pointer to a string variable that contains the source name of the cache entry
		# @param [Fixnum] lpsz_local_file_name Pointer to a string variable that contains the name of the local file that is being cached
		# @param [Fixnum] expire_time FILETIME structure that contains the expire date and time (in Greenwich mean time) of the file that is being cached
		# @param [Fixnum] last_modified_time FILETIME structure that contains the last modified date and time (in Greenwich mean time) of the URL that is being cached
		# @param [Fixnum] cache_entry_type A bitmask indicating the type of cache entry and its properties
		# @param [Fixnum] lp_header_info Pointer to the buffer that contains the header information
		# @param [Fixnum] cch_header_info Size of the header information, in TCHARs
		# @param [Fixnum] lpsz_file_extension This parameter is reserved and must be NULL
		# @param [Fixnum] lpsz_original_url Pointer to a string  that contains the original URL, if redirection has occurred
		#
		# There are quite a few arguments so an opts hash was added.  To clean
		# up the API, you should review it and adjust as needed.  You may want
		# to consider regrouping args for: clarity, so args that are usually
		# left at default values, or are optional, or always a specific value,
		# etc, are put in the opts hash.  Or, you may want to get rid of the
		# opts hash entirely.
		def _commit_url_cache_entry_a(url_name, local_file_name, expire_time, opts = {})
			defaults = {  # defaults for args in opts hash
				:last_modified_time => last_modified_time_default
				:cache_entry_type => cache_entry_type_default
				:header_info => header_info_default
				:header_info => header_info_default
				:file_extension => file_extension_default
				:original_url => original_url_default
			}

			Merge in defaults. This approach allows caller to safely pass in a nil
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

		# @return [Boolean] Returns TRUE if successful, or FALSE otherwise
		# @param [Fixnum] lpsz_url_name Pointer to a string variable that contains the source name of the cache entry
		# @param [Fixnum] lpsz_local_file_name Pointer to a string variable that contains the name of the local file that is being cached
		# @param [Fixnum] expire_time FILETIME structure that contains the expire date and time (in Greenwich mean time) of the file that is being cached
		# @param [Fixnum] last_modified_time FILETIME structure that contains the last modified date and time (in Greenwich mean time) of the URL that is being cached
		# @param [Fixnum] cache_entry_type A bitmask indicating the type of cache entry and its properties
		# @param [Fixnum] lp_header_info Pointer to the buffer that contains the header information
		# @param [Fixnum] cch_header_info Size of the header information, in TCHARs
		# @param [Fixnum] lpsz_file_extension This parameter is reserved and must be NULL
		# @param [Fixnum] lpsz_original_url Pointer to a string  that contains the original URL, if redirection has occurred
		#
		# There are quite a few arguments so an opts hash was added.  To clean
		# up the API, you should review it and adjust as needed.  You may want
		# to consider regrouping args for: clarity, so args that are usually
		# left at default values, or are optional, or always a specific value,
		# etc, are put in the opts hash.  Or, you may want to get rid of the
		# opts hash entirely.
		def _commit_url_cache_entry_w(url_name, local_file_name, expire_time, opts = {})
			defaults = {  # defaults for args in opts hash
				:last_modified_time => last_modified_time_default
				:cache_entry_type => cache_entry_type_default
				:header_info => header_info_default
				:header_info => header_info_default
				:file_extension => file_extension_default
				:original_url => original_url_default
			}

			Merge in defaults. This approach allows caller to safely pass in a nil
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

		# @return [Boolean] Returns TRUE if successful, or FALSE otherwise
		# @param [Fixnum] psz_challenge_info Pointer to the wide-character challenge string to use for the MD5 hash
		# @param [Fixnum] pwsz_realm Pointer to a string that names a realm for which to obtain the password
		# @param [Fixnum] pwsz_target Pointer to a string that names an account for which to obtain the password
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

			Merge in defaults. This approach allows caller to safely pass in a nil
			opts = defaults.merge(opts)

			# Any arg validation can go here

			ret = run_dll_function(:wininet, :CreateMD5SSOHash, challenge_info, realm, target,
				opts[hex_hash],
			)

			# Additional code goes here

		end

		#
		# Creates a local file name for saving the cache entry based on the specified URL and the file name extension.
		# @see http://msdn.microsoft.com/en-us/library/windows/desktop/aa383968(v=vs.85).aspx CreateUrlCacheEntry

		# @return [Boolean] If the function succeeds, the function returns TRUE
		# @param [Fixnum] lpsz_url_name Pointer to a string value that contains the name of the URL
		# @param [Fixnum] dw_expected_file_size Expected size of the file needed to store the data that corresponds to the source entity, in TCHARs
		# @param [Fixnum] lpsz_file_extension Pointer to a string value that contains an extension name of the file in the local storage
		# @param [Fixnum] lpsz_file_name Pointer to a buffer that receives the file name
		# @param [Fixnum] dw_reserved This parameter is reserved and must be 0
		#
		# There are quite a few arguments so an opts hash was added.  To clean
		# up the API, you should review it and adjust as needed.  You may want
		# to consider regrouping args for: clarity, so args that are usually
		# left at default values, or are optional, or always a specific value,
		# etc, are put in the opts hash.  Or, you may want to get rid of the
		# opts hash entirely.
		def _create_url_cache_entry(url_name, expected_file_size, file_extension, opts = {})
			defaults = {  # defaults for args in opts hash
				:file_name => file_name_default
				:reserved => reserved_default
			}

			Merge in defaults. This approach allows caller to safely pass in a nil
			opts = defaults.merge(opts)

			# Any arg validation can go here

			ret = run_dll_function(:wininet, :CreateUrlCacheEntry, url_name, expected_file_size, file_extension,
				opts[file_name],
				opts[reserved],
			)

			# Additional code goes here

		end

		#
		# Generates cache group identifications.
		# @see http://msdn.microsoft.com/en-us/library/windows/desktop/aa383972(v=vs.85).aspx CreateUrlCacheGroup

		# @return [Unknown] Returns a valid GROUPID if successful, or FALSE otherwise
		# @param [Fixnum] dw_flags Controls the creation of the cache group
		# @param [Fixnum] lp_reserved This parameter is reserved and must be NULL
		#
		def _create_url_cache_group(flags, reserved)

			# Any arg validation can go here

			ret = run_dll_function(:wininet, :CreateUrlCacheGroup, flags, reserved)

			# Additional code goes here

		end

		#
		# Removes the file associated with the source name from the cache, if the file exists.
		# @see http://msdn.microsoft.com/en-us/library/windows/desktop/aa383983(v=vs.85).aspx DeleteUrlCacheEntry

		# @return [Boolean] Returns TRUE if successful, or FALSE otherwise
		# @param [Fixnum] lpsz_url_name Pointer to a string that contains the name of the source that corresponds to the cache entry
		#
		def _delete_url_cache_entry(url_name)

			# Any arg validation can go here

			ret = run_dll_function(:wininet, :DeleteUrlCacheEntry, url_name)

			# Additional code goes here

		end

		#
		# Releases the specified GROUPID and any associated state in the cache index file.
		# @see http://msdn.microsoft.com/en-us/library/windows/desktop/aa383990(v=vs.85).aspx DeleteUrlCacheGroup

		# @return [Boolean] Returns TRUE if successful, or FALSE otherwise
		# @param [Unknown] group_id ID of the cache group to be released
		# @param [Fixnum] dw_flags Controls the cache group deletion
		# @param [Fixnum] lp_reserved This parameter is reserved and must be NULL
		#
		def _delete_url_cache_group(group_id, flags, reserved)

			# Any arg validation can go here

			ret = run_dll_function(:wininet, :DeleteUrlCacheGroup, group_id, flags, reserved)

			# Additional code goes here

		end

		#
		# Attempts to determine the location of a WPAD autoproxy script.
		# @see http://msdn.microsoft.com/en-us/library/windows/desktop/aa383993(v=vs.85).aspx DetectAutoProxyUrl

		# @return [Boolean] Returns TRUE if successful, or FALSE otherwise
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
		# Closes the specified cache enumeration handle.
		# @see http://msdn.microsoft.com/en-us/library/windows/desktop/aa384015(v=vs.85).aspx FindCloseUrlCache

		# @return [Boolean] Returns TRUE if successful, or FALSE otherwise
		# @param [Fixnum] h_enum_handle Handle returned by a previous call to the FindFirstUrlCacheEntry function
		#
		def _find_close_url_cache(enum_handle)

			# Any arg validation can go here

			ret = run_dll_function(:wininet, :FindCloseUrlCache, enum_handle)

			# Additional code goes here

		end

		#
		# Begins the enumeration of the Internet cache.
		# @see http://msdn.microsoft.com/en-us/library/windows/desktop/aa384026(v=vs.85).aspx FindFirstUrlCacheEntry

		# @return [Fixnum] Returns a handle that the application can use in the  FindNextUrlCacheEntry function to retrieve subsequent entries in the cache
		# @param [Fixnum] lpsz_url_search_pattern A pointer to a string that contains the source name pattern to search for
		# @param [Unknown] lp_first_cache_entry_info Pointer to an INTERNET_CACHE_ENTRY_INFO structure
		# @param [Fixnum] lpcb_cache_entry_info Pointer to a variable that specifies the size of the lpFirstCacheEntryInfo buffer, in bytes
		#
		def _find_first_url_cache_entry(url_search_pattern, first_cache_entry_info, cache_entry_info)

			# Any arg validation can go here

			ret = run_dll_function(:wininet, :FindFirstUrlCacheEntry, url_search_pattern, first_cache_entry_info, cache_entry_info)

			# Additional code goes here

		end

		#
		# Starts a filtered enumeration of the Internet cache.
		# @see http://msdn.microsoft.com/en-us/library/windows/desktop/aa384034(v=vs.85).aspx FindFirstUrlCacheEntryEx

		# @return [Fixnum] Returns a valid handle if successful, or NULL otherwise
		# @param [Fixnum] lpsz_url_search_pattern A pointer to a string that contains the source name pattern to search for
		# @param [Fixnum] dw_flags Controls the enumeration
		# @param [Fixnum] dw_filter A bitmask indicating the type of cache entry and its properties
		# @param [Unknown] group_id ID of the cache group to be enumerated
		# @param [Unknown] lp_first_cache_entry_info Pointer to a INTERNET_CACHE_ENTRY_INFO structure to receive the cache entry information
		# @param [Fixnum] lpdw_entry_info Pointer to variable that indicates the size of the structure referenced by the lpFirstCacheEntryInfo parameter, in bytes
		# @param [Fixnum] lp_group_attributes This parameter is reserved and must be NULL
		# @param [Fixnum] lpcb_group_attributes This parameter is reserved and must be NULL
		# @param [Fixnum] lp_reserved This parameter is reserved and must be NULL
		#
		# There are quite a few arguments so an opts hash was added.  To clean
		# up the API, you should review it and adjust as needed.  You may want
		# to consider regrouping args for: clarity, so args that are usually
		# left at default values, or are optional, or always a specific value,
		# etc, are put in the opts hash.  Or, you may want to get rid of the
		# opts hash entirely.
		def _find_first_url_cache_entry_ex(url_search_pattern, flags, filter, opts = {})
			defaults = {  # defaults for args in opts hash
				:group_id => group_id_default
				:first_cache_entry_info => first_cache_entry_info_default
				:entry_info => entry_info_default
				:group_attributes => group_attributes_default
				:group_attributes => group_attributes_default
				:reserved => reserved_default
			}

			Merge in defaults. This approach allows caller to safely pass in a nil
			opts = defaults.merge(opts)

			# Any arg validation can go here

			ret = run_dll_function(:wininet, :FindFirstUrlCacheEntryEx, url_search_pattern, flags, filter,
				opts[group_id],
				opts[first_cache_entry_info],
				opts[entry_info],
				opts[group_attributes],
				opts[group_attributes],
				opts[reserved],
			)

			# Additional code goes here

		end

		#
		# Initiates the enumeration of the cache groups in the Internet cache.
		# @see http://msdn.microsoft.com/en-us/library/windows/desktop/aa384044(v=vs.85).aspx FindFirstUrlCacheGroup

		# @return [Fixnum] Returns a valid handle to the first item in the enumeration if successful, or NULL otherwise
		# @param [Fixnum] dw_flags This parameter is reserved and must be 0
		# @param [Fixnum] dw_filter Filters to be used
		# @param [Fixnum] lp_search_condition This parameter is reserved and must be NULL
		# @param [Fixnum] dw_search_condition This parameter is reserved and must be 0
		# @param [Fixnum] lp_group_id Pointer to the ID of the first cache group that matches the search criteria
		# @param [Fixnum] lp_reserved This parameter is reserved and must be NULL
		#
		# There are quite a few arguments so an opts hash was added.  To clean
		# up the API, you should review it and adjust as needed.  You may want
		# to consider regrouping args for: clarity, so args that are usually
		# left at default values, or are optional, or always a specific value,
		# etc, are put in the opts hash.  Or, you may want to get rid of the
		# opts hash entirely.
		def _find_first_url_cache_group(flags, filter, search_condition, opts = {})
			defaults = {  # defaults for args in opts hash
				:search_condition => search_condition_default
				:lp_group_id => lp_group_id_default
				:reserved => reserved_default
			}

			Merge in defaults. This approach allows caller to safely pass in a nil
			opts = defaults.merge(opts)

			# Any arg validation can go here

			ret = run_dll_function(:wininet, :FindFirstUrlCacheGroup, flags, filter, search_condition,
				opts[search_condition],
				opts[lp_group_id],
				opts[reserved],
			)

			# Additional code goes here

		end

		#
		# Retrieves the next entry in the Internet cache.
		# @see http://msdn.microsoft.com/en-us/library/windows/desktop/aa384049(v=vs.85).aspx FindNextUrlCacheEntry

		# @return [Boolean] Returns TRUE if successful, or FALSE otherwise
		# @param [Fixnum] h_enum_handle Handle to the enumeration obtained from a previous call to FindFirstUrlCacheEntry
		# @param [Unknown] lp_next_cache_entry_info Pointer to an INTERNET_CACHE_ENTRY_INFO structure that receives information about the cache entry
		# @param [Fixnum] lpcb_cache_entry_info Pointer to a variable that specifies the size of the lpNextCacheEntryInfo buffer, in bytes
		#
		def _find_next_url_cache_entry(enum_handle, next_cache_entry_info, cache_entry_info)

			# Any arg validation can go here

			ret = run_dll_function(:wininet, :FindNextUrlCacheEntry, enum_handle, next_cache_entry_info, cache_entry_info)

			# Additional code goes here

		end

		#
		# Finds the next cache entry in a cache enumeration started by the FindFirstUrlCacheEntryEx function.
		# @see http://msdn.microsoft.com/en-us/library/windows/desktop/aa384057(v=vs.85).aspx FindNextUrlCacheEntryEx

		# @return [Boolean] Returns TRUE if successful, or FALSE otherwise
		# @param [Fixnum] h_enum_handle Handle returned by FindFirstUrlCacheEntryEx, which started a cache enumeration
		# @param [Fixnum] lp_next_cache_entry_info Pointer to the  INTERNET_CACHE_ENTRY_INFO structure that receives the cache entry information
		# @param [Fixnum] lpcb_entry_info Pointer to a variable that indicates the size of the buffer, in bytes
		# @param [Fixnum] lp_group_attributes This parameter is reserved and must be NULL
		# @param [Fixnum] lpcb_group_attributes This parameter is reserved and must be NULL
		# @param [Fixnum] lp_reserved This parameter is reserved
		#
		# There are quite a few arguments so an opts hash was added.  To clean
		# up the API, you should review it and adjust as needed.  You may want
		# to consider regrouping args for: clarity, so args that are usually
		# left at default values, or are optional, or always a specific value,
		# etc, are put in the opts hash.  Or, you may want to get rid of the
		# opts hash entirely.
		def _find_next_url_cache_entry_ex(enum_handle, next_cache_entry_info, entry_info, opts = {})
			defaults = {  # defaults for args in opts hash
				:group_attributes => group_attributes_default
				:group_attributes => group_attributes_default
				:reserved => reserved_default
			}

			Merge in defaults. This approach allows caller to safely pass in a nil
			opts = defaults.merge(opts)

			# Any arg validation can go here

			ret = run_dll_function(:wininet, :FindNextUrlCacheEntryEx, enum_handle, next_cache_entry_info, entry_info,
				opts[group_attributes],
				opts[group_attributes],
				opts[reserved],
			)

			# Additional code goes here

		end

		#
		# Retrieves the next cache group in a cache group enumeration started by FindFirstUrlCacheGroup.
		# @see http://msdn.microsoft.com/en-us/library/windows/desktop/aa384126(v=vs.85).aspx FindNextUrlCacheGroup

		# @return [Boolean] Returns TRUE if successful, or FALSE otherwise
		# @param [Fixnum] h_find The cache group enumeration handle, which is returned by FindFirstUrlCacheGroup
		# @param [Fixnum] lp_group_id Pointer to a variable that receives the cache group identifier
		# @param [Fixnum] lp_reserved This parameter is reserved and must be NULL
		#
		def _find_next_url_cache_group(find, lp_group_id, reserved)

			# Any arg validation can go here

			ret = run_dll_function(:wininet, :FindNextUrlCacheGroup, find, lp_group_id, reserved)

			# Additional code goes here

		end

		#
		# The FtpCommand function sends commands directly to an FTP server.
		# @see http://msdn.microsoft.com/en-us/library/windows/desktop/aa384133(v=vs.85).aspx FtpCommand

		# @return [Boolean] Returns TRUE if successful, or FALSE otherwise
		# @param [Fixnum] h_connect A handle returned from a call to InternetConnect
		# @param [Unknown] f_expect_response A Boolean value that indicates whether the application expects a data connection to be established by the FTP server
		# @param [Fixnum] dw_flags A parameter that can be set to one of the following values
		# @param [Fixnum] lpsz_command A pointer to a string that contains the command to send to the FTP server
		# @param [Fixnum] dw_context A pointer to a variable that contains an application-defined value used to identify the application context in callback operations
		# @param [Fixnum] ph_ftp_command A pointer to a handle that is created if a valid data socket is opened
		#
		# There are quite a few arguments so an opts hash was added.  To clean
		# up the API, you should review it and adjust as needed.  You may want
		# to consider regrouping args for: clarity, so args that are usually
		# left at default values, or are optional, or always a specific value,
		# etc, are put in the opts hash.  Or, you may want to get rid of the
		# opts hash entirely.
		def _ftp_command(connect, expect_response, flags, opts = {})
			defaults = {  # defaults for args in opts hash
				:command => command_default
				:context => context_default
				:ph_ftp_command => ph_ftp_command_default
			}

			Merge in defaults. This approach allows caller to safely pass in a nil
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

		# @return [Boolean] Returns TRUE if successful, or FALSE otherwise
		# @param [Fixnum] h_connect Handle returned by a previous call to InternetConnect using INTERNET_SERVICE_FTP
		# @param [Fixnum] lpsz_directory Pointer to a null-terminated string that contains the name of the directory to be created
		#
		def _ftp_create_directory(connect, directory)

			# Any arg validation can go here

			ret = run_dll_function(:wininet, :FtpCreateDirectory, connect, directory)

			# Additional code goes here

		end

		#
		# Deletes a file stored on the FTP server.
		# @see http://msdn.microsoft.com/en-us/library/windows/desktop/aa384142(v=vs.85).aspx FtpDeleteFile

		# @return [Boolean] Returns TRUE if successful, or FALSE otherwise
		# @param [Fixnum] h_connect Handle returned by a previous call to InternetConnect using INTERNET_SERVICE_FTP
		# @param [Fixnum] lpsz_file_name Pointer to a null-terminated string that contains the name of the file to be deleted
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
		# @param [Fixnum] lpsz_search_file Pointer to a null-terminated string that specifies a valid directory path or file name for the FTP server's file system
		# @param [Unknown] lp_find_file_data Pointer to a WIN32_FIND_DATA structure that receives information about the found file or directory
		# @param [Fixnum] dw_flags Controls the behavior of this function
		# @param [Fixnum] dw_context Pointer to a variable that specifies the application-defined value that associates this search with any application data
		#
		# There are quite a few arguments so an opts hash was added.  To clean
		# up the API, you should review it and adjust as needed.  You may want
		# to consider regrouping args for: clarity, so args that are usually
		# left at default values, or are optional, or always a specific value,
		# etc, are put in the opts hash.  Or, you may want to get rid of the
		# opts hash entirely.
		def _ftp_find_first_file(connect, search_file, find_file_data, opts = {})
			defaults = {  # defaults for args in opts hash
				:flags => flags_default
				:context => context_default
			}

			Merge in defaults. This approach allows caller to safely pass in a nil
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

		# @return [Boolean] Returns TRUE if successful, or FALSE otherwise
		# @param [Fixnum] h_connect Handle to an FTP session
		# @param [Fixnum] lpsz_current_directory Pointer to a null-terminated string that receives the absolute path of the current directory
		# @param [Fixnum] lpdw_current_directory Pointer to a variable that specifies the length of the buffer, in TCHARs
		#
		def _ftp_get_current_directory(connect, current_directory, current_directory)

			# Any arg validation can go here

			ret = run_dll_function(:wininet, :FtpGetCurrentDirectory, connect, current_directory, current_directory)

			# Additional code goes here

		end

		#
		# Retrieves a file from the FTP server and stores it under the specified file name, creating a new local file in the process.
		# @see http://msdn.microsoft.com/en-us/library/windows/desktop/aa384157(v=vs.85).aspx FtpGetFile

		# @return [Boolean] Returns TRUE if successful, or FALSE otherwise
		# @param [Fixnum] h_connect Handle to an FTP session
		# @param [Fixnum] lpsz_remote_file Pointer to a null-terminated string that contains the name of the file to be retrieved
		# @param [Fixnum] lpsz_new_file Pointer to a null-terminated string that contains the name of the file to be created on the local system
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
				:fail_if_exists => fail_if_exists_default
				:flags_and_attributes => flags_and_attributes_default
				:flags => flags_default
				:context => context_default
			}

			Merge in defaults. This approach allows caller to safely pass in a nil
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
		# @param [Fixnum] lpsz_file_name Pointer to a null-terminated string that contains the name of the file to be accessed
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
				:flags => flags_default
				:context => context_default
			}

			Merge in defaults. This approach allows caller to safely pass in a nil
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

		# @return [Boolean] Returns TRUE if successful, or FALSE otherwise
		# @param [Fixnum] h_connect Handle to an FTP session
		# @param [Fixnum] lpsz_local_file Pointer to a null-terminated string that contains the name of the file to be sent from the local system
		# @param [Fixnum] lpsz_new_remote_file Pointer to a null-terminated string that contains the name of the file to be created on the remote system
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
				:flags => flags_default
				:context => context_default
			}

			Merge in defaults. This approach allows caller to safely pass in a nil
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

		# @return [Boolean] Returns TRUE if successful, or FALSE otherwise
		# @param [Fixnum] h_connect Handle to an FTP session
		# @param [Fixnum] lpsz_directory Pointer to a null-terminated string that contains the name of the directory to be removed
		#
		def _ftp_remove_directory(connect, directory)

			# Any arg validation can go here

			ret = run_dll_function(:wininet, :FtpRemoveDirectory, connect, directory)

			# Additional code goes here

		end

		#
		# Renames a file stored on the FTP server.
		# @see http://msdn.microsoft.com/en-us/library/windows/desktop/aa384175(v=vs.85).aspx FtpRenameFile

		# @return [Boolean] Returns TRUE if successful, or FALSE otherwise
		# @param [Fixnum] h_connect Handle to an FTP session
		# @param [Fixnum] lpsz_existing Pointer to a null-terminated string that contains the name of the file to be renamed
		# @param [Fixnum] lpsz_new Pointer to a null-terminated string that contains the new name for the remote file
		#
		def _ftp_rename_file(connect, existing, new)

			# Any arg validation can go here

			ret = run_dll_function(:wininet, :FtpRenameFile, connect, existing, new)

			# Additional code goes here

		end

		#
		# Changes to a different working directory on the FTP server.
		# @see http://msdn.microsoft.com/en-us/library/windows/desktop/aa384178(v=vs.85).aspx FtpSetCurrentDirectory

		# @return [Boolean] Returns TRUE if successful, or FALSE otherwise
		# @param [Fixnum] h_connect Handle to an FTP session
		# @param [Fixnum] lpsz_directory Pointer to a null-terminated string that contains the name of the directory to become the current working directory
		#
		def _ftp_set_current_directory(connect, directory)

			# Any arg validation can go here

			ret = run_dll_function(:wininet, :FtpSetCurrentDirectory, connect, directory)

			# Additional code goes here

		end

		#
		# Retrieves information about cache configuration.
		# @see http://msdn.microsoft.com/en-us/library/windows/desktop/cc817578(v=vs.85).aspx GetUrlCacheConfigInfo

		# @return [Boolean] Returns TRUE if successful, or FALSE otherwise
		# @param [Fixnum] lp_cache_config_info A pointer to an        INTERNET_CACHE_CONFIG_INFO structure        that receives information about the cache configuration
		# @param [Fixnum] lpcb_cache_config_info This parameter is reserved and must be NULL
		# @param [Fixnum] dw_field_control Determines the behavior of the function, as one of the following values
		#
		def _get_url_cache_config_info(cache_config_info, cache_config_info, field_control)

			# Any arg validation can go here

			ret = run_dll_function(:wininet, :GetUrlCacheConfigInfo, cache_config_info, cache_config_info, field_control)

			# Additional code goes here

		end

		#
		# Retrieves information about a cache entry.
		# @see http://msdn.microsoft.com/en-us/library/windows/desktop/aa384185(v=vs.85).aspx GetUrlCacheEntryInfo

		# @return [Boolean] Returns TRUE if successful, or FALSE otherwise
		# @param [Fixnum] lpsz_url_name Pointer to a null-terminated string that contains the name of the cache entry
		# @param [Unknown] lp_cache_entry_info Pointer to an INTERNET_CACHE_ENTRY_INFO structure that receives information about the cache entry
		# @param [Fixnum] lpcb_cache_entry_info Pointer to a variable that specifies the size of the lpCacheEntryInfo buffer, in bytes
		#
		def _get_url_cache_entry_info(url_name, cache_entry_info, cache_entry_info)

			# Any arg validation can go here

			ret = run_dll_function(:wininet, :GetUrlCacheEntryInfo, url_name, cache_entry_info, cache_entry_info)

			# Additional code goes here

		end

		#
		# Retrieves information on the cache entry associated with the specified URL, taking into account any redirections that are applied in offline mode by the HttpSendRequest function.
		# @see http://msdn.microsoft.com/en-us/library/windows/desktop/aa384188(v=vs.85).aspx GetUrlCacheEntryInfoEx

		# @return [Boolean] Returns TRUE if the URL was located, or FALSE otherwise
		# @param [Fixnum] lpsz_url Pointer to a null-terminated string that contains the name of the cache entry
		# @param [Fixnum] lp_cache_entry_info Pointer to an INTERNET_CACHE_ENTRY_INFO structure that receives information about the cache entry
		# @param [Fixnum] lpcb_cache_entry_info Pointer to a variable that specifies the size of the lpCacheEntryInfo buffer, in bytes
		# @param [Fixnum] lpsz_redirect_url This parameter is reserved and must be NULL
		# @param [Fixnum] lpcb_redirect_url This parameter is reserved and must be NULL
		# @param [Fixnum] lp_reserved This parameter is reserved and must be NULL
		# @param [Fixnum] dw_flags This parameter is reserved and must be 0
		#
		# There are quite a few arguments so an opts hash was added.  To clean
		# up the API, you should review it and adjust as needed.  You may want
		# to consider regrouping args for: clarity, so args that are usually
		# left at default values, or are optional, or always a specific value,
		# etc, are put in the opts hash.  Or, you may want to get rid of the
		# opts hash entirely.
		def _get_url_cache_entry_info_ex(url, cache_entry_info, cache_entry_info, opts = {})
			defaults = {  # defaults for args in opts hash
				:redirect_url => redirect_url_default
				:redirect_url => redirect_url_default
				:reserved => reserved_default
				:flags => flags_default
			}

			Merge in defaults. This approach allows caller to safely pass in a nil
			opts = defaults.merge(opts)

			# Any arg validation can go here

			ret = run_dll_function(:wininet, :GetUrlCacheEntryInfoEx, url, cache_entry_info, cache_entry_info,
				opts[redirect_url],
				opts[redirect_url],
				opts[reserved],
				opts[flags],
			)

			# Additional code goes here

		end

		#
		# Retrieves the attribute information of the specified cache group.
		# @see http://msdn.microsoft.com/en-us/library/windows/desktop/aa384191(v=vs.85).aspx GetUrlCacheGroupAttribute

		# @return [Boolean] Returns TRUE if successful, or FALSE otherwise
		# @param [Unknown] gid Identifier of the cache group
		# @param [Fixnum] dw_flags This parameter is reserved and must be 0
		# @param [Fixnum] dw_attributes Attributes to be retrieved
		# @param [Unknown] lp_group_info Pointer to an INTERNET_CACHE_GROUP_INFO structure that receives the requested information
		# @param [Fixnum] lpdw_group_info Pointer to a variable that contains the size of the lpGroupInfo buffer
		# @param [Fixnum] lp_reserved This parameter is reserved and must be NULL
		#
		# There are quite a few arguments so an opts hash was added.  To clean
		# up the API, you should review it and adjust as needed.  You may want
		# to consider regrouping args for: clarity, so args that are usually
		# left at default values, or are optional, or always a specific value,
		# etc, are put in the opts hash.  Or, you may want to get rid of the
		# opts hash entirely.
		def _get_url_cache_group_attribute(gid, flags, attributes, opts = {})
			defaults = {  # defaults for args in opts hash
				:group_info => group_info_default
				:group_info => group_info_default
				:reserved => reserved_default
			}

			Merge in defaults. This approach allows caller to safely pass in a nil
			opts = defaults.merge(opts)

			# Any arg validation can go here

			ret = run_dll_function(:wininet, :GetUrlCacheGroupAttribute, gid, flags, attributes,
				opts[group_info],
				opts[group_info],
				opts[reserved],
			)

			# Additional code goes here

		end

		#
		# [The GopherAttributeEnumerator function is available for use in the operating systems specified in the Requirements section.]
		# @see http://msdn.microsoft.com/en-us/library/windows/desktop/aa384194(v=vs.85).aspx GopherAttributeEnumerator

		# @return [Boolean] Return TRUE to continue the enumeration, or FALSE to stop it immediately
		# @param [Unk] unknown Pointer to a  GOPHER_ATTRIBUTE_TYPE structure
		# @param [Unk] unknown Error value
		#
		def _gopher_attribute_enumerator(unknown, unknown)

			# Any arg validation can go here

			ret = run_dll_function(:wininet, :GopherAttributeEnumerator, unknown, unknown)

			# Additional code goes here

		end

		#
		# [The GopherCreateLocator function is available for use in the operating systems specified in the Requirements section.]
		# @see http://msdn.microsoft.com/en-us/library/windows/desktop/aa384197(v=vs.85).aspx GopherCreateLocator

		# @return [Boolean] Returns TRUE if successful, or FALSE otherwise
		# @param [Fixnum] lpsz_host Pointer to a null-terminated string that contains the name of the host, or a dotted-decimal IP address (such as 198
		# @param [Unknown] n_server_port Port number on which the Gopher server at lpszHost lives, in host byte order
		# @param [Fixnum] lpsz_display_string Pointer to a null-terminated string that contains the Gopher document or directory to be displayed
		# @param [Fixnum] lpsz_selector_string Pointer to the selector string to send to the Gopher server in order to retrieve information
		# @param [Fixnum] dw_gopher_type Determines whether lpszSelectorString refers to a directory or document, and whether the request is Gopher+ or Gopher
		# @param [Fixnum] lpsz_locator Pointer to a buffer  that receives the locator string
		# @param [Fixnum] lpdw_buffer_length Pointer to a variable that contains the length of the lpszLocator buffer, in characters
		#
		# There are quite a few arguments so an opts hash was added.  To clean
		# up the API, you should review it and adjust as needed.  You may want
		# to consider regrouping args for: clarity, so args that are usually
		# left at default values, or are optional, or always a specific value,
		# etc, are put in the opts hash.  Or, you may want to get rid of the
		# opts hash entirely.
		def _gopher_create_locator(host, server_port, display_string, opts = {})
			defaults = {  # defaults for args in opts hash
				:selector_string => selector_string_default
				:gopher_type => gopher_type_default
				:locator => locator_default
				:buffer_length => buffer_length_default
			}

			Merge in defaults. This approach allows caller to safely pass in a nil
			opts = defaults.merge(opts)

			# Any arg validation can go here

			ret = run_dll_function(:wininet, :GopherCreateLocator, host, server_port, display_string,
				opts[selector_string],
				opts[gopher_type],
				opts[locator],
				opts[buffer_length],
			)

			# Additional code goes here

		end

		#
		# [The GopherFindFirstFile function is available for use in the operating systems specified in the Requirements section.]
		# @see http://msdn.microsoft.com/en-us/library/windows/desktop/aa384202(v=vs.85).aspx GopherFindFirstFile

		# @return [Fixnum] Returns a valid search handle if successful, or NULL otherwise
		# @param [Fixnum] h_connect Handle to a Gopher session returned by InternetConnect
		# @param [Fixnum] lpsz_locator Pointer to a null-terminated string that contains the name of the item to locate
		# @param [Fixnum] lpsz_search_string Pointer to a buffer that contains the strings to search, if this request is to an index server
		# @param [Unknown] lp_find_data Pointer to a GOPHER_FIND_DATA structure that receives the information retrieved by this function
		# @param [Fixnum] dw_flags Controls the function behavior
		# @param [Fixnum] dw_context Pointer to a variable that contains the application-defined value that associates this search with any application data
		#
		# There are quite a few arguments so an opts hash was added.  To clean
		# up the API, you should review it and adjust as needed.  You may want
		# to consider regrouping args for: clarity, so args that are usually
		# left at default values, or are optional, or always a specific value,
		# etc, are put in the opts hash.  Or, you may want to get rid of the
		# opts hash entirely.
		def _gopher_find_first_file(connect, locator, search_string, opts = {})
			defaults = {  # defaults for args in opts hash
				:find_data => find_data_default
				:flags => flags_default
				:context => context_default
			}

			Merge in defaults. This approach allows caller to safely pass in a nil
			opts = defaults.merge(opts)

			# Any arg validation can go here

			ret = run_dll_function(:wininet, :GopherFindFirstFile, connect, locator, search_string,
				opts[find_data],
				opts[flags],
				opts[context],
			)

			# Additional code goes here

		end

		#
		# [The GopherGetAttribute function is available for use in the operating systems specified in the Requirements section.]
		# @see http://msdn.microsoft.com/en-us/library/windows/desktop/aa384205(v=vs.85).aspx GopherGetAttribute

		# @return [Boolean] Returns TRUE if the request is satisfied, or FALSE otherwise
		# @param [Fixnum] h_connect Handle to a Gopher session returned by InternetConnect
		# @param [Fixnum] lpsz_locator Pointer to a null-terminated string that identifies the item at the Gopher server on which to return attribute information
		# @param [Fixnum] lpsz_attribute_name Pointer to a space-delimited string specifying the names of attributes to return
		# @param [Unknown] lp_buffer Pointer to an application-defined buffer from which attribute information is retrieved
		# @param [Fixnum] dw_buffer_length Size of the lpBuffer buffer, in TCHARs
		# @param [Fixnum] lpdw_characters_returned Pointer to a variable that contains the number of characters read into the lpBuffer buffer
		# @param [Unknown] lpfn_enumerator Pointer to a GopherAttributeEnumerator callback function that enumerates each attribute of the locator
		# @param [Fixnum] dw_context Application-defined value that associates this operation with any application data
		#
		# There are quite a few arguments so an opts hash was added.  To clean
		# up the API, you should review it and adjust as needed.  You may want
		# to consider regrouping args for: clarity, so args that are usually
		# left at default values, or are optional, or always a specific value,
		# etc, are put in the opts hash.  Or, you may want to get rid of the
		# opts hash entirely.
		def _gopher_get_attribute(connect, locator, attribute_name, opts = {})
			defaults = {  # defaults for args in opts hash
				:buffer => buffer_default
				:buffer_length => buffer_length_default
				:characters_returned => characters_returned_default
				:enumerator => enumerator_default
				:context => context_default
			}

			Merge in defaults. This approach allows caller to safely pass in a nil
			opts = defaults.merge(opts)

			# Any arg validation can go here

			ret = run_dll_function(:wininet, :GopherGetAttribute, connect, locator, attribute_name,
				opts[buffer],
				opts[buffer_length],
				opts[characters_returned],
				opts[enumerator],
				opts[context],
			)

			# Additional code goes here

		end

		#
		# [The GopherGetLocatorType function is available for use in the operating systems specified in the Requirements section.]
		# @see http://msdn.microsoft.com/en-us/library/windows/desktop/aa384208(v=vs.85).aspx GopherGetLocatorType

		# @return [Boolean] Returns TRUE if successful, or FALSE otherwise
		# @param [Fixnum] lpsz_locator Pointer to a null-terminated string that specifies the Gopher locator to be parsed
		# @param [Fixnum] lpdw_gopher_type Pointer to a variable that receives the type of the locator
		#
		def _gopher_get_locator_type(locator, gopher_type)

			# Any arg validation can go here

			ret = run_dll_function(:wininet, :GopherGetLocatorType, locator, gopher_type)

			# Additional code goes here

		end

		#
		# [The GopherOpenFile function is available for use in the operating systems specified in the Requirements section.]
		# @see http://msdn.microsoft.com/en-us/library/windows/desktop/aa384210(v=vs.85).aspx GopherOpenFile

		# @return [Fixnum] Returns a handle if successful, or NULL if the file cannot be opened
		# @param [Fixnum] h_connect Handle to a Gopher session returned by InternetConnect
		# @param [Fixnum] lpsz_locator Pointer to a null-terminated string that specifies the file to be opened
		# @param [Fixnum] lpsz_view Pointer to a null-terminated string that describes the view to open if several views of the file exist on the server
		# @param [Fixnum] dw_flags Conditions under which subsequent transfers occur
		# @param [Fixnum] dw_context Pointer to a variable that contains an application-defined value that associates this operation with any application data
		#
		# There are quite a few arguments so an opts hash was added.  To clean
		# up the API, you should review it and adjust as needed.  You may want
		# to consider regrouping args for: clarity, so args that are usually
		# left at default values, or are optional, or always a specific value,
		# etc, are put in the opts hash.  Or, you may want to get rid of the
		# opts hash entirely.
		def _gopher_open_file(connect, locator, view, opts = {})
			defaults = {  # defaults for args in opts hash
				:flags => flags_default
				:context => context_default
			}

			Merge in defaults. This approach allows caller to safely pass in a nil
			opts = defaults.merge(opts)

			# Any arg validation can go here

			ret = run_dll_function(:wininet, :GopherOpenFile, connect, locator, view,
				opts[flags],
				opts[context],
			)

			# Additional code goes here

		end

		#
		# Attempts to make a connection to the Internet.
		# @see http://msdn.microsoft.com/en-us/library/windows/desktop/aa384331(v=vs.85).aspx InternetAttemptConnect

		# @return [Unknown] Returns ERROR_SUCCESS if successful, or a system error code otherwise
		# @param [Fixnum] dw_reserved This parameter is reserved and must be 0
		#
		def _internet_attempt_connect(reserved)

			# Any arg validation can go here

			ret = run_dll_function(:wininet, :InternetAttemptConnect, reserved)

			# Additional code goes here

		end

		#
		# Causes the modem to automatically dial the default Internet connection.
		# @see http://msdn.microsoft.com/en-us/library/windows/desktop/aa384336(v=vs.85).aspx InternetAutodial

		# @return [Boolean] If the function succeeds, it returns TRUE
		# @param [Fixnum] dw_flags Controls this operation
		# @param [Fixnum] hwnd_parent Handle to the parent window
		#
		def _internet_autodial(flags, parent)

			# Any arg validation can go here

			ret = run_dll_function(:wininet, :InternetAutodial, flags, parent)

			# Additional code goes here

		end

		#
		# Disconnects an automatic dial-up connection.
		# @see http://msdn.microsoft.com/en-us/library/windows/desktop/aa384340(v=vs.85).aspx InternetAutodialHangup

		# @return [Boolean] If the function succeeds, it returns TRUE
		# @param [Fixnum] dw_reserved This parameter is reserved and must be 0
		#
		def _internet_autodial_hangup(reserved)

			# Any arg validation can go here

			ret = run_dll_function(:wininet, :InternetAutodialHangup, reserved)

			# Additional code goes here

		end

		#
		# Canonicalizes a URL, which includes converting unsafe characters and spaces into escape sequences.
		# @see http://msdn.microsoft.com/en-us/library/windows/desktop/aa384342(v=vs.85).aspx InternetCanonicalizeUrl

		# @return [Boolean] Returns TRUE if successful, or FALSE otherwise
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

			Merge in defaults. This approach allows caller to safely pass in a nil
			opts = defaults.merge(opts)

			# Any arg validation can go here

			ret = run_dll_function(:wininet, :InternetCanonicalizeUrl, url, buffer, buffer_length,
				opts[flags],
			)

			# Additional code goes here

		end

		#
		# Clears all decisions that were made about cookies on a site by site basis.
		# @see http://msdn.microsoft.com/en-us/library/windows/desktop/aa384348(v=vs.85).aspx InternetClearAllPerSiteCookieDecisions

		# @return [Boolean] Returns TRUE if all decisions were cleared and FALSE otherwise
		#
		def _internet_clear_all_per_site_cookie_decisions()
			ret = run_dll_function(:wininet, :InternetClearAllPerSiteCookieDecisions)

			# Additional code goes here

		end

		#
		# Closes a single Internet handle.
		# @see http://msdn.microsoft.com/en-us/library/windows/desktop/aa384350(v=vs.85).aspx InternetCloseHandle

		# @return [Boolean] Returns TRUE if the handle is successfully closed, or FALSE otherwise
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

		# @return [Boolean] Returns TRUE if successful, or FALSE otherwise
		# @param [Fixnum] lpsz_base_url Pointer to a null-terminated string  that contains the base URL
		# @param [Fixnum] lpsz_relative_url Pointer to a null-terminated string  that contains the relative URL
		# @param [Fixnum] lpsz_buffer Pointer to a buffer that receives the combined URL
		# @param [Fixnum] lpdw_buffer_length Pointer to a variable that contains the size of the lpszBuffer buffer, in characters
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
				:buffer_length => buffer_length_default
				:flags => flags_default
			}

			Merge in defaults. This approach allows caller to safely pass in a nil
			opts = defaults.merge(opts)

			# Any arg validation can go here

			ret = run_dll_function(:wininet, :InternetCombineUrl, base_url, relative_url, buffer,
				opts[buffer_length],
				opts[flags],
			)

			# Additional code goes here

		end

		#
		# Checks for changes between secure and nonsecure URLs. Always inform the user when a change occurs in security between two URLs. Typically, an application should allow the user to acknowledge the change through interaction with a dialog box.
		# @see http://msdn.microsoft.com/en-us/library/windows/desktop/aa384358(v=vs.85).aspx InternetConfirmZoneCrossing

		# @return [Unknown] Returns one of the following values
		# @param [Fixnum] h_wnd Handle to the parent window for any required dialog box
		# @param [Fixnum] sz_url_prev Pointer to a null-terminated string that specifies the URL that was viewed before the current request was made
		# @param [Fixnum] sz_url_new Pointer to a null-terminated string that specifies the new URL that the user has requested to view
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

			Merge in defaults. This approach allows caller to safely pass in a nil
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
		# @param [Fixnum] lpsz_server_name Pointer to a null-terminated string that specifies the host name of an Internet server
		# @param [Unknown] n_server_port Transmission Control Protocol/Internet Protocol (TCP/IP) port on the server
		# @param [Fixnum] lpsz_username Pointer to a null-terminated string that specifies the name of the user to log on
		# @param [Fixnum] lpsz_password Pointer to a null-terminated string that contains the password to use to log on
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
				:username => username_default
				:password => password_default
				:service => service_default
				:flags => flags_default
				:context => context_default
			}

			Merge in defaults. This approach allows caller to safely pass in a nil
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

		# @return [Boolean] Returns TRUE if the function succeeds, or FALSE otherwise
		# @param [Fixnum] lpsz_url Pointer to a string that contains the canonical URL to be cracked
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

			Merge in defaults. This approach allows caller to safely pass in a nil
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

		# @return [Boolean] Returns TRUE if the function succeeds, or FALSE otherwise
		# @param [Fixnum] lp_url_components Pointer to a URL_COMPONENTS structure that contains the components from which to create the URL
		# @param [Fixnum] dw_flags Controls the operation of this function
		# @param [Fixnum] lpsz_url Pointer to a buffer that receives the URL
		# @param [Fixnum] lpdw_url_length Pointer to a variable that specifies the size of the URLlpszUrl buffer, in TCHARs
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

			Merge in defaults. This approach allows caller to safely pass in a nil
			opts = defaults.merge(opts)

			# Any arg validation can go here

			ret = run_dll_function(:wininet, :InternetCreateUrl, url_components, flags, url,
				opts[url_length],
			)

			# Additional code goes here

		end

		#
		# Frees the script engine used to process the autoproxy script. This function can only be called by dynamically linking to "JSProxy.dll". For autoproxy support, use Microsoft Windows HTTP Services (WinHTTP) version 5.1 instead. For more information, see WinHTTP AutoProxy Support.
		# @see http://msdn.microsoft.com/en-us/library/windows/desktop/aa384580(v=vs.85).aspx InternetDeInitializeAutoProxyDll

		# @return [Boolean] Returns TRUE if successful, or FALSE otherwise
		# @param [Fixnum] lpsz_mime This parameter is reserved and must be NULL
		# @param [Fixnum] dw_reserved This parameter is reserved and must be 0
		#
		def _internet_de_initialize_auto_proxy_dll(mime, reserved)

			# Any arg validation can go here

			ret = run_dll_function(:wininet, :InternetDeInitializeAutoProxyDll, mime, reserved)

			# Additional code goes here

		end

		#
		# Initiates a connection to the Internet using a modem.
		# @see http://msdn.microsoft.com/en-us/library/windows/desktop/aa384587(v=vs.85).aspx InternetDial

		# @return [Unknown] Returns ERROR_SUCCESS if successful, or an error value otherwise
		# @param [Fixnum] hwnd_parent Handle to the parent window
		# @param [Fixnum] psz_entry_name Pointer to a null-terminated string that specifies the name of the dial-up connection to be used
		# @param [Fixnum] dw_flags Options
		# @param [Fixnum] lpdw_connection Pointer to a variable that specifies the connection number
		# @param [Fixnum] dw_reserved This parameter is reserved and must be NULL
		#
		# There are quite a few arguments so an opts hash was added.  To clean
		# up the API, you should review it and adjust as needed.  You may want
		# to consider regrouping args for: clarity, so args that are usually
		# left at default values, or are optional, or always a specific value,
		# etc, are put in the opts hash.  Or, you may want to get rid of the
		# opts hash entirely.
		def _internet_dial(parent, entry_name, flags, opts = {})
			defaults = {  # defaults for args in opts hash
				:lpdw_connection => lpdw_connection_default
				:reserved => reserved_default
			}

			Merge in defaults. This approach allows caller to safely pass in a nil
			opts = defaults.merge(opts)

			# Any arg validation can go here

			ret = run_dll_function(:wininet, :InternetDial, parent, entry_name, flags,
				opts[lpdw_connection],
				opts[reserved],
			)

			# Additional code goes here

		end

		#
		# Retrieves the domains and cookie settings of websites for which site-specific cookie regulations are set.
		# @see http://msdn.microsoft.com/en-us/library/windows/desktop/aa384688(v=vs.85).aspx InternetEnumPerSiteCookieDecision

		# @return [Boolean] TRUE if the function retrieved the cookie setting for the given domain; otherwise, false
		# @param [Fixnum] psz_site_name An LPSTR that receives a string specifying a website domain
		# @param [Fixnum] pc_site_name_size A pointer to an unsigned long that specifies the size of the pcSiteNameSize parameter provided to the InternetEnumPerSiteCookieDecision function when it is called
		# @param [Fixnum] pdw_decision Pointer to an unsigned long that receives the InternetCookieState enumeration value corresponding to pszSiteName
		# @param [Fixnum] dw_index An unsigned long that specifies the index of the website and corresponding cookie setting to retrieve
		#
		# There are quite a few arguments so an opts hash was added.  To clean
		# up the API, you should review it and adjust as needed.  You may want
		# to consider regrouping args for: clarity, so args that are usually
		# left at default values, or are optional, or always a specific value,
		# etc, are put in the opts hash.  Or, you may want to get rid of the
		# opts hash entirely.
		def _internet_enum_per_site_cookie_decision(site_name, pc_site_name_size, pdw_decision, opts = {})
			defaults = {  # defaults for args in opts hash
				:index => index_default
			}

			Merge in defaults. This approach allows caller to safely pass in a nil
			opts = defaults.merge(opts)

			# Any arg validation can go here

			ret = run_dll_function(:wininet, :InternetEnumPerSiteCookieDecision, site_name, pc_site_name_size, pdw_decision,
				opts[index],
			)

			# Additional code goes here

		end

		#
		# Displays a dialog box for the error that is passed to InternetErrorDlg, if an appropriate dialog box exists. If the FLAGS_ERROR_UI_FILTER_FOR_ERRORS flag is used, the function also checks the headers for any hidden errors and displays a dialog box if needed.
		# @see http://msdn.microsoft.com/en-us/library/windows/desktop/aa384694(v=vs.85).aspx InternetErrorDlg

		# @return [Unknown] Returns one of the following values, or an error value otherwise
		# @param [Fixnum] h_wnd Handle to the parent window for any needed dialog box
		# @param [Fixnum] h_request Handle to the Internet connection used in the call to HttpSendRequest
		# @param [Fixnum] dw_error Error value for which to display a dialog box
		# @param [Fixnum] dw_flags Actions
		# @param [Fixnum] lppv_data Pointer  to the address of a data structure
		#
		# There are quite a few arguments so an opts hash was added.  To clean
		# up the API, you should review it and adjust as needed.  You may want
		# to consider regrouping args for: clarity, so args that are usually
		# left at default values, or are optional, or always a specific value,
		# etc, are put in the opts hash.  Or, you may want to get rid of the
		# opts hash entirely.
		def _internet_error_dlg(wnd, request, error, opts = {})
			defaults = {  # defaults for args in opts hash
				:flags => flags_default
				:lppv_data => lppv_data_default
			}

			Merge in defaults. This approach allows caller to safely pass in a nil
			opts = defaults.merge(opts)

			# Any arg validation can go here

			ret = run_dll_function(:wininet, :InternetErrorDlg, wnd, request, error,
				opts[flags],
				opts[lppv_data],
			)

			# Additional code goes here

		end

		#
		# Continues a file search started as a result of a previous call to FtpFindFirstFile.
		# @see http://msdn.microsoft.com/en-us/library/windows/desktop/aa384698(v=vs.85).aspx InternetFindNextFile

		# @return [Boolean] Returns TRUE if the function succeeds, or FALSE otherwise
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

		# @return [Boolean] Returns TRUE if there is an active modem or a LAN Internet connection, or FALSE if there is no Internet connection, or if all possible Internet connections are not currently active
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
		# @see http://msdn.microsoft.com/en-us/library/windows/desktop/aa384705(v=vs.85).aspx InternetGetConnectedStateEx

		# @return [Boolean] Returns TRUE if there is an Internet connection, or FALSE if there is no Internet connection, or if all possible Internet connections are not currently active
		# @param [Fixnum] lpdw_flags Pointer to a variable that receives the connection description
		# @param [Fixnum] lpsz_connection_name Pointer to a string value that receives the connection name
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

			Merge in defaults. This approach allows caller to safely pass in a nil
			opts = defaults.merge(opts)

			# Any arg validation can go here

			ret = run_dll_function(:wininet, :InternetGetConnectedStateEx, flags, connection_name, name_len,
				opts[reserved],
			)

			# Additional code goes here

		end

		#
		# Retrieves the cookie for the specified URL.
		# @see http://msdn.microsoft.com/en-us/library/windows/desktop/aa384710(v=vs.85).aspx InternetGetCookie

		# @return [Boolean] If the function succeeds, the function returns TRUE
		# @param [Fixnum] lpsz_url A pointer to a null-terminated string that specifies the URL for which cookies are to be retrieved
		# @param [Fixnum] lpsz_cookie_name Not implemented
		# @param [Fixnum] lpsz_cookie_data A pointer to a buffer that receives the cookie data
		# @param [Fixnum] lpdw_size A pointer to a variable that specifies the size of the lpszCookieData parameter buffer, in TCHARs
		#
		# There are quite a few arguments so an opts hash was added.  To clean
		# up the API, you should review it and adjust as needed.  You may want
		# to consider regrouping args for: clarity, so args that are usually
		# left at default values, or are optional, or always a specific value,
		# etc, are put in the opts hash.  Or, you may want to get rid of the
		# opts hash entirely.
		def _internet_get_cookie(url, cookie_name, cookie_data, opts = {})
			defaults = {  # defaults for args in opts hash
				:size => size_default
			}

			Merge in defaults. This approach allows caller to safely pass in a nil
			opts = defaults.merge(opts)

			# Any arg validation can go here

			ret = run_dll_function(:wininet, :InternetGetCookie, url, cookie_name, cookie_data,
				opts[size],
			)

			# Additional code goes here

		end

		#
		# The InternetGetCookieEx function retrieves data stored in cookies associated with a specified URL. Unlike InternetGetCookie, InternetGetCookieEx can be used to  restrict data retrieved to a single cookie name or, by policy, associated with untrusted sites or third-party cookies.
		# @see http://msdn.microsoft.com/en-us/library/windows/desktop/aa384714(v=vs.85).aspx InternetGetCookieEx

		# @return [Boolean] If the function succeeds, the function returns TRUE
		# @param [Fixnum] lpsz_url A pointer to a null-terminated string that contains the URL with which the cookie to retrieve is associated
		# @param [Fixnum] lpsz_cookie_name A pointer to a null-terminated string that contains the name of the cookie to retrieve
		# @param [Fixnum] lpsz_cookie_data A pointer to a buffer to receive the cookie data
		# @param [Fixnum] lpdw_size A pointer to a DWORD variable
		# @param [Fixnum] dw_flags A flag that controls how the function retrieves cookie data
		# @param [Fixnum] lp_reserved Reserved for future use
		#
		# There are quite a few arguments so an opts hash was added.  To clean
		# up the API, you should review it and adjust as needed.  You may want
		# to consider regrouping args for: clarity, so args that are usually
		# left at default values, or are optional, or always a specific value,
		# etc, are put in the opts hash.  Or, you may want to get rid of the
		# opts hash entirely.
		def _internet_get_cookie_ex(url, cookie_name, cookie_data, opts = {})
			defaults = {  # defaults for args in opts hash
				:size => size_default
				:flags => flags_default
				:reserved => reserved_default
			}

			Merge in defaults. This approach allows caller to safely pass in a nil
			opts = defaults.merge(opts)

			# Any arg validation can go here

			ret = run_dll_function(:wininet, :InternetGetCookieEx, url, cookie_name, cookie_data,
				opts[size],
				opts[flags],
				opts[reserved],
			)

			# Additional code goes here

		end

		#
		# Retrieves the last error description or server response on the thread calling this function.
		# @see http://msdn.microsoft.com/en-us/library/windows/desktop/aa384717(v=vs.85).aspx InternetGetLastResponseInfo

		# @return [Boolean] Returns TRUE if error text was successfully written to the buffer, or FALSE otherwise
		# @param [Fixnum] lpdw_error Pointer to a variable that receives an error message pertaining to the operation that failed
		# @param [Fixnum] lpsz_buffer Pointer to a buffer that receives the error text
		# @param [Fixnum] lpdw_buffer_length Pointer to a variable that contains the size of the lpszBuffer buffer, in TCHARs
		#
		def _internet_get_last_response_info(error, buffer, buffer_length)

			# Any arg validation can go here

			ret = run_dll_function(:wininet, :InternetGetLastResponseInfo, error, buffer, buffer_length)

			# Additional code goes here

		end

		#
		# Retrieves a decision on cookies for a given domain.
		# @see http://msdn.microsoft.com/en-us/library/windows/desktop/aa384722(v=vs.85).aspx InternetGetPerSiteCookieDecision

		# @return [Boolean] Returns TRUE if the decision was retrieved and FALSE otherwise
		# @param [Fixnum] pch_host_name An LPCTSTR that points to a string containing a domain
		# @param [Fixnum] p_result A pointer to an unsigned long that contains one of the InternetCookieState enumeration values
		#
		def _internet_get_per_site_cookie_decision(host_name, p_result)

			# Any arg validation can go here

			ret = run_dll_function(:wininet, :InternetGetPerSiteCookieDecision, host_name, p_result)

			# Additional code goes here

		end

		#
		# Retrieves proxy data for accessing specified resources. This function can only be called by dynamically linking to "JSProxy.dll". For better autoproxy support, use HTTP Services (WinHTTP) version 5.1 instead. For more information, see WinHTTP AutoProxy Support.
		# @see http://msdn.microsoft.com/en-us/library/windows/desktop/aa384726(v=vs.85).aspx InternetGetProxyInfo

		# @return [Boolean] Returns TRUE if successful, or FALSE otherwise
		# @param [Fixnum] lpsz_url A pointer to a null-terminated string that specifies the URL of the target HTTP resource
		# @param [Fixnum] dw_url_length The size, in bytes, of the URL pointed to by lpszUrl
		# @param [Fixnum] lpsz_url_host_name A pointer to a null-terminated string  that specifies the host name of the target URL
		# @param [Fixnum] dw_url_host_name_length The size, in bytes, of the host name pointed to by lpszUrlHostName
		# @param [Fixnum] lplpsz_proxy_host_name A pointer to the address of a buffer that receives the URL of the proxy to use in an HTTP request for the specified resource
		# @param [Fixnum] lpdw_proxy_host_name_length A pointer to a variable that receives the size, in bytes, of the string returned in the lplpszProxyHostName buffer
		#
		# There are quite a few arguments so an opts hash was added.  To clean
		# up the API, you should review it and adjust as needed.  You may want
		# to consider regrouping args for: clarity, so args that are usually
		# left at default values, or are optional, or always a specific value,
		# etc, are put in the opts hash.  Or, you may want to get rid of the
		# opts hash entirely.
		def _internet_get_proxy_info(url, url_length, url_host_name, opts = {})
			defaults = {  # defaults for args in opts hash
				:url_host_name_length => url_host_name_length_default
				:lplpsz_proxy_host_name => lplpsz_proxy_host_name_default
				:proxy_host_name_length => proxy_host_name_length_default
			}

			Merge in defaults. This approach allows caller to safely pass in a nil
			opts = defaults.merge(opts)

			# Any arg validation can go here

			ret = run_dll_function(:wininet, :InternetGetProxyInfo, url, url_length, url_host_name,
				opts[url_host_name_length],
				opts[lplpsz_proxy_host_name],
				opts[proxy_host_name_length],
			)

			# Additional code goes here

		end

		#
		# Prompts the user for permission to initiate connection to a URL.
		# @see http://msdn.microsoft.com/en-us/library/windows/desktop/aa384734(v=vs.85).aspx InternetGoOnline

		# @return [Boolean] If the function succeeds, it returns TRUE
		# @param [Fixnum] lpsz_url Pointer to a null-terminated string that specifies the URL of the website for the connection
		# @param [Fixnum] hwnd_parent Handle to the parent window
		# @param [Fixnum] dw_flags This parameter can be zero or the following flag
		#
		def _internet_go_online(url, parent, flags)

			# Any arg validation can go here

			ret = run_dll_function(:wininet, :InternetGoOnline, url, parent, flags)

			# Additional code goes here

		end

		#
		# Instructs the modem to disconnect from the Internet.
		# @see http://msdn.microsoft.com/en-us/library/windows/desktop/aa384737(v=vs.85).aspx InternetHangUp

		# @return [Unknown] Returns ERROR_SUCCESS if successful, or an error value otherwise
		# @param [Fixnum] dw_connection Connection number of  the connection to be disconnected
		# @param [Fixnum] dw_reserved This parameter is reserved and must be 0
		#
		def _internet_hang_up(connection, reserved)

			# Any arg validation can go here

			ret = run_dll_function(:wininet, :InternetHangUp, connection, reserved)

			# Additional code goes here

		end

		#
		# There are two WinINet functions named InternetInitializeAutoProxyDll. The first, which merely refreshes the internal state of proxy configuration information from the registry, has a single parameter as documented directly below.
		# @see http://msdn.microsoft.com/en-us/library/windows/desktop/aa385093(v=vs.85).aspx InternetInitializeAutoProxyDll

		# @return [Boolean] Returns TRUE if successful, or FALSE otherwise
		# @param [Fixnum] dw_reserved This parameter is reserved and must be 0
		#
		def _internet_initialize_auto_proxy_dll(reserved)

			# Any arg validation can go here

			ret = run_dll_function(:wininet, :InternetInitializeAutoProxyDll, reserved)

			# Additional code goes here

		end

		#
		# Places a lock on the file that is being used.
		# @see http://msdn.microsoft.com/en-us/library/windows/desktop/aa385095(v=vs.85).aspx InternetLockRequestFile

		# @return [Boolean] Returns TRUE if successful, or FALSE otherwise
		# @param [Fixnum] h_internet Handle returned by the FtpOpenFile, GopherOpenFile, HttpOpenRequest, or InternetOpenUrl function
		# @param [Fixnum] lph_lock_req_handle Pointer to a handle that receives the lock request handle
		#
		def _internet_lock_request_file(internet, lph_lock_req_handle)

			# Any arg validation can go here

			ret = run_dll_function(:wininet, :InternetLockRequestFile, internet, lph_lock_req_handle)

			# Additional code goes here

		end

		#
		# Initializes an application's use of the WinINet functions.
		# @see http://msdn.microsoft.com/en-us/library/windows/desktop/aa385096(v=vs.85).aspx InternetOpen

		# @return [Fixnum] Returns a valid handle that the application passes to subsequent WinINet functions
		# @param [Fixnum] lpsz_agent Pointer to a null-terminated string  that specifies the name of the application or entity calling the WinINet functions
		# @param [Fixnum] dw_access_type Type of access required
		# @param [Fixnum] lpsz_proxy_name Pointer to a null-terminated string  that specifies the name of the proxy server(s) to use when proxy access is specified by setting dwAccessType to INTERNET_OPEN_TYPE_PROXY
		# @param [Fixnum] lpsz_proxy_bypass Pointer to a null-terminated string  that specifies an optional list of host names or IP addresses, or both, that should not be routed through the proxy when dwAccessType is set to INTERNET_OPEN_TYPE_PROXY
		# @param [Fixnum] dw_flags Options
		#
		# There are quite a few arguments so an opts hash was added.  To clean
		# up the API, you should review it and adjust as needed.  You may want
		# to consider regrouping args for: clarity, so args that are usually
		# left at default values, or are optional, or always a specific value,
		# etc, are put in the opts hash.  Or, you may want to get rid of the
		# opts hash entirely.
		def _internet_open(agent, access_type, proxy_name, opts = {})
			defaults = {  # defaults for args in opts hash
				:proxy_bypass => proxy_bypass_default
				:flags => flags_default
			}

			Merge in defaults. This approach allows caller to safely pass in a nil
			opts = defaults.merge(opts)

			# Any arg validation can go here

			ret = run_dll_function(:wininet, :InternetOpen, agent, access_type, proxy_name,
				opts[proxy_bypass],
				opts[flags],
			)

			# Additional code goes here

		end

		#
		# Opens a resource specified by a complete FTP or HTTP URL.
		# @see http://msdn.microsoft.com/en-us/library/windows/desktop/aa385098(v=vs.85).aspx InternetOpenUrl

		# @return [Fixnum] Returns a valid handle to the URL if the connection is successfully established, or NULL if the connection fails
		# @param [Fixnum] h_internet The handle to the current Internet session
		# @param [Fixnum] lpsz_url A pointer to a null-terminated string variable that specifies the URL to begin reading
		# @param [Fixnum] lpsz_headers A pointer to a null-terminated string  that specifies the headers to be sent to the HTTP server
		# @param [Fixnum] dw_headers_length The size of the additional headers, in TCHARs
		# @param [Fixnum] dw_flags This parameter can be one of the following values
		# @param [Fixnum] dw_context A pointer to a variable that specifies the application-defined value that is passed, along with the returned handle, to any callback functions
		#
		# There are quite a few arguments so an opts hash was added.  To clean
		# up the API, you should review it and adjust as needed.  You may want
		# to consider regrouping args for: clarity, so args that are usually
		# left at default values, or are optional, or always a specific value,
		# etc, are put in the opts hash.  Or, you may want to get rid of the
		# opts hash entirely.
		def _internet_open_url(internet, url, headers, opts = {})
			defaults = {  # defaults for args in opts hash
				:headers_length => headers_length_default
				:flags => flags_default
				:context => context_default
			}

			Merge in defaults. This approach allows caller to safely pass in a nil
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
		# @see http://msdn.microsoft.com/en-us/library/windows/desktop/aa385100(v=vs.85).aspx InternetQueryDataAvailable

		# @return [Boolean] Returns TRUE if the function succeeds, or FALSE otherwise
		# @param [Fixnum] h_file Handle returned by the InternetOpenUrl, FtpOpenFile, GopherOpenFile, or HttpOpenRequest function
		# @param [Fixnum] lpdw_number_of_bytes_available Pointer to a variable that receives the number of available bytes
		# @param [Fixnum] dw_flags This parameter is reserved and must be 0
		# @param [Fixnum] dw_context This parameter is reserved and must be 0
		#
		# There are quite a few arguments so an opts hash was added.  To clean
		# up the API, you should review it and adjust as needed.  You may want
		# to consider regrouping args for: clarity, so args that are usually
		# left at default values, or are optional, or always a specific value,
		# etc, are put in the opts hash.  Or, you may want to get rid of the
		# opts hash entirely.
		def _internet_query_data_available(file, number_of_bytes_available, flags, opts = {})
			defaults = {  # defaults for args in opts hash
				:context => context_default
			}

			Merge in defaults. This approach allows caller to safely pass in a nil
			opts = defaults.merge(opts)

			# Any arg validation can go here

			ret = run_dll_function(:wininet, :InternetQueryDataAvailable, file, number_of_bytes_available, flags,
				opts[context],
			)

			# Additional code goes here

		end

		#
		# Queries an Internet option on the specified handle.
		# @see http://msdn.microsoft.com/en-us/library/windows/desktop/aa385101(v=vs.85).aspx InternetQueryOption

		# @return [Boolean] Returns TRUE if successful, or FALSE otherwise
		# @param [Fixnum] h_internet Handle on which to query information
		# @param [Fixnum] dw_option Internet option to be queried
		# @param [Unknown] lp_buffer Pointer to a buffer that receives the option setting
		# @param [Fixnum] lpdw_buffer_length Pointer to a variable that contains the size of lpBuffer, in bytes
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

			Merge in defaults. This approach allows caller to safely pass in a nil
			opts = defaults.merge(opts)

			# Any arg validation can go here

			ret = run_dll_function(:wininet, :InternetQueryOption, internet, option, buffer,
				opts[buffer_length],
			)

			# Additional code goes here

		end

		#
		# Reads data from a handle opened by the InternetOpenUrl, FtpOpenFile, or HttpOpenRequest function.
		# @see http://msdn.microsoft.com/en-us/library/windows/desktop/aa385103(v=vs.85).aspx InternetReadFile

		# @return [Boolean] Returns TRUE if successful, or FALSE otherwise
		# @param [Fixnum] h_file Handle returned from a previous call to InternetOpenUrl, FtpOpenFile, or HttpOpenRequest
		# @param [Unknown] lp_buffer Pointer to a buffer that receives the data
		# @param [Fixnum] dw_number_of_bytes_to_read Number of bytes to be read
		# @param [Fixnum] lpdw_number_of_bytes_read Pointer to a variable that receives the number of bytes read
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

			Merge in defaults. This approach allows caller to safely pass in a nil
			opts = defaults.merge(opts)

			# Any arg validation can go here

			ret = run_dll_function(:wininet, :InternetReadFile, file, buffer, number_of_bytes_to_read,
				opts[number_of_bytes_read],
			)

			# Additional code goes here

		end

		#
		# Reads data from a handle opened by the InternetOpenUrl or HttpOpenRequest function.
		# @see http://msdn.microsoft.com/en-us/library/windows/desktop/aa385105(v=vs.85).aspx InternetReadFileEx

		# @return [Boolean] Returns TRUE if successful, or FALSE otherwise
		# @param [Fixnum] h_file Handle returned by the InternetOpenUrl or HttpOpenRequest function
		# @param [Unknown] lp_buffers_out Pointer to an INTERNET_BUFFERS structure that receives the data downloaded
		# @param [Fixnum] dw_flags This parameter can be one of the following values
		# @param [Fixnum] dw_context A caller supplied context value used for asynchronous operations
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

			Merge in defaults. This approach allows caller to safely pass in a nil
			opts = defaults.merge(opts)

			# Any arg validation can go here

			ret = run_dll_function(:wininet, :InternetReadFileEx, file, buffers_out, flags,
				opts[context],
			)

			# Additional code goes here

		end

		#
		# Creates a cookie associated with the specified URL.
		# @see http://msdn.microsoft.com/en-us/library/windows/desktop/aa385107(v=vs.85).aspx InternetSetCookie

		# @return [Boolean] Returns TRUE if successful, or FALSE otherwise
		# @param [Fixnum] lpsz_url Pointer to a null-terminated string that specifies the URL for which the cookie should be set
		# @param [Fixnum] lpsz_cookie_name Pointer to a null-terminated string that specifies the name to be associated with the cookie data
		# @param [Fixnum] lpsz_cookie_data Pointer to the actual data to be associated with the URL
		#
		def _internet_set_cookie(url, cookie_name, cookie_data)

			# Any arg validation can go here

			ret = run_dll_function(:wininet, :InternetSetCookie, url, cookie_name, cookie_data)

			# Additional code goes here

		end

		#
		# The InternetSetCookieEx function 	      creates a cookie with a specified name that is associated with a specified URL. This function differs from 	      the InternetSetCookie function by being able 	      to create third-party cookies.
		# @see http://msdn.microsoft.com/en-us/library/windows/desktop/aa385108(v=vs.85).aspx InternetSetCookieEx

		# @return [Unknown] Returns a member of the InternetCookieState enumeration if successful,  or  FALSE if the function fails
		# @param [Fixnum] lpsz_url Pointer to a null-terminated string that contains the URL for which the cookie should be set
		# @param [Fixnum] lpsz_cookie_name Pointer to a null-terminated string that  contains the name to associate with this cookie
		# @param [Fixnum] lpsz_cookie_data Pointer to a null-terminated string that contains the data to be associated with the new cookie
		# @param [Fixnum] dw_flags Flags that control how the function retrieves cookie data:ValueMeaningINTERNET_COOKIE_EVALUATE_P3PIf this flag is set and the dwReserved parameter is not NULL, then the dwReserved parameter is cast to an LPCTSTR that points to a Platform-for-Privacy-Protection (P3P) header for the cookie in question
		# @param [Fixnum] dw_reserved NULL, or contains a pointer to a Platform-for-Privacy-Protection (P3P) header to be associated with the cookie
		#
		# There are quite a few arguments so an opts hash was added.  To clean
		# up the API, you should review it and adjust as needed.  You may want
		# to consider regrouping args for: clarity, so args that are usually
		# left at default values, or are optional, or always a specific value,
		# etc, are put in the opts hash.  Or, you may want to get rid of the
		# opts hash entirely.
		def _internet_set_cookie_ex(url, cookie_name, cookie_data, opts = {})
			defaults = {  # defaults for args in opts hash
				:flags => flags_default
				:reserved => reserved_default
			}

			Merge in defaults. This approach allows caller to safely pass in a nil
			opts = defaults.merge(opts)

			# Any arg validation can go here

			ret = run_dll_function(:wininet, :InternetSetCookieEx, url, cookie_name, cookie_data,
				opts[flags],
				opts[reserved],
			)

			# Additional code goes here

		end

		#
		# No description found

		#
		# Sets a file position for InternetReadFile. This is a synchronous call; however, subsequent calls to InternetReadFile might block or return pending if the data is not available from the cache and the server does not support random access.
		# @see http://msdn.microsoft.com/en-us/library/windows/desktop/aa385113(v=vs.85).aspx InternetSetFilePointer

		# @return [Unknown] I the function succeeds, it returns the current file position
		# @param [Fixnum] h_file Handle returned from a previous call to InternetOpenUrl (on an HTTP or HTTPS						URL) or HttpOpenRequest (using the GET or HEAD HTTP verb and passed to HttpSendRequest or HttpSendRequestEx)
		# @param [Unknown] l_distance_to_move The low order 32-bits of a signed 64-bit number of bytes to move the file pointer
		# @param [Unknown] lp_distance_to_move_high A pointer to the high order 32-bits of the signed 64-bit distance        to move
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
				:move_method => move_method_default
				:context => context_default
			}

			Merge in defaults. This approach allows caller to safely pass in a nil
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

		# @return [Boolean] Returns TRUE if successful, or FALSE otherwise
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

			Merge in defaults. This approach allows caller to safely pass in a nil
			opts = defaults.merge(opts)

			# Any arg validation can go here

			ret = run_dll_function(:wininet, :InternetSetOption, internet, option, buffer,
				opts[buffer_length],
			)

			# Additional code goes here

		end

		#
		# No description found

		#
		# Sets a decision on cookies for a given domain.
		# @see http://msdn.microsoft.com/en-us/library/windows/desktop/aa385118(v=vs.85).aspx InternetSetPerSiteCookieDecision

		# @return [Boolean] Returns TRUE if the decision is set and FALSE otherwise
		# @param [Fixnum] pch_host_name An LPCTSTR that points to a string containing a domain
		# @param [Fixnum] dw_decision A value of type DWORD that contains one of the InternetCookieState enumeration values
		#
		def _internet_set_per_site_cookie_decision(host_name, decision)

			# Any arg validation can go here

			ret = run_dll_function(:wininet, :InternetSetPerSiteCookieDecision, host_name, decision)

			# Additional code goes here

		end

		#
		# The InternetSetStatusCallback function sets up a callback function that WinINet functions can call as progress is made during an operation.
		# @see http://msdn.microsoft.com/en-us/library/windows/desktop/aa385120(v=vs.85).aspx Unknown

		# @return [Unknown] Returns the previously defined status callback function if successful, NULL if there was no previously defined status callback function, or INTERNET_INVALID_STATUS_CALLBACK if the callback function is not valid
		# @param [Unk] unknown The						handle for which the callback is set
		# @param [Fixnum] h_internet A pointer to the callback function to call when progress is made, or  NULL to remove the existing callback function
		# @param [Unknown] lpfn_internet_callback description TBD
		#
		def _unknown(unknown, internet, internet_callback)

			# Any arg validation can go here

			ret = run_dll_function(:wininet, :Unknown, unknown, internet, internet_callback)

			# Additional code goes here

		end

		#
		# Prototype for an application-defined status callback function.
		# @see http://msdn.microsoft.com/en-us/library/windows/desktop/aa385121(v=vs.85).aspx Unknown

		# @return [Unknown] This callback function does not return a value
		# @return [Unknown] This callback function does not return a value
		# @param [Fixnum] h_internet The handle for which the callback function is called
		# @param [Fixnum] dw_context A pointer to a variable that specifies the application-defined context value associated with hInternet
		# @param [Fixnum] dw_internet_status A status code that indicates why the callback function is called
		# @param [Fixnum] lpv_status_information A pointer to additional status information
		# @param [Fixnum] dw_status_information_length The size, in bytes, of the data pointed to by lpvStatusInformation
		#
		# There are quite a few arguments so an opts hash was added.  To clean
		# up the API, you should review it and adjust as needed.  You may want
		# to consider regrouping args for: clarity, so args that are usually
		# left at default values, or are optional, or always a specific value,
		# etc, are put in the opts hash.  Or, you may want to get rid of the
		# opts hash entirely.
		def _unknown(internet_status_callback(, internet, context, opts = {})
			defaults = {  # defaults for args in opts hash
				:internet_status => internet_status_default
				:status_information => status_information_default
				:status_information_length => status_information_length_default
			}

			Merge in defaults. This approach allows caller to safely pass in a nil
			opts = defaults.merge(opts)

			# Any arg validation can go here

			ret = run_dll_function(:wininet, :Unknown, internet_status_callback(, internet, context,
				opts[internet_status],
				opts[status_information],
				opts[status_information_length],
			)

			# Additional code goes here

		end

		#
		# Formats a date and time according to the HTTP version 1.0 specification.
		# @see http://msdn.microsoft.com/en-us/library/windows/desktop/aa385123(v=vs.85).aspx InternetTimeFromSystemTime

		# @return [Boolean] Returns TRUE if the function succeeds, or FALSE otherwise
		# @param [Unknown] pst Pointer to a SYSTEMTIME structure that contains the date and time to format
		# @param [Fixnum] dw_rfc RFC format used
		# @param [Fixnum] lpsz_time Pointer to a string buffer that receives the formatted date and time
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

			Merge in defaults. This approach allows caller to safely pass in a nil
			opts = defaults.merge(opts)

			# Any arg validation can go here

			ret = run_dll_function(:wininet, :InternetTimeFromSystemTime, pst, rfc, time,
				opts[time],
			)

			# Additional code goes here

		end

		#
		# Converts an HTTP time/date string to a SYSTEMTIME structure.
		# @see http://msdn.microsoft.com/en-us/library/windows/desktop/aa385125(v=vs.85).aspx InternetTimeToSystemTime

		# @return [Boolean] Returns TRUE if the string was converted, or FALSE otherwise
		# @param [Fixnum] lpsz_time Pointer to a null-terminated string that specifies the date/time to  be converted
		# @param [Fixnum] pst Pointer to a SYSTEMTIME structure that receives the converted time
		# @param [Fixnum] dw_reserved This parameter is reserved and must be 0
		#
		def _internet_time_to_system_time(time, pst, reserved)

			# Any arg validation can go here

			ret = run_dll_function(:wininet, :InternetTimeToSystemTime, time, pst, reserved)

			# Additional code goes here

		end

		#
		# Unlocks a file that was locked using InternetLockRequestFile.
		# @see http://msdn.microsoft.com/en-us/library/windows/desktop/aa385126(v=vs.85).aspx InternetUnlockRequestFile

		# @return [Boolean] Returns TRUE if successful, or FALSE otherwise
		# @param [Fixnum] h_lock_request_info Handle to a lock request that was returned by InternetLockRequestFile
		#
		def _internet_unlock_request_file(lock_request_info)

			# Any arg validation can go here

			ret = run_dll_function(:wininet, :InternetUnlockRequestFile, lock_request_info)

			# Additional code goes here

		end

		#
		# Writes data to an open Internet file.
		# @see http://msdn.microsoft.com/en-us/library/windows/desktop/aa385128(v=vs.85).aspx InternetWriteFile

		# @return [Boolean] Returns TRUE if the function succeeds, or FALSE otherwise
		# @param [Fixnum] h_file Handle returned from a previous call to FtpOpenFile or an HINTERNET handle sent by HttpSendRequestEx
		# @param [Fixnum] lp_buffer Pointer to a buffer that contains the data to be written to the file
		# @param [Fixnum] dw_number_of_bytes_to_write Number of bytes to be written to the file
		# @param [Fixnum] lpdw_number_of_bytes_written Pointer to a variable that receives the number of bytes written to the file
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

			Merge in defaults. This approach allows caller to safely pass in a nil
			opts = defaults.merge(opts)

			# Any arg validation can go here

			ret = run_dll_function(:wininet, :InternetWriteFile, file, buffer, number_of_bytes_to_write,
				opts[number_of_bytes_written],
			)

			# Additional code goes here

		end

		#
		# Retrieves the privacy settings for a given URLZONE and PrivacyType.
		# @see http://msdn.microsoft.com/en-us/library/windows/desktop/aa385336(v=vs.85).aspx PrivacyGetZonePreferenceW

		# @return [Unknown] Returns zero if successful
		# @param [Fixnum] dw_zone A value of type DWORD that specifies the URLZONE for which privacy settings are being retrieved
		# @param [Fixnum] dw_type A value of type DWORD that specifies the PrivacyType for which privacy settings are being retrieved
		# @param [Fixnum] pdw_template An LPDWORD that returns a pointer to a DWORD containing which of the PrivacyTemplates is in use for this dwZone and dwType
		# @param [Fixnum] psz_buffer An  LPWSTR that points to a buffer containing a LPCWSTR representing a string version of the pdwTemplate or a customized string if the pdwTemplate is set to PRIVACY_TEMPLATE_CUSTOM
		# @param [Fixnum] pdw_buffer_length An LPDWORD that contains the buffer length in characters
		#
		# There are quite a few arguments so an opts hash was added.  To clean
		# up the API, you should review it and adjust as needed.  You may want
		# to consider regrouping args for: clarity, so args that are usually
		# left at default values, or are optional, or always a specific value,
		# etc, are put in the opts hash.  Or, you may want to get rid of the
		# opts hash entirely.
		def _privacy_get_zone_preference_w(zone, type, template, opts = {})
			defaults = {  # defaults for args in opts hash
				:psz_buffer => psz_buffer_default
				:buffer_length => buffer_length_default
			}

			Merge in defaults. This approach allows caller to safely pass in a nil
			opts = defaults.merge(opts)

			# Any arg validation can go here

			ret = run_dll_function(:wininet, :PrivacyGetZonePreferenceW, zone, type, template,
				opts[psz_buffer],
				opts[buffer_length],
			)

			# Additional code goes here

		end

		#
		# Sets the privacy settings for a given URLZONE and PrivacyType.
		# @see http://msdn.microsoft.com/en-us/library/windows/desktop/aa385338(v=vs.85).aspx PrivacySetZonePreferenceW

		# @return [Unknown] Returns zero if successful
		# @param [Fixnum] dw_zone Value of type DWORD that specifies the URLZONEfor which privacy settings are being set
		# @param [Fixnum] dw_type Value of type DWORD that specifies the PrivacyType for which privacy settings are being set
		# @param [Fixnum] dw_template Value of type DWORD that specifies which of the privacy templates is to be used to set the privacy settings
		# @param [Fixnum] psz_preference If dwTemplate is set to PRIVACY_TEMPLATE_CUSTOM, this parameter is the string representation of the custom preferences
		#
		# There are quite a few arguments so an opts hash was added.  To clean
		# up the API, you should review it and adjust as needed.  You may want
		# to consider regrouping args for: clarity, so args that are usually
		# left at default values, or are optional, or always a specific value,
		# etc, are put in the opts hash.  Or, you may want to get rid of the
		# opts hash entirely.
		def _privacy_set_zone_preference_w(zone, type, template, opts = {})
			defaults = {  # defaults for args in opts hash
				:preference => preference_default
			}

			Merge in defaults. This approach allows caller to safely pass in a nil
			opts = defaults.merge(opts)

			# Any arg validation can go here

			ret = run_dll_function(:wininet, :PrivacySetZonePreferenceW, zone, type, template,
				opts[preference],
			)

			# Additional code goes here

		end

		#
		# Reads the cached data from a stream that has been opened using the RetrieveUrlCacheEntryStream function.
		# @see http://msdn.microsoft.com/en-us/library/windows/desktop/aa385354(v=vs.85).aspx ReadUrlCacheEntryStream

		# @return [Boolean] Returns TRUE if successful, or FALSE otherwise
		# @param [Fixnum] h_url_cache_stream Handle that was returned by the RetrieveUrlCacheEntryStream function
		# @param [Fixnum] dw_location Offset to be read from
		# @param [Fixnum] lp_buffer Pointer to a buffer that receives the data
		# @param [Fixnum] lpdw_len Pointer to a  variable that specifies the size of the lpBuffer buffer, in bytes
		# @param [Fixnum] dw_reserved This parameter is reserved and must be 0
		#
		# There are quite a few arguments so an opts hash was added.  To clean
		# up the API, you should review it and adjust as needed.  You may want
		# to consider regrouping args for: clarity, so args that are usually
		# left at default values, or are optional, or always a specific value,
		# etc, are put in the opts hash.  Or, you may want to get rid of the
		# opts hash entirely.
		def _read_url_cache_entry_stream(url_cache_stream, location, buffer, opts = {})
			defaults = {  # defaults for args in opts hash
				:len => len_default
				:reserved => reserved_default
			}

			Merge in defaults. This approach allows caller to safely pass in a nil
			opts = defaults.merge(opts)

			# Any arg validation can go here

			ret = run_dll_function(:wininet, :ReadUrlCacheEntryStream, url_cache_stream, location, buffer,
				opts[len],
				opts[reserved],
			)

			# Additional code goes here

		end

		#
		# The ResumeSuspendedDownload function resumes a request that is suspended by a user interface dialog box.
		# @see http://msdn.microsoft.com/en-us/library/windows/desktop/aa385357(v=vs.85).aspx ResumeSuspendedDownload

		# @return [Boolean] Returns TRUE if successful; otherwise  FALSE
		# @param [Fixnum] h_request Handle of the request that is suspended by a user interface dialog box
		# @param [Fixnum] dw_result_code The error result returned from InternetErrorDlg, or zero if a different dialog  is  invoked
		#
		def _resume_suspended_download(request, result_code)

			# Any arg validation can go here

			ret = run_dll_function(:wininet, :ResumeSuspendedDownload, request, result_code)

			# Additional code goes here

		end

		#
		# Locks the cache entry file associated with the specified URL.
		# @see http://msdn.microsoft.com/en-us/library/windows/desktop/aa385365(v=vs.85).aspx RetrieveUrlCacheEntryFile

		# @return [Boolean] Returns TRUE if successful, or FALSE otherwise
		# @param [Fixnum] lpsz_url_name Pointer to a string that contains the URL of the resource associated with the cache entry
		# @param [Unknown] lp_cache_entry_info Pointer to a cache entry information buffer
		# @param [Fixnum] lpcb_cache_entry_info Pointer to an unsigned long integer variable that specifies the size of the lpCacheEntryInfo buffer, in bytes
		# @param [Fixnum] dw_reserved This parameter is reserved and must be 0
		#
		# There are quite a few arguments so an opts hash was added.  To clean
		# up the API, you should review it and adjust as needed.  You may want
		# to consider regrouping args for: clarity, so args that are usually
		# left at default values, or are optional, or always a specific value,
		# etc, are put in the opts hash.  Or, you may want to get rid of the
		# opts hash entirely.
		def _retrieve_url_cache_entry_file(url_name, cache_entry_info, cache_entry_info, opts = {})
			defaults = {  # defaults for args in opts hash
				:reserved => reserved_default
			}

			Merge in defaults. This approach allows caller to safely pass in a nil
			opts = defaults.merge(opts)

			# Any arg validation can go here

			ret = run_dll_function(:wininet, :RetrieveUrlCacheEntryFile, url_name, cache_entry_info, cache_entry_info,
				opts[reserved],
			)

			# Additional code goes here

		end

		#
		# Provides the most efficient and implementation-independent way to access the cache data.
		# @see http://msdn.microsoft.com/en-us/library/windows/desktop/aa385368(v=vs.85).aspx RetrieveUrlCacheEntryStream

		# @return [Fixnum] If the function succeeds, the function returns a valid handle for use in the  ReadUrlCacheEntryStream and  UnlockUrlCacheEntryStream functions
		# @param [Fixnum] lpsz_url_name Pointer to a null-terminated string that contains the source name of the cache entry
		# @param [Unknown] lp_cache_entry_info Pointer to an INTERNET_CACHE_ENTRY_INFO structure that receives information about the cache entry
		# @param [Fixnum] lpcb_cache_entry_info Pointer to a variable that specifies the size, in bytes, of the lpCacheEntryInfo buffer
		# @param [Unknown] f_random_read Whether the stream is open for random access
		# @param [Fixnum] dw_reserved This parameter is reserved and must be 0
		#
		# There are quite a few arguments so an opts hash was added.  To clean
		# up the API, you should review it and adjust as needed.  You may want
		# to consider regrouping args for: clarity, so args that are usually
		# left at default values, or are optional, or always a specific value,
		# etc, are put in the opts hash.  Or, you may want to get rid of the
		# opts hash entirely.
		def _retrieve_url_cache_entry_stream(url_name, cache_entry_info, cache_entry_info, opts = {})
			defaults = {  # defaults for args in opts hash
				:random_read => random_read_default
				:reserved => reserved_default
			}

			Merge in defaults. This approach allows caller to safely pass in a nil
			opts = defaults.merge(opts)

			# Any arg validation can go here

			ret = run_dll_function(:wininet, :RetrieveUrlCacheEntryStream, url_name, cache_entry_info, cache_entry_info,
				opts[random_read],
				opts[reserved],
			)

			# Additional code goes here

		end

		#
		# Adds entries to or removes entries from a cache group.
		# @see http://msdn.microsoft.com/en-us/library/windows/desktop/aa385390(v=vs.85).aspx SetUrlCacheEntryGroup

		# @return [Boolean] Returns TRUE if successful, or FALSE otherwise
		# @param [Fixnum] lpsz_url_name Pointer to a null-terminated string value that specifies the URL of the cached resource
		# @param [Fixnum] dw_flags Determines whether the entry is added to or removed from a cache group
		# @param [Unknown] group_id Identifier of the cache group that the entry will be added to or removed from
		# @param [Fixnum] pb_group_attributes This parameter is reserved and must be NULL
		# @param [Fixnum] cb_group_attributes This parameter is reserved and must be 0
		# @param [Fixnum] lp_reserved This parameter is reserved and must be NULL
		#
		# There are quite a few arguments so an opts hash was added.  To clean
		# up the API, you should review it and adjust as needed.  You may want
		# to consider regrouping args for: clarity, so args that are usually
		# left at default values, or are optional, or always a specific value,
		# etc, are put in the opts hash.  Or, you may want to get rid of the
		# opts hash entirely.
		def _set_url_cache_entry_group(url_name, flags, group_id, opts = {})
			defaults = {  # defaults for args in opts hash
				:group_attributes => group_attributes_default
				:group_attributes => group_attributes_default
				:reserved => reserved_default
			}

			Merge in defaults. This approach allows caller to safely pass in a nil
			opts = defaults.merge(opts)

			# Any arg validation can go here

			ret = run_dll_function(:wininet, :SetUrlCacheEntryGroup, url_name, flags, group_id,
				opts[group_attributes],
				opts[group_attributes],
				opts[reserved],
			)

			# Additional code goes here

		end

		#
		# Sets the specified members of the INTERNET_CACHE_ENTRY_INFO structure.
		# @see http://msdn.microsoft.com/en-us/library/windows/desktop/aa385396(v=vs.85).aspx SetUrlCacheEntryInfo

		# @return [Boolean] Returns TRUE if successful, or FALSE otherwise
		# @param [Fixnum] lpsz_url_name Pointer to a null-terminated string that specifies the name of the cache entry
		# @param [Fixnum] lp_cache_entry_info Pointer to an INTERNET_CACHE_ENTRY_INFO structure containing the values to be assigned to the cache entry designated by lpszUrlName
		# @param [Fixnum] dw_field_control Indicates the members that are to be set
		#
		def _set_url_cache_entry_info(url_name, cache_entry_info, field_control)

			# Any arg validation can go here

			ret = run_dll_function(:wininet, :SetUrlCacheEntryInfo, url_name, cache_entry_info, field_control)

			# Additional code goes here

		end

		#
		# Sets the attribute information of the specified cache group.
		# @see http://msdn.microsoft.com/en-us/library/windows/desktop/aa385401(v=vs.85).aspx SetUrlCacheGroupAttribute

		# @return [Boolean] Returns TRUE if successful, or FALSE otherwise
		# @param [Unknown] gid Identifier of the cache group
		# @param [Fixnum] dw_flags This parameter is reserved and must be 0
		# @param [Fixnum] dw_attributes Attributes to be set
		# @param [Fixnum] lp_group_info Pointer to an INTERNET_CACHE_GROUP_INFO structure that specifies the attribute information to be stored
		# @param [Fixnum] lp_reserved This parameter is reserved and must be NULL
		#
		# There are quite a few arguments so an opts hash was added.  To clean
		# up the API, you should review it and adjust as needed.  You may want
		# to consider regrouping args for: clarity, so args that are usually
		# left at default values, or are optional, or always a specific value,
		# etc, are put in the opts hash.  Or, you may want to get rid of the
		# opts hash entirely.
		def _set_url_cache_group_attribute(gid, flags, attributes, opts = {})
			defaults = {  # defaults for args in opts hash
				:group_info => group_info_default
				:reserved => reserved_default
			}

			Merge in defaults. This approach allows caller to safely pass in a nil
			opts = defaults.merge(opts)

			# Any arg validation can go here

			ret = run_dll_function(:wininet, :SetUrlCacheGroupAttribute, gid, flags, attributes,
				opts[group_info],
				opts[reserved],
			)

			# Additional code goes here

		end

		#
		# Unlocks the cache entry that was locked while the file was retrieved for use from the cache.
		# @see http://msdn.microsoft.com/en-us/library/windows/desktop/aa385407(v=vs.85).aspx UnlockUrlCacheEntryFile

		# @return [Boolean] Returns TRUE if successful, or FALSE otherwise
		# @param [Fixnum] lpsz_url_name Pointer to a null-terminated string that specifies the source name of the cache entry that is being unlocked
		# @param [Fixnum] dw_reserved This parameter is reserved and must be 0
		#
		def _unlock_url_cache_entry_file(url_name, reserved)

			# Any arg validation can go here

			ret = run_dll_function(:wininet, :UnlockUrlCacheEntryFile, url_name, reserved)

			# Additional code goes here

		end

		#
		# Closes the stream that has been retrieved using the RetrieveUrlCacheEntryStream function.
		# @see http://msdn.microsoft.com/en-us/library/windows/desktop/aa385415(v=vs.85).aspx UnlockUrlCacheEntryStream
		# @return [Boolean] Returns TRUE if successful, or FALSE otherwise
		# @param [Fixnum] h_url_cache_stream Handle that was returned by the RetrieveUrlCacheEntryStream function
		# @param [Fixnum] dw_reserved This parameter is reserved and must be NULL
		#
		def _unlock_url_cache_entry_stream(url_cache_stream, reserved)

			# Any arg validation can go here

			ret = run_dll_function(:wininet, :UnlockUrlCacheEntryStream, url_cache_stream, reserved)

			# Additional code goes here

		end

	end # Ie

end # Browser
end # Windows
end # Post
end # Msf
