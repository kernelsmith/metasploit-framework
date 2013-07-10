# -*- coding: binary -*-

module Msf
class Post
module Windows

module Browser
	# API for browser manipulation, automation, and control etc
	# (InternetAttemptConnection -> InternetOpen -> InternetOpenUrl -> InternetReadFile? -> InternetCloseHandle

	# Check internet connection with wininet.dll!InternetCheckConnection on the
	# given host or the local machine if :host option is nil. 
	#
	# @param opts [Hash]
	# @option opts [String] :url (nil)  May be a hostname or IP address.
	# @option opts [Fixnum] :access (0xF003F) Bitwise-or of the
	#   SC_MANAGER_* constants (see
	#   {http://msdn.microsoft.com/en-us/library/windows/desktop/ms685981(v=vs.85).aspx})
	#
	# @return [true,false] True if there were no errors, false otherwise
	# @raise [RuntimeError] if InternetCheckConnection returns an error
	#
	def check_internet_connection(opts = {})
		defaults = {:url => "www.google.com", :force_connection => false}
		opts = defaults.merge(opts)
		if opts[:force_connection]
			dwflags = FLAG_ICC_FORCE_CONNECTION # is this quoted?  can't recall
		else
			dwflags = 0
		end
		res = session.railgun.wininet.InternetCheckConnection(opts[:url],dwflags)
		if not res["GetLastError"] == 0
			raise RuntimeError.new("Unable to check internet connection, GetLastError: #{res["GetLastError"]}")
			# @todo:  add error code lookup?
		else
			return res["return"]
		end
	end

	# @return [Fixnum] Opaque Windows handle HINTERNET as returned by InternetOpenA()
	def initialize_internet(handle, url, opts = {})
		defaults = {
					:headers => nil,
					:headers_length => 0,
					:flags => INTERNET_FLAG_HYPERLINK && \
								INTERNET_FLAG_IGNORE_REDIRECT_TO_HTTPS && \
								INTERNET_FLAG_NO_CACHE_WRITE && \
								INTERNET_FLAG_NO_UI && \
								INTERNET_FLAG_PRAGMA_NOCACHE,
					:context => nil # is this right?  it's a PDWORD, could we use it for port in firebind?
				}
		opts = defaults.merge(opts)
		res = session.railgun.wininet.InternetOpenUrl(
			handle,
			url,
			opts[:headers],
			opts[:headers_length],
			opts[:flags],
			opts[:context])
		if not res["GetLastError"] == 0
			raise RuntimeError.new("Unable to initialize wininet dll, GetLastError: #{res["GetLastError"]}")
			# @todo:  To determine why access to the service was denied, call InternetGetLastResponseInfo.
			# @todo:  add error code lookup?
		else
			return res["return"]
			# use InternetReadFile to read the returned data
		end
	end

	def open_url_simple(opts = {})
		defaults = {
					:ua => "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)", # ghetto, detect it
					:access => INTERNET_OPEN_TYPE_PRECONFIG,
					:proxy_name => nil,
					:proxy_bypass => nil,
					:flags => INTERNET_FLAG_ASYNC,
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
	end

module Ie
	# API for Internet Explorer manipulation, automation, and control etc via Railgun

	# should we use a class instead?
	# The class object could have the HINTERNET handle as it's primary attribute


	#
	# Description
	#
	# @param str1 [String] The str to blah
	# @param num1 [Fixnum] The base number to blah
	# @param pid  [Fixnum] The process ID to fondle
	#
	# @return [Boolean] True if successful, otherwise false
	#
	def execute_shellcode(shellcode, base_addr=nil, pid=nil)
		pid ||= session.sys.process.getpid
		host  = session.sys.process.open(pid.to_i, PROCESS_ALL_ACCESS)
		if base_addr.nil?
			shell_addr = host.memory.allocate(shellcode.length)
		else
			shell_addr = host.memory.allocate(shellcode.length, nil, base_addr)
		end
		if host.memory.write(shell_addr, shellcode) < shellcode.length
			vprint_error("Failed to write shellcode")
			return false
		end

		vprint_status("Creating the thread to execute in 0x#{shell_addr.to_s(16)} (pid=#{pid.to_s})")
		ret = session.railgun.kernel32.CreateThread(nil, 0, shell_addr, nil, 0, nil)
		if ret['return'] < 1
			vprint_error("Unable to CreateThread")
			return false
		end

		true
	end

	#
	# From MSDN
	#


end # Ie
end # Browser
end # Windows
end # Post
end # Msf
