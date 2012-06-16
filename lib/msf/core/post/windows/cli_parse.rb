
module Msf
class Post
module Windows

module CliParse

	require 'msf/windows_error'
	require 'rex/logging'
	require 'rex/exceptions'

	# some constants
	REG_DATA_TYPES = 'REG_SZ|REG_MULTI_SZ|REG_DWORD_BIG_ENDIAN|REG_DWORD|REG_BINARY|' +
	'REG_DWORD_LITTLE_ENDIAN|REG_NONE|REG_EXPAND_SZ|REG_LINK|REG_FULL_RESOURCE_DESCRIPTOR'

	#Msf::Post::Windows::CliParse::ParseError
	class ParseError < ArgumentError
		def initialize(method, einfo='', ecode=nil, clicmd=nil)
			@method = method
			@info = einfo
			# try to look up info if not given, but code is?
			@code   = ecode
			@clicmd = clicmd || "Unknown shell command"
		end

		def to_s
			"#{@method}: Operation failed: #{@info}:#{@code} while running #{@clicmd}"
		end

		# The method that failed.
		attr_reader :method

		# The error info that occurred, typically a windows error message.
		attr_reader :info

		# The error result that occurred, typically a windows error code.
		attr_reader :code

		# The shell command that caused the error, if known
		attr_reader :clicmd
	end

	#
	# Parses output of some windows CLI commands and returns a hash with the
	# keys/vals detected.  If the item has multiple values, they will all be
	# returned in the val separated by commas. Keys are downcased and
	# symbolized (key.downcase.to_sym)
	#
	# sc.exe example (somewhat contrived):
	#    SERVICE_NAME: dumbservice
	#    DISPLAY_NAME: KernelSmith Dumb Service - User-mode
	#    TYPE               : 20  WIN32_SHARE_PROCESS
	#    STATE              : 4  RUNNING
	#                            (NOT_STOPPABLE, NOT_PAUSABLE, IGNORES_SHUTDOWN)
	#    START_TYPE         : 2   AUTO_START
	#    BINARY_PATH_NAME   : C:\Windows\system32\svchost.exe -k LocalSystemNetworkRestricted
	#    DEPENDENCIES       : PlugPlay
	#                       : DumberService
	#    SERVICE_START_NAME : LocalSystem
	#
	# returns:
	#    {
	#      :service_name     => "dumbservice",
	#      :display_name     => "KernelSmith Dumb Service - User-mod",
	#      :state            => "4  RUNNING",
	#      :start_type       => "2   AUTO_START",
	#      :binary_path_name => "C:\Windows\system32\svchost.exe -k LocalSystemNetworkRestricted",
	#      :dependencies     => "PlugPlay,DumberService"
	#      <...etc...>
	#    }
	#
	def win_parse_results(str)
		tip = false
		hashish = {}
		lastkey = nil
		str.each_line do |line|
			line.chomp!
			line.gsub!("\t",' ') # lose any tabs
			if (tip == true && line =~ /^ + :/)
				# then this is probably a continuation of the previous, let's append to previous
				# NOTE:  this will NOT pickup the (NOT_STOPPABLE, NOT_PAUSABLE), see next, but it
				# 	 will pickup when there's multiple dependencies
				arr = line.scan(/\w+/)
				val = arr.join(',') # join with commas, tho there is probably only one item in arr
				hashish[lastkey] << ",#{val}" # append to old val with preceding ','
				# if that's confusing, maybe:  hashish[lastkey] = "#{hashish[lastkey]},#{val}"
				tip = false
			elsif (tip == true && line =~ /^ + \(/)
				# then this is probably a continuation of the previous, let's append to previous
				# NOTE:  this WILL pickup (NOT_STOPPABLE, NOT_PAUSABLE) etc
				arr = line.scan(/\w+/) # put each "word" into an array
				val = arr.join(',') # join back together with commas in case comma wasn't the sep
				hashish[lastkey] << ",#{val}" # append to old val with preceding ','
				# if that's confusing, maybe:  hashish[lastkey] = "#{hashish[lastkey]},#{val}"
				tip = false
			elsif line =~ /^ *[A-Z]+[_]*[A-Z]+.*:/
				tip = true
				arr = line.split(':')
				k = arr[0].strip.downcase.to_sym
				# grab all remaining fields for hash val in case ':' present in val
				v = arr[1..-1].join(':').strip
				# now add this entry to the hash
				hashish[k] = v
				lastkey = k
			end
		end
		# finally, do type conversion as applicable
		hashish.each_pair do |k,v|
			hashish[k] = normalize_stupid_win_hex(v)
		end
		return hashish
	end

	#
	# Parses error output of some windows CLI commands and returns hash with
	# the keys/vals detected always returns hash as follows but :errval only
	# comes back from sc.exe using 'FAILED' keyword
	#
	# Note, most of the time the :errval will be nil, it's not usually provided
	#
	#
	# sc.exe error example:
	#    [SC] EnumQueryServicesStatus:OpenService FAILED 1060:
	#
	#    The specified service does not exist as an installed service.
	# returns:
	#    {
	#      :error  => "The specified service does not exist as an installed service",
	#      :errval => 1060
	#    }
	#
	# reg.exe error example:
	#    ERROR: Invalid key name.
	#    Type "REG QUERY /?" for usage.
	# returns:
	#    {
	#      :error  => "INVALID KEY NAME."
	#      :errval => nil
	#    }
	#
	def win_parse_error(results)
		hashish = {
			:error => "Unknown Error",
			:errval => nil
		}
		# parse the results
		if ma = /^error:.*/i.match(results) # if line starts with Error: just pass to regular parser
			hashish.merge!(win_parse_results(ma[0].upcase)) #upcase required to satisfy regular parser
			# merge results.  Results from win_parse_results will override any duplicates in hashish
		elsif ma = /FAILED +[0-9]+/.match(results) # look for 'FAILED ' followed by some numbers
			sa = ma[0].split(' ')
			hashish[:errval] = sa[1].chomp.to_i
			# ^ intended to capture the numbers after the word 'FAILED' as [:errval]
			ma = /^[^\[\n].+/.match(results)
			hashish[:error] = ma[0].chomp.strip
			# above intended to capture first non-empty line not starting with '[' or \n into [:error]
		else
			# do nothing, defaults are good
		end
		return hashish
	end

	def normalize_reg_data_val(val,type)
		# we want to normalize stuff but we need to be wary of what type of data
		# is being processes, and by type we mean windows type
		# we might get "alwayson" or "0x0A" or "1001" etc
		# if we get an integer, we assume it's already correct and return it
		return val if val.class == Fixnum
		# otherwise we have to use the type to figure it out
		case normalize_reg_data_type(type)
		when 0 #REG_NONE
			# then we have no idea what to do with the val so we return it
			return val
		when 1 #REG_SZ: A null-terminated string] Running against session 1
			# we want to normalize w/o major changes, so we only rstrip to kill any nulls
			return val.to_s.rstrip # I wonder if unpack("A*").join would be better?
		when 2 #REG_EXPAND_SZ null-terminated string containing unexpanded refs to env vars
			# we're not going to play dat, we just treat it as a string
			return val.to_s.rstrip # I wonder if unpack("A*").join would be better?
		when 3 #REG_BINARY duh.
			return val.to_i(2)
		when 4 #REG_WORD 32-bit number
			if val =~ /x/
				return val.hex.to_i
			else
				return val.to_i
			end
		when 5 #REG_DWORD_BIG_ENDIAN A 32-bit number in big-endian format.
			return val.unpack("N*") # TODO:  this is crap, just guessing
		when 6 #REG_LINK A null-terminated Unicode string that contains the target path of a
			#symbolic link created by calling the RegCreateKeyEx function w/ REG_OPTION_CREATE_LINK
			return val.to_s.rstrip # I wonder if unpack("A*").join would be better?
		when 7 #REG_MULTI_SZ
			return val.split(/\0/)
		else return nil
		end
	end

	def normalize_reg_data_type(type)
		#TODO: integrate with railgun's api manager to reduce duplication?
		return type if type.class == Fixnum
		return nil if not type =~ /^REG_/
		type = type.to_s.strip
		case type
		when /REG_NONE/
			return 0
		when /REG_SZ/
			return 1
		when /REG_EXPAND_SZ/
			return 2
		when /REG_BINARY/
			return 3
		when /REG_DWORD/
			return 4
		when /REG_DWORD_BIG_ENDIAN/
			return 5
		when /REG_LINK/
			return 6
		when /REG_MULTI_SZ/
			return 7
		else return nil
		end
	end

	# Ensures mode is sane, like what sc.exe wants to see, e.g. 2 or "AUTO_START" etc returns "auto"
	# If the second argument it true, integers are returned instead of strings  
	#
	def normalize_mode(mode,i=false)
		mode = mode.to_s # someone could theoretically pass in a 2 instead of "2"
		# accepted boot|system|auto|demand|disabled
		case mode
		when /(0|BOOT)/i
			mode = i ? 0 : 'boot' # mode is 'boot', unless i is true, then it's 0
		when /(1|SYSTEM)/i
			mode = i ? 1 : 'system'
		when /(2|AUTO)/i
			mode = i ? 2 : 'auto'
		when /(3|DEMAND|MANUAL)/i
			mode = i ? 3 : 'demand'
		when /(4|DISABLED)/i
			mode = i ? 4 : 'disabled'
		else
			mode = nil
		end
		return mode		
	end

	def normalize_stupid_win_hex(str)
		# str could be stuff like "fix", "0x0", "0x01", "0"
		return str if str.class == Fixnum # dumb, rules out any shenanigans
		return nil if str == ""
		if is_valid_hex?(str)
			# then convert this hex string to hex and then to int
			return str.hex.to_i
		elsif is_valid_int?(str)
			return str.to_i
		end
		# otherwise return this presumably straight up string
		return str
	end
	def is_valid_hex?(str)
		# NOTE: this will not trigger if vals not prefixed with "0x", looking at you service type..
		str =~ /^0x[a-fA-F0-9]*$/
	end
	def is_valid_int?(str)
		str =~ /^[0-9]+$/ # don't want "" to return 0, prefer nil
	end
end

end
end
end
