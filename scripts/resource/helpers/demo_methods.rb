# include this file to gain a buch of methods helpful to writing more elaborate resource files
# like when using a resource file for a demo or automation etc
# $Author: kernelsmith

# this is what I do at the top of my resource file:  
#<ruby>
	#  Assuming this file is located at <install_dir>/scripts/resource/helpers/demo_methods.rb
	#resource_dir = File.join(Msf::Config.install_root, "scripts", "resource")
	#require File.join(resource_dir, "helpers","demo_methods")
	#  and this is a good spot to run stuff like rc_auto_lhost and rc_auto_handler etc
#</ruby>

	#`'~.~'^\_/^*-..-*`'~.~'^\_/^*-..-*`'~.~'^\_/^*-..-*`'~.~'^\_/^*-.
	#                                                                 \
	# Helper methods for demo'ing and general resource visual coolness >
	#                                                                 /
	#_.~*~._/^\_,-''-._.~*~._/^\_,-''-._.~*~._/^\_,-''-._.~*~._/^\_,-'

	#
	# Method for simple pause, press any key to continue, optional timeout +tout+
	# optional +verbose+ for slightly more status information output
	# the displayed message can be specified with +msg+
	# use array of regular expression strings +continue_regexps+ to specify what
	# keystrokes will release the pause and continue
	#
	def rc_pause(tout = 0, verbose = true, msg = nil, continue_regexps = ['.*'])
		# tout of 0 means wait forever
		# popular vals for continue_regexps
		# ['.*']		=>  any key
		# ['Y', 'y']	=>  Y or y
		# ['Y|y']		=>  Y or y
		require 'timeout'
		msg = 'PAUSED - any key to continue' unless msg
		continue_words =  [continue_words] if continue_words.class = String
		print_good(msg) if verbose
		begin
			Timeout::timeout(tout) do
				freeme = true
				while freeme
					typed = gets()
					continue_words.each do |re|
						if typed.chomp =~ Regexp.new(re)
							freeme = false 
							break
						end
					end
				end
			end
		rescue Timeout::Error
			print_status "The pause timed out" if verbose
		end
		print_good('Continuing...') if verbose
	end

	#
	# this method helps you perform a clear screen, as a part of and during a resource script run,
	# esp when other methods of doing so fail
	#

	# The default +rc_clear_string+ should work for Linux BASH shells (tested with BT5r1 in BASH),
	# you might have to pass a custom string (described below) for your OS & shell.  
	# To do so do the following:
	# run %x{clear} (or cls in Windows) in irb (in your intented OS & shell)
	# pass the string returned by that command to this method
	# If you're running msf in Cygwin, on Windows, make sure to run the irb command in Cygwin (untested)
	# If you are running MSF in Windows, run %x{cls} in irb and pass that string

	def rc_clear(rc_clear_string = "\e[H\e[2J")
		$stdout.print rc_clear_string
	end

	#
	# Method to let us do variable timing delays
	#
	def rc_var_delay(dmin=20,dmax=300)
		wtime = rand(dmax-dmin) + dmin
		print_good "Delaying for #{wtime} seconds"
		while wtime > 0
			printf("\r%d",wtime)
			select(nil, nil, nil, 1)
			wtime -= 1
		end
		print_line
		print_good "Continuing..."
	end

	#
	# Method for a simple delay
	#
	def rc_delay(wtime=5,verbose=true)
		print_good "Delaying for #{wtime} seconds" if verbose
		while wtime > 0
			printf("\r%d",wtime) if verbose
			select(nil, nil, nil, 1)
			wtime -= 1
		end
		print_line
		print_good "Continuing..." if verbose
	end

	#`'~.~'^\_/^*-..-*`'~.~'^\_/^*-..-*`'~.~'^\_/^*-..-*`'~.~'^\_/^*-.
	#                                                                 \
	# Helper methods for running modules more easily & automatically   >
	#                                                                 /
	#_.~*~._/^\_,-''-._.~*~._/^\_,-''-._.~*~._/^\_,-''-._.~*~._/^\_,-'

	#
	# this method helps automatically set LHOST
	#

	# NOTE: if you don't want LHOST to be your "default route" interface, you should call this
	#     with target net changed to something in the network attached to the interface you do want

	# target_net is important if you have multiple interfaces and you want a specific one.
	# The interface LHOST will be set to is chosen by what interface is used to route to target_net
	# whether or not target_net exists is irrelevant, but if it doesn't LHOST will become
	# whatever interface is connected to the default route, in that case target_net could be any
	# publicly routable IP, or just nil
	# if you are using virtual interfaces etc, you might want target_net to be one of your vmnets
	# like if your "host-only" network is 192.168.170.1/24 you could: rc_auto_lhost("192.168.170.1")
	# and no matter what your ip actually is on that network, this will figure it out

	def rc_auto_lhost(target_network="5.5.5.5")
		# in case someone accidentally passes in a cidr range:
		target_network = target_network.split('/').first if target_network =~ /\//
		# in case someone passes in a network range, which most likely won't work well but...
		# and this just picks the first ip in the range provided
		if target_network =~ /-/
			tmp = []
			target_octets = target_network.split('.')
			target_octets.each do |octet|
				tmp << octet.split('-').first
			end
			target_network = tmp.join('.')
		end
		print_status "Using target network #{target_network}"
		my_interface = Rex::Socket.source_address(target_network)
		print_status "Setting LHOST to #{my_interface}"
		run_single("set LHOST #{my_interface}")
		#run_single("setg LHOST #{my_interface}") #optional
	end

	#
	# this method just sets up a persistent multi/handler, for reverse connections on +lport+
	# using the payload specified by +payload+
	# defaults are 4444 and "windows/meterpreter/reverse_tcp" respectively
	#
	def rc_auto_handler(lport=4444, payload="windows/meterpreter/reverse_tcp")
		run_single("use multi/handler")
		run_single("set PAYLOAD #{payload}")
		run_single("set LPORT #{lport}")
		run_single("set ExitOnSession false")
		run_single("exploit -j -z")
	end

	def rc_run_on_all_sessions(mod=nil)
		# if a mod was specified, use that instead of current (not recommended)
		run_single("use $mod") if mod # if mod specified, switch to it first
		# keep in mind you'll have to make sure your datastore for that mod is correct already

		framework.sessions.each_key do |session|
			run_single("set SESSION #{session}")
			print_status("Running #{active_module.fullname} against session #{session}")
			run_single("run")
			select(nil, nil, nil, 1) # sleep 1
		end
	end
