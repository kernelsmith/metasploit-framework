#
# by kernelsmith (kernelsmith+\x40+kernelsmith+\.com)
#

require 'msf/core'
require 'rex'
# TODO:  change this back to require 'msf/core/post/windows/services' 
load 'msf/core/post/windows/services.rb'

class Metasploit3 < Msf::Post

	include Msf::Post::Windows::WindowsServices

	def initialize(info={})
		super( update_info( info,
				'Name'          => 'services_post_testing',
				'Description'   => %q{ This module will test windows services methods within a shell},
				'License'       => MSF_LICENSE,
				'Author'        => [ 'kernelsmith'],
				'Version'       => '$Revision: 11663 $',
				'Platform'      => [ 'windows' ],
				'SessionTypes'  => [ 'shell' ]
			))
		register_options(
			[
				OptBool.new("VERBOSE" , [true, "Verbose test, shows service status after each test",
				false]),
				OptString.new("QSERVICE" , [true, "Service (keyname) to query", "winmgmt"]),
				OptString.new("NSERVICE" , [true, "New Service (keyname) to create/del", "testes"]),
				OptString.new("SSERVICE" , [true, "Service (keyname) to be stopped then started",
				"W32Time"]),
				OptString.new("MODE" , [true, "Mode to use for startup/create tests", "demand"]),
				OptString.new("DNAME" , [true, "Display name used for create test",
				"Cool display name"]),
				OptString.new("BINPATH" , [true, "Binary path for create test", 
				"C:\\WINDOWS\\system32\\svchost.exe -k netsvcs"]),
			], self.class)

	end

	def run
		begin

		blab = datastore['VERBOSE']
		print_status("Running against session #{datastore["SESSION"]}")
		print_status("Session type is #{session.type}")
		print_status("Verbosity is set to #{blab.to_s}")
		print_status("Don't be surprised to see some errors as the script is faster")
		print_line("than the windows SCM, just make sure the errors are sane.  You can")
		print_line("set VERBOSE to true to see more details")
# The methods to be supported by the new API
	# List methods:  service_list, service_list_running
	# Service query methods:  service_running?, service_get_config, service_get_status, 
	# 	service_get_display_name
	# Service action methods:  service_change_startup, service_create,service_delete,
	# 	service_start, service_stop
	# Deprecated:  service_info

		#  LIST METHODS
		print_status()
		print_status("TESTING service_query_status on servicename: #{datastore["QSERVICE"]}")
		results = service_query_status(datastore['QSERVICE'])
		print_status("RESULTS: #{results.class} #{results.pretty_inspect}")

		print_status()
		print_status("TESTING service_list")
		results = service_list
		print_status("RESULTS: #{results.class} \n#{results.pretty_inspect}")

		#  SERVICE QUERY METHODS
		print_status()
		print_status("TESTING service_list_running")
		results = service_list_running
		print_status("RESULTS: #{results.class} \n#{results.pretty_inspect}")

		print_status "TESTING service_running?(#{datastore['QSERVICE']})"
		results = service_running?(datastore['QSERVICE'])
		print_status("RESULTS: #{results.class} #{results.pretty_inspect}")

		print_status()
		print_status("TESTING service_get_config on servicename: #{datastore["QSERVICE"]}")
		results = service_get_config(datastore['QSERVICE'])
		print_status("RESULTS: #{results.class} #{results.pretty_inspect}")

		print_status()
		print_status("TESTING service_get_status on servicename: #{datastore["QSERVICE"]}")
		results = service_get_status(datastore['QSERVICE'])
		print_status("RESULTS: #{results.class} #{results.pretty_inspect}")

		print_status()
		print_status("TESTING service_get_display_name on servicename: #{datastore["QSERVICE"]}")
		results = service_get_display_name(datastore['QSERVICE'])
		print_status("RESULTS: #{results.class} #{results.pretty_inspect}")

		#  SERVICE ACTION METHODS
		print_status()
		print_status("TESTING service_change_startup on servicename: #{datastore['QSERVICE']} " +
					"to #{datastore['MODE']}")
		results = service_change_startup(datastore['QSERVICE'],datastore['MODE'])
		print_status("RESULTS (Expecting nil on success): #{results.class} #{results.pretty_inspect}")
		print_status("Current status of this service " + 
					"#{service_query_ex(datastore['QSERVICE']).pretty_inspect}") if blab

		print_status()
		print_status("TESTING service_create on servicename: #{datastore['NSERVICE']} using\n" +
					"display_name: #{datastore['DNAME']}, executable_on_host: " + 
					"#{datastore['BINPATH']}, and startupmode: #{datastore['MODE']}")
		results = service_create(datastore['NSERVICE'],datastore['DNAME'],datastore['BINPATH'],datastore['MODE'])
		print_status("RESULTS (Expecting nil on success): #{results.class} #{results.pretty_inspect}")
		print_status("Current status of this service " + 
					"#{service_query_ex(datastore['QSERVICE']).pretty_inspect}") if blab

		print_status()
		print_status("TESTING service_stop on servicename: #{datastore['SSERVICE']}")
		print_status("Returns nil on success, otherwise error (like if the service is already stopped)")
		results = service_stop(datastore['SSERVICE'])
		print_status("RESULTS (Expecting nil on success): #{results.class} #{results.pretty_inspect}")
		print_status("Current status of this service " + 
					"#{service_query_ex(datastore['SSERVICE']).pretty_inspect}") if blab
		print_status("Sleeping to give the service a chance to report itself as stopped")
		select(nil, nil, nil, 4) # give service time to report as stopped, reduces false negatives

		print_status()
		print_status("TESTING service_start on servicename: #{datastore['SSERVICE']}")
		print_status("Returns nil on success, otherwise error (like if the service is already running)")
		results = service_start(datastore['SSERVICE'])
		print_status("RESULTS (Expecting nil on success): #{results.class} #{results.pretty_inspect}")
		print_status("Current status of this service " + 
					"#{service_query_ex(datastore['SSERVICE']).pretty_inspect}") if blab

		print_status()
		print_status("TESTING service_delete on servicename: #{datastore['NSERVICE']}")
		results = service_delete(datastore['NSERVICE'])
		print_status("RESULTS: #{results.class} #{results.pretty_inspect}")
		print_status("Current status of this service " + 
					"#{service_query_ex(datastore['QSERVICE']).pretty_inspect}") if blab
		
		#  DEPRECATED METHODS
		print_status()
		print_status("TESTING service_info on servicename: #{datastore["QSERVICE"]}")
		results = service_info(datastore['QSERVICE'])
		print_status("RESULTS: #{results.class} #{results.pretty_inspect}")
		print_status()
		print_status("Testing complete.")
		rescue NotImplementedError => e
			print_status "Not implemented yet:  #{e.to_s}"
		end # end rescue
	end # end run`
end # end class
