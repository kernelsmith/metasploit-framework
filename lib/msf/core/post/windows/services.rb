require 'msf/core/post/windows/registry'  # TODO:  Remove this dependency
require 'rex/post/meterpreter/extensions/stdapi/railgun/util.rb'

module Msf
class Post
module Windows

module WindowsServices

	# these symbols are used for hash keys and are scoped here to allow a consistent api
	SERVICE_PROCESS_STRUCT_NAMES = [:type,:state,:controls,:win32_exit_code,:service_exit_code,
		:checkpoint,:wait_hint,:pid,:flags]
	SERVICE_CONFIG_STRUCT_NAMES = [:service_name,:type,:start_type,:error_control,
		:binary_path_name,:load_order_group,:tag,:display_name,:dependencies,:service_start_name]

	include Msf::Post::Windows::CliParse
	
	@prefer_display_names = false
	def self.prefer_display_names
		@prefer_display_names
	end
	def self.prefer_display_names=(boo)
		@prefer_display_names = boo
	end
	
# The methods supported by the old API:
	# List methods:  service_list
	# Service action methods:  service_change_startup,service_create,service_start,service_stop,
	# 	service_delete
	# Service query methods:  service_info

# The methods to be supported by the new API
	# List methods:  service_list, service_list_running
	# Service query methods:  service_running?, service_get_config, service_get_status, 
	# 	service_get_display_name
	# Service action methods:  service_change_startup, service_create,service_delete,
	# 	service_start, service_stop
	# Deprecated:  service_info

	#
	# List all Windows Services present. Returns an Array containing the names (keynames)
	# of the services, whether they are running or not.
	#

	def service_list
		if session_has_services_depend?
			meterpreter_service_list
		else
			shell_service_list
		end
	end
	
	#
	# List all running Windows Services present. Returns an Array containing the names
	# (keynames) of the services.
	#
	
	def service_list_running
		if session_has_services_depend?
			meterpreter_service_list_running
		else
			shell_service_list_running
		end
	end
	
	#
	# Returns true if the given service is running
	#
	def service_running?(service_name)
		if session_has_services_depend?
			meterpreter_service_running?(service_name)
		else
			shell_service_running?(service_name)
		end
	end
	
	#
	# Changes a given service startup mode, name must be provided, mode defaults to auto.
	#
	# Mode is an int or string with either 2/auto, 3/manual or 4/disable etc for the
	# corresponding setting (see normalize_mode).
	#

	def service_change_startup(name,mode="auto")
		if session_has_services_depend?
			meterpreter_service_change_startup(name,mode)
		else
			shell_service_change_startup(name,mode)
		end
	end

	#
	# Create a service.  Returns nil if success
	#
	# It takes as values the service name as string, the display name as
	# string, the path of the executable on the host that will execute at
	# startup as string and the startup mode as an integer or string of:
	# 	2/auto for 		Auto
	# 	3/manual/demand	Manual
	# 	4/disable for 	Disable
	# See normalize_mode for details
	# Default is Auto.
	# TODO: convert args to take a hash so a variable number of options can be provided?
	#

	def service_create(name, display_name, executable_on_host, startup=2)
		if session_has_services_depend?
			meterpreter_service_create(name, display_name, executable_on_host,startup)
		else
			shell_service_create(name, display_name, executable_on_host,startup)
		end
	end
	
	#
	# Start a service.  Returns nil if success
	#
	
	def service_start(name)
		if session_has_services_depend?
			meterpreter_service_start(name)
		else
			shell_service_start(name)
		end
	end
	
	#
	# Stop a service.  Returns nil if success
	#
	
	def service_stop(name)
		if session_has_services_depend?
			meterpreter_service_stop(name)
		else
			shell_service_stop(name)
		end
	end
	
	#
	# Delete a service
	#
	# Delete a service by deleting the key in the registry (meterpreter) or sc delete <name>
	# Returns nil if success.
	#
	
	def service_delete(name)
		if session_has_services_depend?
			meterpreter_service_delete(name)
		else
			shell_service_delete(name)
		end
	end
	
	#
	# Get Windows Service config information. 
	#
	# Info returned stuffed into a hash with most service config info available 
	# Service name is case sensitive.
	#
	# Hash keys match the keys returned by sc.exe qc <service_name>, but downcased and symbolized
	# captured as SERVICE_CONFIG_STRUCT_NAMES
	# e.g returns {
	# :service_name => "winmgmt",
	# :type 		=> "20 WIN32_SHARE_PROCESS",
	# :start_type 	=> "2 AUTO_START",
	# <...>
	# :dependencies => "RPCSS,OTHER",
	# :service_start_name => "LocalSystem" }
	#
	def service_get_config(service_name)
		if session_has_services_depend?
			#TODO:  implement this
			return "not implemented yet"
			meterpreter_service_get_config(service_name)
		else
			shell_service_get_config(service_name)
		end
	end

	#
	# Get Windows Service extended status information. 
	#
	# Info returned stuffed into a hash with most service status info available 
	# Service name is case sensitive.
	#
	# Hash keys match the keys returned by sc.exe qc <service_name>, but downcased and symbolized
	# captured as SERVICE_PROCESS_STRUCT_NAMES
	# e.g returns {
	# :service_name => "winmgmt",
	# :type 		=> "20 WIN32_SHARE_PROCESS",
	# :state		=> "4 RUNNING, STOPPABLE,NOT_PAUSABLE"
	# <...>
    # :pid			=>	1084,
    # :flags		=>	nil }
	
	def service_get_status(service_name)
		if session_has_services_depend?
			meterpreter_service_get_status(service_name)
			# TODO:  meterp version needs to parse and return full state like "4 RUNNING,STOPPABLE"
		else
			shell_service_get_status(service_name)
		end
	end
	
	def service_get_display_name(service_name)
		if session_has_services_depend?
			meterpreter_service_get_display_name(service_name)
		else
			shell_service_get_display_name(service_name)
		end
	end
	
	#
	# Get Windows Service information. (To be deprecated)
	#
	# Information returned in a hash with display name, startup mode and
	# command executed by the service. Service name is case sensitive.  Hash
	# keys are Name, Start, Command and Credentials.
	# TODO:  Deprecate this in favor os service_get_config and service_query_ex

	def service_info(name,extended_info=false)
		if session_has_services_depend?
			meterpreter_service_info(name)
		else
			shell_service_info(name, extended_info)
		end
	end
	
protected

	##
	# Non-native Meterpreter windows service manipulation methods, i.e. shell or java meterp etc
	##
	def shell_service_list()
		services = []
		begin
			cmd = "cmd.exe /c sc query type= service state= all"
			results = session.shell_command_token_win32(cmd)
			if results =~ /SERVICE_NAME:/
				results.each_line do |line| 
					if line =~ /SERVICE_NAME:/
						h = win_parse_results(line)
						if prefer_display_names
							services << h[:display_name]
						else
							services << h[:service_name]
						end
					end 
				end
			elsif results =~ /(^Error:.*|FAILED.*:)/
				return nil
			elsif results =~ /SYNTAX:/
				# Syntax error
				raise Msf::Post::Windows::CliParse::ParseError.new(__method__,"Syntax error",nil,cmd)
			else
				raise Msf::Post::Windows::CliParse::ParseError.new(__method__,
				"Unparsable error:  #{results}",nil,cmd)
			end
		rescue Msf::Post::Windows::CliParse::ParseError => e
			print_error(e.to_s)
			return nil
		end
		return services
	end

	def shell_service_list_running()
		#SERVICE_NAME: Winmgmt
		#DISPLAY_NAME: Windows Management Instrumentation
      	# <...etc...>
		#
		services = []
		begin
			cmd = "cmd.exe /c sc query type= service"
			results = session.shell_command_token_win32(cmd)
			if results =~ /SERVICE_NAME:/
				results.each_line do |line| 
					if line =~ /SERVICE_NAME:/
						h = win_parse_results(line)
						if prefer_display_names
							services << h[:display_name]
						else
							services << h[:service_name]
						end
					end 
				end
			elsif results =~ /(^Error:.*|FAILED.*:)/
				return nil
			elsif results =~ /SYNTAX:/
				# Syntax error
				raise Msf::Post::Windows::CliParse::ParseError.new(__method__,"Syntax error",nil,cmd)
			else
				raise Msf::Post::Windows::CliParse::ParseError.new(__method__,
				"Unparsable error:  #{results}",nil,cmd)
			end
		rescue Msf::Post::Windows::CliParse::ParseError => e
			print_error(e.to_s)
			return nil
		end
		return services
	end

	def shell_service_running?(service_name)
		# TODO:  Accomodate if prefer_display_names ??
		running_services = shell_service_list_running
		return true if running_services.include?(service_name)
	end
	
	def shell_service_get_config(service_name)
		# TODO:  Accomodate if prefer_display_names ??
		service = {}
		begin
			cmd = "cmd.exe /c sc qc #{service_name.chomp}"
			results = session.shell_command_token_win32(cmd)
			if results =~ /SUCCESS/
				#[SC] QueryServiceConfig SUCCESS
				#
				#SERVICE_NAME: winmgmt
				#      TYPE          : 20  WIN32_SHARE_PROCESS
				#      START_TYPE      : 2  AUTO_START
				#      ERROR_CONTROL    : 0  IGNORE
				#      BINARY_PATH_NAME  : C:\Windows\system32\svchost.exe -k netsvcs
				#      <...>
				#      DISPLAY_NAME     : Windows Management Instrumentation
				#      DEPENDENCIES     : RPCSS
				#      		   : OTHER
				#      SERVICE_START_NAME : LocalSystem
				# 
				service = win_parse_results(results)
			elsif results =~ /(^Error:.*|FAILED.*:)/
				return nil
			elsif results =~ /SYNTAX:/
				# Syntax error
				raise Msf::Post::Windows::CliParse::ParseError.new(__method__,"Syntax error",nil,cmd)
			else
				raise Msf::Post::Windows::CliParse::ParseError.new(__method__,
				"Unparsable error:  #{results}",nil,cmd)
			end
		rescue Msf::Post::Windows::CliParse::ParseError => e
			print_error(e.to_s)
			return nil
		end
		return service
	end
	
	def shell_service_get_status(service_name)
		# TODO:  Accomodate if prefer_display_names ??
		service = {}
		begin
			cmd = "cmd.exe /c sc queryex #{name.chomp}"
			results = session.shell_command_token_win32(cmd)
			if results =~ /SERVICE_NAME/ # NOTE: you can't use /SUCCESS/ here
				#SERVICE_NAME: winmgmt
				#      TYPE          : 20  WIN32_SHARE_PROCESS
				#      STATE          : 4  RUNNING
				#                      (STOPPABLE,PAUSABLE,ACCEPTS_SHUTDOWN)
				#      WIN32_EXIT_CODE   : 0  (0x0)
				#      SERVICE_EXIT_CODE  : 0  (0x0)
				#      CHECKPOINT      : 0x0
				#      WAIT_HINT       : 0x0
				#      PID           : 1088
				#      FLAGS          :
				# 
				service = win_parse_results(results)
			elsif results =~ /(^Error:.*|FAILED.*:)/
				return nil
			elsif results =~ /SYNTAX:/
				# Syntax error
				raise Msf::Post::Windows::CliParse::ParseError.new(__method__,"Syntax error",nil,cmd)
			else
				raise Msf::Post::Windows::CliParse::ParseError.new(__method__,
				"Unparsable error:  #{results}",nil,cmd)
			end
		rescue Msf::Post::Windows::CliParse::ParseError => e
			print_error(e.to_s)
			return nil
		end
		return service
	end

	def shell_service_change_startup(name,mode)
		# TODO:  Accomodate if prefer_display_names ??
		begin
			mode = normalize_mode(mode)
			cmd = "cmd.exe /c sc config #{name} start= #{mode}"
			results = session.shell_command_token_win32(cmd)
			if results =~ /SUCCESS/
				return nil
			elsif results =~ /(^Error:.*|FAILED.*:)/
				eh = win_parse_error(results)
				raise Msf::Post::Windows::CliParse::ParseError.new(
					__method__,"Error changing startup mode #{name} to #{mode}:  #{eh[:error]}",
					eh[:errval],cmd) 
			elsif results =~ /SYNTAX:/
				# Syntax error
				raise Msf::Post::Windows::CliParse::ParseError.new(__method__,"Syntax error",nil,cmd)
			else
				raise Msf::Post::Windows::CliParse::ParseError.new(__method__,
				"Unparsable error:  #{results}",nil,cmd)
			end
		rescue Msf::Post::Windows::CliParse::ParseError => e
			print_error(e.to_s)
		end
	end

	def shell_service_create(name,display_name="Server Service",executable_on_host="",mode="auto")
		#  sc create [service name] [binPath= ] <option1> <option2>...
		begin
			mode = normalize_mode(mode)
			cmd = "cmd.exe /c sc create #{name} binPath= \"#{executable_on_host}\" " +
				"start= #{mode} DisplayName= \"#{display_name}\""
			results = session.shell_command_token_win32(cmd)
			if results =~ /SUCCESS/
				return nil
			elsif results =~ /(^Error:.*|FAILED.*:)/
				eh = win_parse_error(results)
				raise Msf::Post::Windows::CliParse::ParseError.new(
					__method__,"Error creating service #{name}:  #{eh[:error]}",eh[:errval],cmd)
			elsif results =~ /SYNTAX:/
				# Syntax error
				raise Msf::Post::Windows::CliParse::ParseError.new(__method__,"Syntax error",nil,cmd)
			else
				raise Msf::Post::Windows::CliParse::ParseError.new(__method__,
				"Unparsable error:  #{results}:  #{results}",nil,cmd)
			end
		rescue Msf::Post::Windows::CliParse::ParseError => e
			print_error(e.to_s)
		end
	end

	def shell_service_start(name)
		# TODO:  Accomodate if prefer_display_names ??
		begin
			cmd = "cmd.exe /c sc start #{name}"
			results = session.shell_command_token_win32(cmd)
			if results =~ /(SUCCESS|START_PENDING|RUNNING)/
				return nil
			elsif results =~ /(^Error:.*|FAILED.*:)/
				eh = win_parse_error(results)
				raise Msf::Post::Windows::CliParse::ParseError.new(
					__method__,"Error starting #{name}:  #{eh[:error]}",eh[:errval],cmd)
			elsif results =~ /SYNTAX:/
				# Syntax error
				raise Msf::Post::Windows::CliParse::ParseError.new(__method__,"Syntax error",nil,cmd)
			else
				raise Msf::Post::Windows::CliParse::ParseError.new(__method__,
				"Unparsable error:  #{results}",nil,cmd)
			end
		rescue Msf::Post::Windows::CliParse::ParseError => e
			print_error(e.to_s)
		end
	end

	def shell_service_stop(name)
		# TODO:  Accomodate if prefer_display_names ??
		begin
			cmd = "cmd.exe /c sc stop #{name}"
			results = session.shell_command_token_win32(cmd)
			if results =~ /SUCCESS|STOP_PENDING|STOPPED|/
				return nil
			elsif results =~ /(^Error:.*|FAILED.*:)/
				eh = win_parse_error(results)
				raise Msf::Post::Windows::CliParse::ParseError.new(
					__method__,"Error stopping service #{name}:  #{eh[:error]}",eh[:errval],cmd)
			elsif results =~ /SYNTAX:/
				# Syntax error
				raise Msf::Post::Windows::CliParse::ParseError.new(__method__,"Syntax error",nil,cmd)
			else
				raise Msf::Post::Windows::CliParse::ParseError.new(__method__,
				"Unparsable error:  #{results}",nil,cmd)
			end
		rescue Msf::Post::Windows::CliParse::ParseError => e
			print_error(e.to_s)
		end
	end

	def shell_service_delete(service_name)
		# TODO:  Accomodate if prefer_display_names ??
		begin
			cmd = "cmd.exe /c sc delete #{service_name}"
			results = session.shell_command_token_win32(cmd)
			if results =~ /SUCCESS/
				return nil
			elsif results =~ /(^Error:.*|FAILED.*:)/
				eh = win_parse_error(results)
				raise Msf::Post::Windows::CliParse::ParseError.new(__method__,
				"Error deleting service #{name}:  #{eh[:error]}",eh[:errval],cmd)
			elsif results =~ /SYNTAX:/
				# Syntax error
				raise Msf::Post::Windows::CliParse::ParseError.new(__method__,
				"Syntax error",nil,cmd)
			else
				raise Msf::Post::Windows::CliParse::ParseError.new(__method__,
				"Unparsable error:  #{results}",nil,cmd)
			end
		rescue Msf::Post::Windows::CliParse::ParseError => e
			print_error(e.to_s)
		end
	end
	
	def shell_service_get_display_name(service_name)
		begin
			cmd = "cmd.exe /c sc GetDisplayName #{service_name}"
			results = session.shell_command_token_win32(cmd)
			if results =~ /SUCCESS/
				# can't use cliparse's win_parse_results here as MS failed to keep consistent output
				# output looks like:  [SC] GetServiceDisplayName SUCCESS  Name = Windows Time
				return results.split(/= +/).last
			elsif results =~ /(^Error:.*|FAILED.*:)/
				eh = win_parse_error(results)
				raise Msf::Post::Windows::CliParse::ParseError.new(__method__,
				"Error getting display name for #{name}:  #{eh[:error]}",eh[:errval],cmd)
			elsif results =~ /SYNTAX:/
				# Syntax error
				raise Msf::Post::Windows::CliParse::ParseError.new(__method__,
				"Syntax error",nil,cmd)
			else
				raise Msf::Post::Windows::CliParse::ParseError.new(__method__,
				"Unparsable error:  #{results}",nil,cmd)
			end
		rescue Msf::Post::Windows::CliParse::ParseError => e
			print_error(e.to_s)
		end
	end

	def shell_service_info(name,extended_info=false)
		# TODO:  Deprecate this for get_config and query_ex
		# TODO:  If not deprecated, accomodate if prefer_display_names ??
		service = {}
		begin
			h = shell_service_get_config(name)
			return nil unless h
			if ! extended_info
				# this is here only for backwards compatibility with the original meterp version
				service['Name'] = h[:service_name]
				service['Startup'] = normalize_mode(h[:start_type])
				service['Command'] = h[:binary_path_name]
				service['Credentials'] = h[:service_start_name]
				return service
			else
				# this is alot more useful stuff, but not backward compatible
				return h
			end
		rescue Exception => e
			print_error(e.to_s)
			return nil
		end
		return nil
	end
	
	##
#---# Native Meterpreter-specific windows service manipulation methods
	##
	def meterpreter_service_list()
		arr_of_hashes = meterpreter_get_service_hashes(state=0x03, type=0x10)
		ret_array = []
		arr_of_hashes.each do |h|
			if prefer_display_names
				ret_array << h[:display_name]
			else
				ret_array << h[:service_name]
			end
		end
	end

	def meterpreter_service_list_running
		arr_of_hashes = meterpreter_get_service_hashes (state=0x01, type=0x10)
		ret_array = []
		arr_of_hashes.each do |h|
			if h:[state] =~ /4/
				if prefer_display_names
					ret_array << h[:display_name]
				else
					ret_array << h[:service_name]
				end
			end
		end
		return ret_array
	end
	
	def meterpreter_service_running?(service_name)
		# TODO:  Accomodate if prefer_display_names ??
		return true if meterpreter_service_get_status(service_name)[:state] =~ /4/
		# otherwise
		return false
	end
	
	# returns hash
	def meterpreter_service_get_status(service_name)
		# must be a service name
		rg = session.railgun
		rg.add_dll('advapi32') unless rg.get_dll('advapi32') # load dll if not loaded
		# define the function if not defined
		if ! rg.advapi32.functions['QueryServiceStatusEx']
			# MSDN
			#BOOL WINAPI QueryServiceStatusEx(
			#	__in       SC_HANDLE hService,
			#	__in       SC_STATUS_TYPE InfoLevel,
			#	__out_opt  LPBYTE lpBuffer,
			#	__in       DWORD cbBufSize,
			#	__out      LPDWORD pcbBytesNeeded
			#);
			rg.add_function('advapi32', 'QueryServiceStatusEx', 'BOOL',[
				['DWORD','hService',		'in'],
				['DWORD','InfoLevel',		'in'], # SC_STATUS_PROCESS_INFO, always 0
				['PBLOB','lpBuffer',		'out'],
				['DWORD','cbBufSize',		'in'],
				['PDWORD','pcBytesNeeded',	'out']
			])
		end
		# run the railgun query
		begin
			serv_handle,scum_handle = get_serv_handle(service_name,"SERVICE_get_status")
			#print_debug "Railgunning queryservicestatusEx"
			railhash = rg.advapi32.QueryServiceStatusEx(serv_handle,0,37,37,4)
			#print_debug "Railgun returned:  #{railhash.inspect}"
			if railhash["GetLastError"] == 0
				return parse_service_status_process_structure(railhash["lpBuffer"])
			else # there was an error, let's handle it
				err = railhash["GetLastError"]
				handle_railgun_error(err,__method__,"Error querying service status",rg,
				/^[ERROR_INVALID_|ERROR_ACCESS_|ERROR_INSUFFICIENT_|ERROR_SHUTDOWN_]/)
				# ^^^^ filter reverse error lookups (helps to look at msdn function return vals)
			end
		rescue Rex::Post::Meterpreter::RequestError => e
			print_error e.to_s
			return nil
		ensure
			rg.advapi32.CloseServiceHandle(scum_handle) if scum_handle
			rg.advapi32.CloseServiceHandle(serv_handle) if serv_handle
		end
	end

	def meterpreter_service_change_startup(name,mode)
		#TODO convert this to railgun, see service_start and _create etc
		servicekey = "HKLM\\SYSTEM\\CurrentControlSet\\Services\\#{name.chomp}"
		mode = normalize_mode(mode,true).to_s # the string version of the int, e.g. "2"
		begin
			registry_setvaldata(servicekey,'Start',mode,'REG_DWORD')
			return nil
		rescue::Exception => e
			print_error("Error changing startup mode.  #{e.to_s}")
		end
	end

	def meterpreter_service_create(name, display_name, executable_on_host,mode=2)
		mode = normalize_mode(mode,true)
		nil_handle,scum_handle = get_serv_handle(0,nil,"SC_MANAGER_CREATE_SERVICE")
		begin
			new_service = rg.advapi32.CreateServiceA(
				scum_handle,
				name,
				display_name,
				#"SERVICE_ALL_ACCESS", railgun doesn't recognize this
				0xF01FF,
				"SERVICE_WIN32_OWN_PROCESS",
				mode,
				0,
				executable_on_host,
				nil,nil,nil,nil,nil)
			err = new_service["GetLastError"]
			case err
			when 0 #success
				return nil
			else
				handle_railgun_error(err,__method__,"Error starting service",rg,
				/^[ERROR_INVALID_|ERROR_ACCESS_|ERROR_CIRCULAR_|ERROR_SERVICE_|ERROR_DUPLICATE_]/)
				# ^^^^ filter reverse error lookups (helps to look at msdn function return vals)
			end
		rescue Rex::Post::Meterpreter::RequestError => e
			print_error e.to_s
		ensure
			rg.advapi32.CloseServiceHandle(new_service["return"]) if new_service
			rg.advapi32.CloseServiceHandle(scum_handle) if scum_handle
		end
	end

	def meterpreter_service_start(service_name)
		rg = session.railgun
		begin
			serv_handle,scum_handle = get_serv_handle(service_name,"SERVICE_START")
			# railgun doesn't 'end
			railhash = rg.advapi32.StartServiceA(serv_handle,0,nil)
			if railhash["GetLastError"] == 0
				return nil
			else # there was an error, let's handle it
				err = railhash["GetLastError"]
				handle_railgun_error(err,__method__,"Error starting service",rg,
				/^[ERROR_INVALID_|ERROR_ACCESS_|ERROR_PATH_|ERROR_SERVICE_]/)
				# ^^^^ filter reverse error lookups (helps to look at msdn function return vals)
			end
		rescue Rex::Post::Meterpreter::RequestError => e
			print_error e.to_s
		ensure 
			rg.advapi32.CloseServiceHandle(serv_handle) if serv_handle
			rg.advapi32.CloseServiceHandle(scum_handle) if scum_handle
		end
	end

	def meterpreter_service_stop(service_name)
		#TODO:  create a meterpreter_service_control, and bounce this method to it
		rg = session.railgun
		begin
			serv_handle,scum_handle = get_serv_handle(service_name,"SERVICE_STOP")
			railhash = rg.advapi32.ControlService(serv_handle,"SERVICE_CONTROL_STOP",4)
			if railhash["GetLastError"] == 0
				return nil
			else # there was an error, let's handle it
				err = railhash["GetLastError"]
				handle_railgun_error(err,__method__,"Error stopping service",rg,
				/^[ERROR_INVALID_|ERROR_ACCESS_|ERROR_DEPENDENT_|ERROR_SHUTDOWN_|ERROR_SERVICE_]/)
				# ^^^^ filter reverse error lookups (helps to look at msdn function return vals)
			end
		rescue Rex::Post::Meterpreter::RequestError => e
			print_error e.to_s
		ensure 
			rg.advapi32.CloseServiceHandle(serv_handle) if serv_handle
			rg.advapi32.CloseServiceHandle(scum_handle) if scum_handle
		end
	end

	def meterpreter_service_delete(service_name)
		rg = session.railgun
		begin
			serv_handle,scum_handle = get_serv_handle(service_name,"DELETE")
			railhash = rg.advapi32.DeleteService(serv_handle)
			if railhash["GetLastError"] == 0
				return nil
			else # there was an error, let's handle it
				err = railhash["GetLastError"]
				handle_railgun_error(err,__method__,"Error deleting service",rg,
				/^[ERROR_INVALID_|ERROR_ACCESS_|ERROR_SERVICE_]/)
				# ^^^^ filter reverse error lookups (helps to look at msdn function return vals)
			end
		rescue Rex::Post::Meterpreter::RequestError => e
			print_error e.to_s
		ensure 
			rg.advapi32.CloseServiceHandle(serv_handle) if serv_handle
			rg.advapi32.CloseServiceHandle(scum_handle) if scum_handle
		end
	end
	def meterpreter_service_get_config(service_name)
	# http://msdn.microsoft.com/en-us/library/windows/desktop/ms684932(v=vs.85).aspx
	#	BOOL WINAPI QueryServiceConfig(
	#  		__in       SC_HANDLE hService,
	#  		__out_opt  LPQUERY_SERVICE_CONFIG lpServiceConfig,
	#  		__in       DWORD cbBufSize,
	#  		__out      LPDWORD pcbBytesNeeded
	#	);
	
	# http://msdn.microsoft.com/en-us/library/windows/desktop/ms684950(v=vs.85).aspx
#	typedef struct _QUERY_SERVICE_CONFIG {
#  		DWORD  dwServiceType;
#  		DWORD  dwStartType;
#  		DWORD  dwErrorControl;
#  		LPTSTR lpBinaryPathName;
#  		LPTSTR lpLoadOrderGroup;
#  		DWORD  dwTagId;
#  		LPTSTR lpDependencies;
#  		LPTSTR lpServiceStartName;
#  		LPTSTR lpDisplayName;
#	} QUERY_SERVICE_CONFIG, *LPQUERY_SERVICE_CONFIG;
	end

	def meterpreter_service_get_display_name(service_name)
		if ! rg.advapi32.functions['GetServiceDisplayNameA']
			#	BOOL WINAPI GetServiceDisplayName(
			#  __in       SC_HANDLE hSCManager,
			#  __in       LPCTSTR lpServiceName,
			#  __out_opt  LPTSTR lpDisplayName,
			#  __inout    LPDWORD lpcchBuffer
			#);
			rg.add_function('advapi32', 'GetServiceDisplayNameA', 'BOOL',[
				['DWORD','hService',		'in'],
				['LPTSTR','lpServiceName',	'in'],
				['LPTSTR','lpDisplayName',	'out'],
				['PDWORD','lpcchBuffer',	'out']
			])
		end
		rg = session.railgun
		begin
			# get a scum handle
			nil_handle,scum_handle = get_serv_handle(0,nil,"GENERIC_READ")
			railhash = rg.advapi32.GetServiceDisplayNameA(scum_handle,service_name,4,4)
			if railhash["GetLastError"] == 0
				return railhash["lpDisplayName"]
			else # there was an error, let's handle it
				err = railhash["GetLastError"]
				handle_railgun_error(err,__method__,"Error getting display name",rg)
				# ^^^^ filter reverse error lookups (helps to look at msdn function return vals)
			end
		rescue Rex::Post::Meterpreter::RequestError => e
			print_error e.to_s
		ensure 
			rg.advapi32.CloseServiceHandle(serv_handle) if serv_handle
			rg.advapi32.CloseServiceHandle(scum_handle) if scum_handle
		end
	end

	def meterpreter_service_info(service_name)
		#TODO:  deprecate for get_config
		h = meterpreter_service_get_config(service_name)
		begin
			service["Name"] = h[:display_name] # <-- will fail right now, no display_name
			service["Startup"] = normalize_mode(registry_getvaldata(servicekey,"Start").to_i)
			service["Command"] = registry_getvaldata(servicekey,"ImagePath").to_s
			service["Credentials"] = registry_getvaldata(servicekey,"ObjectName").to_s
		rescue Exception => e
			print_error("Error collecing service info.  #{e.to_s}")
			return nil
		end
		return service
	end

	##
#---# Helper methods
	##
	
	# Determines whether the session can use meterpreter services methods
	#
	def session_has_services_depend?
		begin
			return !!(session.sys.registry and session.railgun)
			##print_debug "using meterpreter version"
		rescue NoMethodError
			##print_debug "using SHELL version"
			return false
		end
	end

	# Ensures mode is sane, like what sc.exe wants to see, e.g. 2 or "AUTO_START" etc returns "auto"
	# If the second argument it true, integers are returned instead of strings  
	#
	def normalize_mode(mode,i=false)
		mode = mode.to_s # someone could theoretically pass in a 2 instead of "2"
		# accepted boot|system|auto|demand|disabled
		if mode =~ /(0|BOOT)/i
			mode = i ? 0 : 'boot' # mode is 'boot', unless i is true, then it's 0
		elsif mode =~ /(1|SYSTEM)/i
			mode = i ? 1 : 'system'
		elsif mode =~ /(2|AUTO)/i
			mode = i ? 2 : 'auto'
		elsif mode =~ /(3|DEMAND|MANUAL)/i
			mode = i ? 3 : 'demand'
		elsif mode =~ /(4|DISABLED)/i
			mode = i ? 4 : 'disabled'
		end
		return mode		
	end
	
	def handle_railgun_error(error_code, blame_method, message, railgun_instance, filter_regex=nil)
		err_name_array = railgun_instance.error_lookup(error_code,filter_regex)
		if not err_name_array.nil? and not err_name_array.empty?
			error_name = err_name_array.first
		else
			error_name = nil
		end
    	raise Rex::Post::Meterpreter::RequestError.new(blame_method,
    	"#{message}, Windows returned the following error:  #{error_name}(#{error_code})",error_code)
	end
	
	def get_serv_handle(s_name,serv_privs="SERVICE_INTERROGATE",scm_privs="SC_MANAGER_ENUMERATE_SERVICE")
		# s_name is normally a string, but if s_name is the value 0 then
		# a serv_handle will not be attempted, essentially only a scum_handle will be returned
		if not session_has_services_depend?
			raise Error.new "get_serv_handle only valid for meterpreter sessions"
		end
		rg = session.railgun
		begin
			# get the SCManager handle
			manag = rg.advapi32.OpenSCManagerA(nil,nil,scm_privs)
			scum_handle = manag["return"]
			err = manag["GetLastError"]
			if scum_handle == 0 #then OpenSCManagerA had a problem
				handle_railgun_error(err,__method__,"Error opening the SCManager",rg)
			else # move on to getting the service handle if requested
				return nil,scum_handle if s_name == 0 # only a scum_handle is requested
				servhandleret = rg.advapi32.OpenServiceA(scum_handle,s_name,serv_privs)
				serv_handle = servhandleret["return"]
				
				if(serv_handle == 0) # then OpenServiceA had a problem
					err = servhandleret["GetLastError"]
					handle_railgun_error(err, __method__,"Error opening service handle", rg,
					/^[ERROR_ACCESS_|ERROR_SERVICE_|ERROR_INVALID]/) #limit our error lookups
				end
				#print_debug "Returning:  #{serv_handle.to_s}, #{scum_handle.to_s}"
				return serv_handle,scum_handle
			end
		rescue Rex::Post::Meterpreter::RequestError => e
			print_error e.to_s
			rg.advapi32.CloseServiceHandle(scum_handle) if scum_handle
			rg.advapi32.CloseServiceHandle(serv_handle) if serv_handle
			return nil
		# we don't use ensure here cuz we don't want the handles to get closed if no error
		end
	end
	#
	# Return an array of hashes corresponding to the list of services of +state+ and +type+
	#  Hashes have :service_name, :display_name, and SERVICE_PROCESS_STRUCT_NAMES as keys
	#
	def meterpreter_get_service_hashes (state=0x03, type=0x10)
		# other choices for state: 
		# "SERVICE_STATE_ALL" = 0x03
		# "SERVICE_STATE_ACTIVE" = 0x01
		# "SERVICE_STATE_INACTIVE" = 0x02
		#TODO:  Railgun doesn't seem to know the above constants
		# other choices for type:
		# Driver = 0x0B, file system driver = 0x02, kernel driver = 0x01
		# service_win32 = 0x30, service_win32_own_process = 0x10, service_win32_share_process = 0x20
		
		# use railgun to make the service query
		rg = session.railgun
		# define the function if not defined
		if not rg.advapi32.functions['EnumServicesStatusExA']		
			# MSDN http://msdn.microsoft.com/en-us/library/windows/desktop/ms682640(v=vs.85).aspx
			#BOOL WINAPI EnumServicesStatusEx(
			#	__in 		 SC_HANDLE hSCManager,
			#	__in         SC_ENUM_TYPE InfoLevel,
			#	__in         DWORD dwServiceType,
			#	__in         DWORD dwServiceState,
			#	__out_opt    LPENUM_SERVICE_STATUS lpServices,
			#	__in         DWORD cbBufSize,
			#	__out        LPDWORD pcbBytesNeeded,
			#	__out        LPDWORD lpServicesReturned,
			#	__inout_opt  LPDWORD lpResumeHandle, [in, out, optional]
			#	__in_opt     LPCTSTR pszGroupName [in, optional]
			#);
			rg.add_function('advapi32', 'EnumServicesStatusExA', 'BOOL',[
				['DWORD','hSCManager',		'in'],
				['DWORD','InfoLevel',		'in'], # 0
				['DWORD','dwServiceType',	'in'], #SERVICE_WIN32
				['DWORD','dwServiceState',	'in'], #1, 2, or 3
				['PBLOB','lpServices',		'out'], 
				['DWORD','cbBufSize',		'in'],
				['PDWORD','pcBytesNeeded',	'out'],
				['PDWORD','lpServicesReturned','out'], # the number of svs returned
				['PDWORD','lpResumeHandle','inout'], # 0
				['PCHAR','pszGroupName', 'in'], # use nil, not "" unless you know what u doin (msdn)
			])
		end
		# run the railgun query
		begin
			# "SERVICE_get_status"
			nil_handle,scum_handle = get_serv_handle(
				0,"SC_MANAGER_ENUMERATE_SERVICE | SC_MANAGER_CONNECT")
			# ok, let's use the winapi to figure out just how big our buffer needs to be
			# note, there could be a "race" condition where the buffer size increases after we query
			# but this is about as good as we can do
			print_debug "Running EnumServicesStatusExA to get buf_size"
			# TODO:  Railgun doesn't know:  SERVICE_WIN32 = 0x30
			# check if it knows SERVICE_WIN32_OWN_PROCESS = 0x10
			railhash = rg.advapi32.EnumServicesStatusExA(scum_handle,0,type,state,4,0,4,4,4,nil)
			# passing in a buf size of 0 gives us the required buf size in pcBytesNeeded
			if not railhash["GetLastError"] == 0 #change this to if == 0xEA going forward
				#then this is good, this puts buf size in pcBytesNeeded
				buf_size = railhash["pcBytesNeeded"].to_i
				print_debug "Buffer size:  " + buf_size.to_s
			else # if no error, bad things
				raise Rex::Post::Meterpreter::RequestError.new(__method__,"Problem getting buffer size")
			end
			# now use that buf_size to make the real query
			# TODO:  railgun doesn't seem to know "SERVICE_WIN32" which is 0x30
			print_debug "Running EnumServicesStatusExA with buf_size of #{buf_size}"
			railhash = rg.advapi32.EnumServicesStatusExA(
				scum_handle,0,type,state,buf_size,buf_size,4,4,4,nil)
			# for now, let's just see this buffer boyyyyyy, try to parse it but...
			if railhash["GetLastError"] == 0
				#print_debug "Buffer:  " + railhash["lpServices"].inspect
				num_services_returned = railhash["lpServicesReturned"].to_i
				print_debug "Number of services:  " + num_services_returned.to_s
				parsed_arr = parse_enum_service_status_process_structure(
					railhash["lpServices"], num_services_returned )
				return parsed_arr
			else # there was an error, let's handle it
				err = railhash["GetLastError"]
				handle_railgun_error(err,__method__,"Error querying service status",rg,
				/^[ERROR_INVALID_|ERROR_ACCESS_|ERROR_INSUFFICIENT_|ERROR_SHUTDOWN_]/)
				# ^^^^ filter reverse error lookups (helps to look at msdn function return vals)
			end
		rescue Rex::Post::Meterpreter::RequestError => e
			print_error e.to_s
			return nil
		ensure
			rg.advapi32.CloseServiceHandle(scum_handle) if scum_handle
		end
	end
	#
	# Converts a hex string into hash representing a service_status_process_structure
	# with decimal windows constants.  hex_string normally comes from a PBLOB lpBuffer (Railgun)
	#
	def parse_service_status_process_structure(hex_string)
		#print_debug "parsing #{hex_string.inspect}"
		names = SERVICE_PROCESS_STRUCT_NAMES
		arr_of_arrs = names.zip(hex_string.unpack("V8"))
		hashish = Hash[*arr_of_arrs.flatten]
	end
	
	
	# Array of:
	# typedef struct _ENUM_SERVICE_STATUS_PROCESS {
  	# LPTSTR 	lpServiceName; non-const TCHAR str, TCHAR is wide char if unicode defined
  	# LPTSTR	lpDisplayName;
	# SERVICE_STATUS_PROCESS ServiceStatusProcess;
	# } ENUM_SERVICE_STATUS_PROCESS, *LPENUM_SERVICE_STATUS_PROCESS;

	#typedef struct _SERVICE_STATUS_PROCESS {
	#	DWORD dwServiceType;
	#	DWORD dwCurrentState;
	#	DWORD dwControlsAccepted;
	#	DWORD dwWin32ExitCode;
	#	DWORD dwServiceSpecificExitCode;
	#	DWORD dwCheckPoint;
	#	DWORD dwWaitHint;
	#	DWORD dwProcessId;
	#	DWORD dwServiceFlags;
	#}

	#
	# Converts a hex string into an array of hashes representing an
	# _ENUM_SERVICE_STATUS_PROCESS which is an array of _SERVICE_STATUS_PROCESS 
	# with decimal windows constants.  hex_string normally comes from a PBLOB lpBuffer (Railgun)
	#
	def parse_enum_service_status_process_structure(hex_string, num_items_in_array)
		# first, define the service status process data structure type
#		_SERVICE_STATUS_PROCESS = [
#				[:dwServiceType, :DWORD],
#				[:dwCurrentState, :DWORD],
#				[:dwControlsAccepted, :DWORD],
#				[:dwWin32ExitCode, :DWORD],
#				[:dwServiceSpecificExitCode, :DWORD],
#				[:dwCheckPoint, :DWORD],
#				[:dwWaitHint, :DWORD],
#				[:dwProcessId, :DWORD],
#				[:dwServiceFlags, :DWORD],
#		]
		_SERVICE_STATUS_PROCESS = []
		# we use SERVICE_PROCESS_STRUCT_NAMES as the keys so the api is consistent between shell/met
		SERVICE_PROCESS_STRUCT_NAMES.each do |key|
			_SERVICE_STATUS_PROCESS << [key, :DWORD]
		end
		_SERVICE_STATUS_PROCESS
		# now the enum service status process struct
#		_ENUM_SERVICE_STATUS_PROCESS = [
#				[:lpServiceName, :LPSTR],
#				[:lpDisplayName, :LPSTR],
#				[:serviceStatusProcess, _SERVICE_STATUS_PROCESS],
#		]
		_ENUM_SERVICE_STATUS_PROCESS = [
				[:service_name, :LPSTR],
				[:display_name, :LPSTR],
				[:serviceStatusProcess, _SERVICE_STATUS_PROCESS],
		]
		rg = session.railgun
		data = rg.util.read_array(_ENUM_SERVICE_STATUS_PROCESS,num_items_in_array, 0, hex_string)
		off = num_items_in_array*44
		len = hex_string.length - off
		arr_of_strings = ghetto_string_parse(hex_string, len, off, :UCHAR)
		arr_of_names = arr_of_strings.select {|item| item if item.length > 1}
		# if arr_of_names, display Names are first, and Service Names are second
		# merge the correct names into the data array
		# also, un-nest the nested hash which has the key :serviceStatusProcess
		data_with_names_unnested = []
		data.each_with_index do |val,idx|
			val[:display_name] = arr_of_names[idx*2]
			val[:service_name] = arr_of_names[idx*2+1]
			data_with_names << val.delete(:serviceStatusProcess).merge(val)# un-nest
		end
		return data_with_names_unnested
	end
	#
	# Parses a String of PBLOB for Ascii strings, returns array of strings
	#
	def ghetto_string_parse(buffer,length,offset,type=:UCHAR)
		rg = session.railgun
		arr_of_chars = rg.util.read_array(type, length, offset, buffer)
		stacker=""
		ret_array = []
		arr_of_chars.each do |item|
			if item == "\x00"
				ret_array << stacker if stacker
				stacker=""
			else
				stacker << item
			end
		end
		return ret_array
	end
	
	#
	# Converts a hash into human readable service_status_process_structure info
	# as a hash adding human readable commentary.  ssps_hash normally comes
	# from parse_service_status_process_structure
	#
	def beautify_service_status_process_structure(ssps_hash,railgun_instance)
		rg = railgun_instance
		rg.const("SERVICE_get_status") # returns 4
		# TODO:  Is there any easy way to do this?
	end
	
	def parse_and_pretty_service_status_process_structure(hex_string,railgun_instance)
		h = parse_and_pretty_service_status_process_structure(hex_string)
		beautify_service_status_process_structure(h,railgun_instance)
	end
end

end
end
end
