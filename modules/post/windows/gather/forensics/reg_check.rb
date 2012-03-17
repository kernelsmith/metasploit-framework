##
# ## This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##

require 'msf/core'
require 'msf/core/post/common'
require 'msf/core/post/windows/priv'

class Metasploit3 < Msf::Post

	# TODO:  Better support for keys/vals with spaces in the name like HKLM/Vmware Tools

	include Msf::Post::Common
	include Msf::Post::Windows::Registry
	include Msf::Auxiliary::Report

	def initialize(info={})
		super( update_info( info,
				'Name' => 'Registry Check',
				'Description' => %q{ This module searches for registry artifacts, presumably malware related.},
				'License' => MSF_LICENSE,
				'Author' => [ 'Marcus J. Carey <mjc[at]threatagent.com>', 'kernelsmith'],
				'Version' => '$Revision$',
				'Platform' => [ 'windows' ],
				'SessionTypes' => [ 'meterpreter','shell' ],
				'References' => []
		))
		register_options(
			[
				OptString.new('REG_KEYS', [false, 'Registry keys for which to look, comma separated', '']),
				OptString.new('REG_VALS', [false, 'Registry values for which to look, comma separated', '']),
				OptBool.new('USE_DB', [true, 'Whether to store results in the database', false]),
				OptBool.new('HALT', [true, 'Stop if a key or value is found',false]),
				#OptBool.new('DEBUG', [false, 'Print debug info', true]),
			], self.class)
	end

	def run
		key_artifacts = []
		val_artfiacts = []
		key_artifacts = datastore['REG_KEYS'].split(',') if datastore['REG_KEYS'].respond_to?("split")
		val_artifacts = datastore['REG_VALS'].split(',') if datastore['REG_VALS'].respond_to?("split")
		if (key_artifacts.empty? and val_artifacts.empty?)
				# then we can't run
				print_error "REG_KEY and REG_VAL can't both be empty"
				return
		end
		print_deb ("Keys:  #{key_artifacts.to_s}")
		print_deb ("Vals:  #{val_artifacts.to_s}")

		if not key_artifacts.empty?
		print_deb "Checking for registry keys"
		matches = 0
		#begin
			key_artifacts.each do |artifact|
				path, query = parse_path(artifact)
				print_status("Searching registry on #{sysinfo['Computer']} for #{path}\\#{query}")
				has = registry_enumkeys(path) || []
				print_deb "Keys enumerated:  #{has.to_s}"
				if not has.empty? and has.include?(query)
					matches += 1
					found_msg = "Registry artifact found:  #{path}\\#{query}"
					print_warning(found_msg)
					if datastore['USE_DB']
						report_vuln(
							:host			=>	target_host,
							:name			=>	self.fullname,
							:info			=>	found_msg,
							:refs			=>	self.references,
							:exploited_at	=>	Time.now.utc
							)
					end
				end
				if datastore['HALT'] and matches > 0
					print_status "Match found, halting (HALT is set to true)"
					return true
				end
			end
		#rescue;	end
		end

		if not val_artifacts.empty?
		print_deb "Checking for registry values"
		matches = 0
		#begin
			val_artifacts.each do |artifact|
				path, query = parse_path(artifact)
				print_status("Searching registry on #{sysinfo['Computer']} for #{path}\\#{query}")
				has = registry_enumvals(path) || []
				print_deb "Values enumerated:  #{has.to_s}"
				if not has.empty? and has.include?(query)
					matches += 1
					found_msg = "Registry artifact found:  #{path}\\#{query}"
					print_warning(found_msg)
					if datastore['USE_DB']
						report_vuln(
							:host			=>	target_host,
							:name			=>	self.fullname,
							:info			=>	found_msg,
							:refs			=>	self.references,
							:exploited_at	=>	Time.now.utc
							)
					end
				end
				if datastore['HALT'] and matches > 0
					print_status "Match found, halting (HALT is set to true)"
					return true
				end
			end
		#rescue;	end
		end

	end
	protected
	#
	# split KEYHOME/KEYPATH/KEY into KEYHOME/KEYPATH and KEY
	#
	def parse_path(artifact)
		parts = artifact.split("\\")
		query = parts[-1]
		parts.pop
		path = parts.join("\\")
		return path, query
	end

	#
	# Our own little warning message printer
	#
	def print_warning(msg='')
		print_line("%bld%red[warning]%clr #{msg}")
	end
	#
	# Yeay debug
	#
	def print_deb(msg='')
		print_line("%bld%mag[debug]%clr #{msg}") if datastore['VERBOSE']
	end
end
