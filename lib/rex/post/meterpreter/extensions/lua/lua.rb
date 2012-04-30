#!/usr/bin/env ruby

require 'rex/post/meterpreter/extensions/lua/tlv'

module Rex
module Post
module Meterpreter
module Extensions
module Lua

###
#
# This meterpreter extension injects a lua interpreter on the target so you can run
# arbitrarily complex lua scripts.  Eventually this will be possible in win & *nix
#
###
class Lua < Extension


	def initialize(client)
		super(client, 'lua')

		client.register_extension_aliases(
			[
				{ 
					'name' => 'lua',
					'ext'  => self
				},
			])
	end


	def run_script(script)
		request = Packet.create_request('run_script')
		request.add_tlv(TLV_TYPE_LUA_RUN_SCRIPT, script)

		response = client.send_request(request)
		
		return {
			'results' => response.get_tlv_value(TLV_TYPE_LUA_RESULTS),
		}
	end

	def load_lua_extension(lua_ext)
		request = Packet.create_request('lua_ext')
		request.add_tlv(TLV_TYPE_LUA_LOAD_EXTENSION, lua_ext)
		response = client.send_request(request)

		response.get_tlv_value(TLV_TYPE_LUA_LOAD_RESPONSE)
	end

#	def incognito_add_user(host, username, password)
#		request = Packet.create_request('incognito_add_user')
#		request.add_tlv(TLV_TYPE_INCOGNITO_USERNAME, username)
#		request.add_tlv(TLV_TYPE_INCOGNITO_PASSWORD, password)
#		request.add_tlv(TLV_TYPE_INCOGNITO_SERVERNAME, host)
#		response = client.send_request(request)

#		response.get_tlv_value(TLV_TYPE_INCOGNITO_GENERIC_RESPONSE)
#	end

#	def incognito_add_group_user(host, groupname, username)
#		request = Packet.create_request('incognito_add_group_user')
#		request.add_tlv(TLV_TYPE_INCOGNITO_USERNAME, username)
#		request.add_tlv(TLV_TYPE_INCOGNITO_GROUPNAME, groupname)
#		request.add_tlv(TLV_TYPE_INCOGNITO_SERVERNAME, host)
#		response = client.send_request(request)

#		response.get_tlv_value(TLV_TYPE_INCOGNITO_GENERIC_RESPONSE)
#	end

#	def incognito_add_localgroup_user(host, groupname, username)
#		request = Packet.create_request('incognito_add_localgroup_user')
#		request.add_tlv(TLV_TYPE_INCOGNITO_USERNAME, username)
#		request.add_tlv(TLV_TYPE_INCOGNITO_GROUPNAME, groupname)
#		request.add_tlv(TLV_TYPE_INCOGNITO_SERVERNAME, host)
#		response = client.send_request(request)

#		response.get_tlv_value(TLV_TYPE_INCOGNITO_GENERIC_RESPONSE)
#	end

#	def incognito_snarf_hashes(host)
#		request = Packet.create_request('incognito_snarf_hashes')
#		request.add_tlv(TLV_TYPE_INCOGNITO_SERVERNAME, host)
#		response = client.send_request(request)

#		return true
#	end

end

end; end; end; end; end
