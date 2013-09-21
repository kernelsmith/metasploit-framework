#rip_msdn_to_railgun
# e.g. http://msdn.microsoft.com/en-us/library/windows/desktop/aa385125(v=vs.85).aspx

require 'nokogiri'
require 'open-uri'

#
# Handle CLI arguments
#
url = nil
source = nil
additional = nil
if ARGV.length == 1
	source = ARGV[0]
elsif ARGV.length == 2
	source = ARGV[0]
	additional = ARGV[1] =~ /^\s*all\s*$/i ? -1 : ARGV[1].to_i
	# adjust additional to get desired result later
	additional -= 1 if additional >= 1 and not additional == -1
else
	# "InternetOpen" => "http://msdn.microsoft.com/en-us/library/windows/desktop/aa385096%28v=vs.85%29.aspx"
	puts "Usage: #{$0} source [num_additional|all]"
	puts
	puts "source should be a url or a local html file containing msdn documentation for the method to be parsed"
	puts "optionally, provide the number of additional functions to parse (default's to 0) or 'all' for entire dll"
	exit 1
end


class MsdnMethod
	# necessary if we ever pull this class def out of this file
	# require 'nokogiri'
	# require 'open-uri'

	include Comparable

	attr_reader :source, :description, :nokodoc, :dll_name, :yard_factory, :param_infos, :return_desc, :reqs
	attr_reader :c_args, :c_ret_type, :c_name, :c_code # c_args are really railgun args ATM.
	attr_reader :ruby_args, :ruby_ret_type, :ruby_name, :ruby_code, :ruby_yard_tags
	attr_reader :railgun_args, :railgun_ret_type, :railgun_name, :railgun_code 

	# various constants we'll need to reference
	INDENT = "\t"
	DESCRIPTION_XPATH = "div[@id='mainSection']"
	DLL_NAME_XPATH = "//div[@id='page']//div[@id='body']//div[@id='leftNav']//div[@id='tocnav']//div[@class='toclevel1']"
	ALL_FXNS_XPATH = "//div[@id='page']//div[@id='body']//div[@id='leftNav']//div[@id='tocnav']//div[@class='toclevel2']"
	CODE_SNIP_CONTAINER_XPATH = "//div[@class='codeSnippetContainer']" # e.g. id="code-snippet-1"
	CODE_SNIP_CONTAINER_TABS_XPATH = "//div[@class='codeSnippetContainerTabs']"
	CODE_SNIP_CONTAINER_TAB_SINGLE_XPATH = "//div[@class='codeSnippetContainerTabSingle']" # e.g. text=C++
	CODE_SNIP_CONTAINER_CODE_XPATH = "//div[@class='codeSnippetContainerCode']" # the code itself
	MAIN_SECTION_XPATH = "//div[@id='mainSection']" # all the info after the code snippet

	C_STRUCTS_TO_RAILGUN = {
		'ret' => {
					#'bool'     => 'BOOL',
					#'BOOL'     => 'BOOL',
					#'Bool'     => 'BOOL',
					#'BOOLAPI'  => 'BOOL', # I have no idea what BOOLAPI is.
					# I got sick of all the bool variants and just used a regex b4 calling in  here.
					'handle'   => 'DWORD',
					'HANDLE'   => 'DWORD',
					'void'     => 'VOID',
					'VOID'     => 'VOID',
				},
		'in'  => { # NOTES:  LP = Pointer, C = Const, STR = String, W = Wide or Unicode
					# T = W if unicode is def, else regular, so TCHAR = WCHAR if unicode, else TCHAR = CHAR
					# Likewise, TSTR = WSTR if unicode, else TSTR = STR.
					# See http://www.codeproject.com/Articles/2995/The-Complete-Guide-to-C-Strings-Part-I-Win32-Chara
					# out params are always PBLOB's if they are pointer indicated like *so? or start with p?
					'HANDLE'   => 'DWORD',
					'LPCSTR'   => 'PCHAR', # Constant String
					'PWSTR'    => 'PWCHAR',
					'PBYTE'    => 'DWORD', # not sure what else to do w/pbyte
					'LPCTSTR'  => {'A' => 'PCHAR', 'W' => 'PWCHAR'}, # Constant TCHAR String (wide char or char dep on unicode)
					'LPTSTR'   => {'A' => 'PCHAR', 'W' => 'PWCHAR'},  # Regular  TCHAR String (wide char or char dep on unicode)
					'DWORD'    => 'DWORD',
					'LPDWORD'  => 'PDWORD',
					'PVALENT'  => 'PBLOB',
					'LPVOID'   => 'PBLOB',
					'PVOID'    => 'PBLOB',
					'PSECURITY_DESCRIPTOR' => 'PBLOB',
					'PGENERIC_MAPPING'     => 'PBLOB',
					'GUID'     => 'PBLOB', # if thing is *thing
					'BOOLEAN'  => 'BOOL',
					'PSID'     => 'LPVOID',
					'DWORD_PTR' => 'PDWORD',
					'FILETIME' => 'QWORD', # not sure if QWORD is actually supported or not
				},
		'out' => {
					# out params are always PBLOB's if they are pointer indicated like *so? or start with p?
					'PBLOB'    => 'PBLOB',
					'PSECURITY_DESCRIPTOR' => 'PBLOB', # if thing is *thing
					'PSID'     => 'PBLOB',
					'LPDWORD'  => 'PBLOB',
					# String-buffers that are OUT-only use a Fixnum describing the buffer size (including the null)--railgun_manual.pdf
					'LPTSTR'   => 'DWORD',
					'LPCSTR'   => 'DWORD',
					'LPCTSTR'  => 'DWORD',
					'LPWSTR'   => 'DWORD',
					'LPCWSTR'  => 'DWORD',
					'FILETIME' => 'QWORD', # not sure if QWORD is actually supported or not
						# typedef struct _FILETIME {
						#   DWORD dwLowDateTime;
						#   DWORD dwHighDateTime;
						# } FILETIME, *PFILETIME;
				},
		'inout' => {
					'HANDLE'   => 'DWORD',
					# should these also be handled like 'out' params, or 'in'?
					'LPCSTR'   => 'PCHAR', # Constant String
					'LPCTSTR'  => {'A' => 'PCHAR', 'W' => 'PWCHAR'}, # Constant TCHAR String (wide char or char dep on unicode)
					'LPTSTR'   => {'A' => 'PCHAR', 'W' => 'PWCHAR'},  # Regular  TCHAR String (wide char or char dep on unicode)
					'DWORD'    => 'DWORD',
					'LPDWORD'  => 'PDWORD',
					'PVALENT'  => 'PBLOB',
					'LPVOID'   => 'PBLOB',
					'PVOID'    => 'PBLOB',
					'PSECURITY_DESCRIPTOR' => 'PBLOB',
					'PGENERIC_MAPPING'     => 'PBLOB',
					'GUID'     => 'PBLOB', # if thing is *thing
					'BOOLEAN'  => 'BOOL',
					'PSID'     => 'LPVOID',
					'DWORD_PTR' => 'PDWORD',
				},
		'unk' => Hash.new("UNK")
	}

	RAILGUN_TO_YARD = {
		'BOOL'     => 'Bool',
		'DWORD'    => 'Fixnum',
		'VOID'     => 'Void',
		'PCHAR'    => 'String',
		'PWCHAR'   => 'String', # Should this be some other kind of string?
		'PDWORD'   => 'Fixnum', # ?? @TODO, confirm these w/railgun manual and/or testing
		'PBLOB'    => 'String',
		'PBLOB'    => 'PBLOB', # if thing is *thing
		'LPVOID'   => 'Void',
		'UNK'      => 'Unknown'
	}

	def self.remove_artifact(str)
		#puts "Cleaning:\n#{str}"
		s = str.force_encoding("ASCII-8BIT")
		s.gsub!(/^\s*$/,'')
		s.gsub!(/\P{ASCII}/, ' ') # nuke all non-ascii chars for now (esp 0xA0 and 0xC2 etc)
		s.squeeze!(" ")
		s.strip!
	end

	def self.commentify(str)
		# we use the lines method in case there are embedded newlines
		accum = ''
		str.lines do |line|
			accum += line =~ /^ *#/ ? "#{line}\n" : "# #{line}\n"
		end
		accum
	end

	def initialize(page)
		#puts "Creating nokogiri doc for #{page}..."
		# +page+ should be either a local file to read, or a url to scrape, or anything else Nokogiri::HTML(open()) can handle
		# http://msdn.microsoft.com/en-us/library/windows/desktop/aa384247(v=vs.85).aspx
		@nokodoc = Nokogiri::HTML(open(page))
		puts "Done."
		@source = page
		@yard_factory = YardTagFactory.new
	end

	def parse
		@dll_name = nokodoc.xpath(DLL_NAME_XPATH).text.strip.split(/\s/).first.downcase
		all_code_snippet_containers = nokodoc.xpath(CODE_SNIP_CONTAINER_XPATH)
		# until forced to do something fancier, we only parse the first code sample we encounter
		@c_code = get_code_from_nodeset(all_code_snippet_containers)
		return nil if @c_code.nil? or @c_code.empty? # some urls just display "This function is not supported"
		# @TODO:  we only support cpp parsing at the moment, maybe add C parsing some day
		@c_name, @c_ret_type, @c_args = analyze_cpp_code(@c_code)
		#puts "Got #{@c_name}, #{@c_ret_type}, #{@c_args.inspect}"
		@railgun_name = @c_name # identical
		#puts "Converting c method name to ruby method name"
		@ruby_name = rubify_name(@c_name)
		if @c_ret_type =~ /^bool/i
			# let's just nip all the numerous bool variants in the bud
			@railgun_ret_type = "BOOL"
		else
			@railgun_ret_type = C_STRUCTS_TO_RAILGUN['ret'][@c_ret_type] || "UNK"
		end
		@railgun_args = @c_args.map do |arg|
			arg.map {|a| a.gsub('*','')}
		end # remove any *'s
		@railgun_code = format_railgun_code(@railgun_name, @railgun_ret_type, @railgun_args)
		@ruby_args = []
		@c_args.each do |arg|
			#puts "Converting this c_arg:#{arg} to a ruby_arg"
			if not arg[1] =~ /[A-Z]+/ # if no capital letters found
				@ruby_args << rubify_name(arg[1]) # then send the entire name to be rubified
			else
				@ruby_args << rubify_name(arg[1].split(/^[a-z]+/).last) # drop lead low case ltrs first
			end
		end
		main_section = nokodoc.xpath(MAIN_SECTION_XPATH)
		return unless main_section # we couldn't find any other info to look at
		parse_main_section(main_section)
		ret_type_is_bool = @c_ret_type =~ /^bool/i ? true : false
		@ruby_code = rubify_code(@c_name, @ruby_name, @ruby_args, ret_type_is_bool)
		# YARD
		@ruby_yard_tags = yard_factory.garden(self)
		true
	end

	def header(type)
		hdr = "[*]  #{type} Code:\n"
		hdr += "---------------------------------------------------\n"
		hdr += self.send("#{type.downcase}_code".to_sym)
		hdr += "\n"
	end

	def display
		puts header("C")
		puts
		puts header("Railgun")
		puts
		puts header("Ruby")
	end

	def ruby_yard_tags_as_comments
		if ruby_yard_tags and not ruby_yard_tags.empty?
			ruby_yard_tags.collect {|y| y.to_comment}
		else
			["# "]
		end
	end

	def ruby_yard_tags_comment_block
		self.ruby_yard_tags_as_comments.join("\n")
	end

	def get_remaining_dll_function_urls
		all_functions_ns = nokodoc.xpath(ALL_FXNS_XPATH)
		all_function_urls = []
		all_functions_ns.each do |f|
			next_uri = f.xpath("a").first.attributes["href"].value
			all_function_urls << {:name => f.text.strip, :url => next_uri =~ /msdn/ ? next_uri : "http://msdn.microsoft.com#{next_uri}"}
		end
		all_function_urls
	end

	def get_dll_dry_helper_function
%q~#
# This method helps DRY out our code and provides basic error handling and messaging.
# It only returns the "return" part of the hash returned by railgun, unless there is an error
# @example run_dll_function(:wininet, :InternetOpen, nil, "my ua string", "INTERNET_OPEN_TYPE_DIRECT", nil, nil, 0)
# @param [Symbol] DLL name as a Symbol
# @param [Symbol] C Function name as a Symbol
# @param [String, nil] Custom error message to use instead of dyanmically generated message
# @todo finish this yard doc
# @param Variable number of additional args as needed
# @return varies depending on the C-function that is called
def run_dll_function(dll_as_sym, function_name_as_sym, custom_error_msg = nil, *function_args)
	args = [function_name_as_sym]
	args += function_args
	results = session.railgun.send(dll_as_sym).send(args * ",") # use this array format to avoid extra comma when args initially empty
	err = results["GetLastError"]
	if not err == 0
		err_code = results['GetLastError']
		error_msg = custom_error_msg || "Error running #{dll_as_sym.to_s}.dll function.  #{function_name_as_sym.to_s} error code: #{err_code}\n"
		error_msg += "This WinAPI error may mean:  #{lookup_error(err_code, /^ERROR_/)}"
		# @TODO; see if we can add to this error regex, look at msdn for wininet fxns, might be ERROR_INTERNET_* etc
		raise RuntimeError.new(error_msg)
	else
		results["return"]
	end
end
private :run_dll_function
~
	end

	def <=>(other)
		self.c_name <=> other.c_name
	end

	private

	def cc(str)
		MsdnMethod.commentify(str)
	end

	def rubify_name(cname)
		tmp = cname.gsub(/::/, '/')
		tmp = tmp.gsub(/([A-Z]+)([A-Z][a-z])/,'\1_\2')
		tmp = tmp.gsub(/([a-z\d])([A-Z])/,'\1_\2')
		# '*' from pointers are handled here
		tmp.gsub('*','').tr("-", "_").downcase
	end

	def rubify_code(c_method_name, ruby_method_name, ruby_arguments, bool = false)
		res = ""
		arr = []
		if ruby_arguments.length > 3
			res += cc("README & DELETE ME")
			res += cc("There are quite a few arguments so an opts hash was added.  To clean")
			res += cc("up the API, you should review it and adjust as needed.  You may want")
			res += cc("to consider regrouping args for: clarity, so args that are usually")
			res += cc("left at default values, or are optional, or always a specific value,")
			res += cc("etc, are put in the opts hash.  Or, you may want to get rid of the")
			res += cc("opts hash entirely.")
			first_three = ruby_arguments[0..2]
			opts_args = ruby_arguments[3..-1]
			first_three << "opts = {}"
			res += "def _#{ruby_method_name}(#{first_three.join(', ')})\n"
			res += "#{INDENT}defaults = {  # defaults for args in opts hash\n"
			opts_args.each do |arg|
				res += "#{INDENT}#{INDENT}:#{arg} => #{arg}_default # CHANGEME\n"
			end
			res += "#{INDENT}}\n\n"
			res += "# #{INDENT}Merge in defaults. This approach allows caller to safely pass in a nil\n"
			res += "#{INDENT}opts = defaults.merge(opts)\n"
			first_three.pop
			arr = [":"+dll_name, ":"+c_method_name] + first_three
			res += "\n#{INDENT}# Any arg validation can go here\n\n"
			res += "#{INDENT}ret = run_dll_function(#{arr.join(", ")},\n"
			opts_args.each {|arg| res += "#{INDENT}#{INDENT}opts[:#{arg}],\n"}
			res += "#{INDENT})\n"
		else
			res += "def _#{ruby_method_name}(#{ruby_arguments.join(', ')})\n"
			res += "\n#{INDENT}# Any arg validation can go here\n\n" if ruby_arguments.length > 0
			arr = [":"+dll_name, ":"+c_method_name] + ruby_arguments
			res += "#{INDENT}"
			res += "ret = " unless bool # don't add this if ret is BOOL cuz prob won't need
			res += "run_dll_function(#{arr.join(", ")})\n"
		end
		res += "\n#{INDENT}# Additional code goes here\n\n"
		res += "end\n"
	end

	def get_code_from_nodeset(nodeset, start_index = 0, style = /C\+\+/)
		nodeset.each_with_index do |node,idx|
			next if idx < start_index
			# get all the tables in current snippet node
			tables = node.xpath(CODE_SNIP_CONTAINER_TABS_XPATH)
			#puts "#{tables}.length table nodes"
			# grab the code example text if it's the correct style example
			tables.each do |table_node|
				ts = table_node.xpath(CODE_SNIP_CONTAINER_TAB_SINGLE_XPATH)
				#puts "#{ts.length} ts_nodes"
				ts.each do |ts_node|
					t = ts_node.text
					if t and t =~ style
						# then this is our guy
						code_containers = ts_node.xpath(CODE_SNIP_CONTAINER_CODE_XPATH)
						#puts "#{code_containers.length} code_containers"
						# for now, we assume there is only one of these (not a bad assumption)
						the_code = code_containers[0].text
						return MsdnMethod.remove_artifact(the_code)
					end
				end
			end
		end
		return nil
	end

	def get_c_ret_type_and_func_name(line)
		#puts "Determining return type and function name from:\n#{line}"
		parts = line.split(/\s+/) # always returns an array, even an empty one

		c_ret_type = "UNK"
		c_func_name = "Unknown"
		unless parts.empty?
			c_ret_type = parts[0] =~ /^H/ ? "HANDLE" : parts[0] || "UNK"
			c_func_name = parts[1].sub(/\($/,'')
			# if func_name still has () in it, it's probably a one-line (void) deal like
			# http://msdn.microsoft.com/en-us/library/windows/desktop/aa383938(v=vs.85).aspx
			if c_func_name =~ /\([A-Za-z]*\)/
				c_func_name = c_func_name.split(/\(/).first
			end
		end
		return [c_ret_type, c_func_name]
	end

	def convert_in_param(cpp_type, name, unicode = false)
		if cpp_type == "unsigned long"
			# Basic Rule (in):  If type is "unsigned long" and name starts w/ *, it's a PDWORD
			if name =~ /^\*/
				interim_type = "LPDWORD"
			# Basic Rule (in):  If type is "unsigned long" and name starts w/ dw, it's a DWORD
			elsif name =~ /^dw/
				interim_type = "DWORD"
			end
		# Basic Rule (in):  If it starts w/"H", prolly a handle so DWORD
		elsif cpp_type =~ /^H/ # ghetto, will have false pos
			interim_type = "HANDLE"
		# Basic Rule (in):  If it starts w/"LP", prolly a ptr so PDWORD
		elsif cpp_type =~ /^LP/ # ghetto, will have false pos
			interim_type = "LPDWORD" # will become PDWORD
		# Basic Rule (in):  If none of above, rely on the hash
		else
			interim_type = cpp_type
		end
		rg_type = C_STRUCTS_TO_RAILGUN['in'][interim_type]
		if rg_type.class == Hash
			rg_type = unicode ? rg_type["W"] : rg_type["A"]
		end
		rg_type
	end

	def convert_out_param(cpp_type, name, unicode = false)
		# Basic Rule (out):  If it starts w/"P" & name starts w/ * prolly a pointer to struct, aka PBLOB
		if cpp_type =~ /^P/ and name =~ /^\*/
			interim_type = "LPDWORD"
		elsif cpp_type == "unsigned long"
			# Basic Rule (out):  If type is "unsigned long" and name starts w/ *, it's a PBLOB
			if name =~ /^\*/
				interim_type = "LPDWORD"
			# Basic Rule (out):  If type is "unsigned long" and name starts w/ dw, it's a DWORD
			elsif name =~ /^dw/
				interim_type = "DWORD"
			end
		# Basic Rule (out):  params are always PBLOB's if they are pointers indicated like *so
		# ghetto, might have false pos, we'll see
		elsif name =~ /^\*/
			interim_type = "PBLOB"
		# Basic Rule (out):  If none of above, rely on the hash
		else
			interim_type = cpp_type
		end
		rg_type = C_STRUCTS_TO_RAILGUN['out'][interim_type]
		if rg_type.class == Hash
			rg_type = unicode ? rg_type["W"] : rg_type["A"]
		end
		rg_type
	end

	def convert_inout_param(cpp_type, name, unicode = false)
		# treat as an 'in' param for now
		convert_in_param(cpp_type, name, unicode)
	end

	def get_param(line, unicode = false)
		#puts "Line is:  #{line}"
		parts = line.split(/\s+/)
		if parts.length == 3
			direction = normalize_param_direction(parts[0])
			cpp_type = parts[1]
			name = parts[2].sub(/,$/,'')
		elsif parts.length == 4
			# assume it has a 2-word type like "unsigned long"
			# e.g. http://msdn.microsoft.com/en-us/library/windows/desktop/aa384688(v=vs.85).aspx
			direction = normalize_param_direction(parts[0])
			cpp_type = parts[1,2].join(" ")
			name = parts[3].sub(/,$/,'')		
		else
			# we can probably trust the direction
			direction = normalize_param_direction(parts[0])
			# type and name are ???
			cpp_type = "UNK"
			name = "unknown"
		end
		case direction
		when 'in'
			rg_type = convert_in_param(cpp_type, name, unicode)
		when 'out'
			rg_type = convert_out_param(cpp_type, name, unicode)
		when 'inout'
			rg_type = convert_inout_param(cpp_type, name, unicode)
		else
			rg_type = "UNK"
		end
		rg_type ||= "UNK"
		return [rg_type, name, direction]
	end

	def analyze_c_code(c_code)
		raise Exception.new("parsing code documented with C-style syntax is not currently supported")
	end

	def analyze_cpp_code(cpp_code)
		#puts "Analyzing this code: #{cpp_code}"

		# BOOL InternetCheckConnection(
		#   _In_  LPCTSTR lpszUrl,
		#   _In_  DWORD dwFlags,
		#   _In_  DWORD dwReserved
		# );
		####################
		# ["PBLOB","lpsaAddress","in"],
		# ["DWORD","dwAddressLength","in"],
		# ["PBLOB","lpProtocolInfo","in"],
		# ["PCHAR","lpszAddressString","inout"],
		ret_type = "UNK"
		func_name = "Unknown"
		params = []

		cpp_code.lines do |line|
			next if line =~ /^\s*$/ or line =~ /^\s*\);/ # blank or last line
			line.strip!
			#puts "Analyzing line: #{line}"
			line.sub!("WINAPI ",'') # sometimes you get this WINAPI thing like in
			# http://msdn.microsoft.com/en-us/library/windows/desktop/aa384688(v=vs.85).aspx
			# It defines the call type as WINAPI which is the windows default anyways
			#puts "Checking regex against:#{line}"
			if line =~ /^[A-Z]+[a-z]*\s+[A-Z]+[a-z]+.*\([A-Za-z);]*$/ # should probably just use /\(/
				# this is the first line, we need to grab the ret type & name
				ret_type, func_name = get_c_ret_type_and_func_name(line)
			else
				# this is a regular param line
				params << get_param(line)
			end
		end
		return func_name, ret_type, params
	end

	def format_railgun_code(rg_method_name, rg_ret_type, rg_parameters = [])
		res = "#{INDENT}#{INDENT}dll.add_function(\'#{rg_method_name}\', \'#{rg_ret_type}\', [\n"
		rg_parameters.each do |p|
			res += "#{INDENT}#{INDENT}#{INDENT}[#{p.map {|x| "\'#{x}\'"}.join(", ")}],\n"
		end
		res += "#{INDENT}#{INDENT}])\n"
	end

	def normalize_param_direction(cpp_code_dir)
		# @todo: what about _in_out_?
		case cpp_code_dir
		when /_inout_/i
			res = 'inout'
		when /(_in_|_Reserved_)/i
			res = 'in'
		when /_out_/i
			res = 'out'
		else
			res = 'unk'
		end
		return res
	end

	def parse_main_section(ms_nodeset)
		node = ms_nodeset.first
		#node.children.each {|e| puts e.text if e.name == "p"} #if e.text == "Parameters"}
		ns = node.children
		paragraphs = ns.select {|child| child.name == "p"}
		indx = 0
		@description = paragraphs[indx]
		@description = @description.text.strip.gsub(/\n/,'') if @description
		# @TODO:  Good enuf for now, we could also pull remarks and notes etc with
		# various h's and p's etc
		# n = paragraphs[1]
		# if n and n.text =~ /The function has no parameters/i
		# 	indx += 2 if not n # typical when the function has no parameters
		# else
		# 	indx += 1
		# end
		# @ret = paragraphs[indx]
		# @ret = @ret.text.strip if @ret
		# //div[@id='mainSection']//p[@class='note'] # this is where the amplifying note lives
		# puts "desc = #{@description.to_s}"
		# puts "ret = #{@ret.to_s}"
		ns.each_with_index do |elem, idx|
			case elem.text.strip
			when "Parameters"
				# gets [[name, descript],]
				@param_infos = parse_params_ns(ns.at(idx+2))
			when "Return value"
				# gets retval text
				@return_desc = parse_retval_ns(ns.at(idx+2))
			when "Remarks"
				# just skip this for now
				# parse_rems_ns(ns.at(idx+2))
			when "Requirements"
				# gets [[type, value],]
				@reqs = parse_reqs_ns(ns.at(idx+2))
				break # no reason to keep parsing
			end
		end
	end

	def parse_params_ns(nodeset)
		#inform "Looking for parameters in #{nodeset.to_s}"
		descripts = []
		names = []
		# someday could use something like if node.href add tag "@see #{node.href}"
		nodeset.children.each do |node|
			#puts "node is:#{node.to_s}"
			if node.name == "dt"
				#puts "Child:dt text:#{node.text.strip}"
				names << node.text.strip
			elsif node.name == "dd"
				#puts "Child:dd text:#{node.text.strip}"
				# We take the first sentence only to hopefully avoid getting sued.
				descripts << node.text.strip.split(/\./).first.gsub(/\n/,'')
			end
		end
		#names.each_with_index {|name,idx| puts("name:#{name}, descript:#{descripts[idx]}")}
		names.zip(descripts)
	end

	def parse_retval_ns(nodeset)
		txt = nodeset.text
		txt.strip.gsub(/\n/,' ') if txt
	end

	def parse_rems_ns(nodeset)
		# it's not worth parsing this and would probably get us sued.
		#puts "Found remarks nodeset"
		#puts nodeset.children
	end

	def parse_reqs_ns(nodeset)
		keys = []
		values = []
		#puts nodeset.children
		nodeset.children.each do |node|
			if node.name == "tr"
				node.children.each do |trnode|
					if trnode.name == "th"
						keys << trnode.text.strip
					elsif trnode.name == "td"
						values << MsdnMethod.remove_artifact(trnode.text.strip)
					end
				end
			end
		end
		#keys.each_with_index {|key,idx| puts("#{key}:#{values[idx]}")}
		keys.zip(values)
	end

end # MsdnMethod

class YardTag
	attr_accessor :tag, :description # @todo
	attr_reader :arg_name, :arg_type
	
	def initialize(tag = "@param", arg_type = "String", arg_name, description)
		tag = tag.to_s.strip.downcase
		@tag = tag =~  /^@[a-z]{3,}$/ ? tag : "@#{tag}"
		arg_type = arg_type.to_s.strip.capitalize
		@arg_type = arg_type =~ /^\[[A-Z][a-z]{2,}\]$/ ? arg_type : "[#{arg_type}]"
		@arg_name = arg_name
		@description = description.gsub(/^This parameter /, "Parameter ")
		#@name = arg_name # might not be needed at all, tbd
	end
	# Use this for an opts hash
	# @param [Hash] opts the options to create a message with.
	# @option opts [String] :subject The subject
	# @option opts [String] :from ('nobody') From address

	def to_s
		if tag.to_s == "@option"
			# this may not suffice, we'll see
			"#{tag.to_s} #{arg_type.to_s} :#{arg_name} #{description.to_s}"
		elsif tag.to_s == "@return"
			"#{tag.to_s} #{arg_type.to_s} #{description.to_s}"
		else
			"#{tag.to_s} #{arg_type.to_s} #{arg_name} #{description.to_s}"
		end
	end

	def to_comment
		"# #{self.to_s}"
	end

end # YardTag

# @example factory = YardTagFactory.new; factory.source = an_msdn_method; tags = factory.garden
# @example factory = YardTagFactory.new(c_code).new; tags = factory.garden;
# @example factory ||= YardTagFactory.new; factory.yard = more_c_code; tags = factory.garden
# @example factory = YardTagFactory.new; tags = factory.garden(c_code)
class YardTagFactory
	attr_accessor :yard, :default_tag, :default_description, :source

	def initialize(default_tag = "@param", default_description = "description TBD")
		@default_tag = default_tag
		@default_description = default_description
	end

	def translate(*rg_formatted_arg)
		# some of these are a bit redundant, but we include them for readability
		type, name, direction = rg_formatted_arg
		case direction
		when "in"
			type = case type
			when /^[L]?P/ # [L]PDWORD etc, pointers basically, also PBLOB
				"Fixnum"
			when /[A-Z]?WORD$/ # WORD, DWORD, QWORD, yeah so basically DWORD
				"Fixnum"
			when /CHAR/
				"String"
			when /VOID/
				"Nil"
			else
				"Unknown"
			end
		when /out/ # out or inout
			type = case type
			when /^[L]?P/ # [L]PDWORD etc, pointers basically, also PBLOB
				"Fixnum"
			when /[A-Z]?WORD$/ # WORD, DWORD, QWORD, yeah so basically DWORD
				"Fixnum"
			else
				"Unknown"
			end
		when "ret"
			#dword, void, bool
			type = case type
			when /[A-Z]?WORD$/ # WORD, DWORD, QWORD, yeah so basically DWORD
				"Fixnum"
			when /BOOL/
				"Boolean"
			when /VOID/
				"Nil"
			else
				"Unknown"
			end
		#when "inout" # for now, this is treat the same as 'out'
			#
		else
			#barf?
		end
		name = rubify_name(name)
		return [type, name]
	end
	# support c_code &&/|| args + ret_type?
		# dll.add_function('InternetTimeToSystemTime', 'BOOL', [
		# 	['PDWORD', 'lpszTime', 'in'],
		# 	['UNK', '*pst', 'out'],
		# 	['DWORD', 'dwReserved', 'in'],
		# ])

	# Turn a C-like name into a ruby-friendly name
	def rubify_name(cname)
		tmp = cname.gsub(/::/, '/') # replace :: with /
		tmp = tmp.gsub('*', '') # replace * with nothing
		if tmp =~ /[A-Z]/ # if there are any capital letters
			tmp = tmp.gsub(/([A-Z]+)([A-Z][a-z])/,'\1_\2') # replace
			tmp = tmp.gsub(/([a-z\d])([A-Z])/,'\1_\2') # replace
		end
		tmp.tr("-", "_").downcase # in case a "*" makes it this far
	end

	def garden(src) # (rg_code = @yard)
		#
		# @TODO:  Need Description down here
		#
		#inform "Gardening a:#{src.class.to_s}"
		desc = default_description
		if src.class == MsdnMethod
			#inform "Getting the rg code from the msdn method"
			rg_code = src.railgun_code
			#inform "rg code is:\n#{rg_code}"
		elsif src.respond_to?(:to_s)
			rg_code = src.to_s
		end
		plants = []
		ret_type = 'BOOL'
		# we assume it's well formatted c/cpp code
		param_ctr = 0
		rg_code.lines do |line|
			#puts "processing the line:#{line}"
			parts = line.split(',')
			next if line =~ /^\s*$/
			if line =~ /\(/
				# then consider it the first line
				ret_type = parts[1].gsub("'","") # BOOL etc
				#puts "we think we found a 'first line' for #{line}"
				type, name = translate(ret_type, "return", "ret")
				desc = src.class == MsdnMethod ? src.return_desc.split('.').first.gsub(/\n/,'') : "returns a #{type}"
				plants << YardTag.new('@return', type, "return", desc)
			elsif line =~ /\[.+\]/
				#puts "Found param line"
				# it's a param line
				type = parts[0].gsub("'","").sub("[","").strip # PDWORD etc
				name = parts[1].gsub("'","").strip # lpszTime etc
				dir =  parts[2].gsub("'","").sub("]","").strip # in/out etc
				type, name = translate(type, name, dir)
				#
				# @TODO:  need description, but also need to handle the opts = {} case
				#inform "Param infos are:\n#{src.param_infos}"
				desc = default_description
				if src.class == MsdnMethod
					pi = src.param_infos
					#inform "PI is #{pi.to_s}"
					if pi
						a = pi[param_ctr]
						if a and not a.empty?
							desc = a[1]
						end
					end
				end
				param_ctr += 1 # this ghetto, we're assuming params_info and args are synched

				#inform "Creating new yard tag with:#{default_tag}, #{type}, #{name}, #{desc}"
				plants << YardTag.new(default_tag, type, name, desc)
			end
		end
		plants # give me all the created YardTag objects
	end

end # YardTagFactory

# def get_method_name(page)
# 	# uses the page title
# 	t = page.title
# 	if t
# 		t = t.split(/\s/)[0]
# 	else
# 		t = nil
# 	end
# 	return t
# end

def inform(msg = nil)
	msg.respond_to?(:to_s) ? puts("[*] #{msg.to_s}") : puts()
end

inform "Parsing #{source}"
orig_msdn_method = MsdnMethod.new(source)
orig_msdn_method.parse
msdn_methods = [orig_msdn_method]
if additional
	inform "Enumerating related functions..."
	remaining_function_urls = orig_msdn_method.get_remaining_dll_function_urls
	#puts all_function_urls.inspect
	inform "Done.  Parsing enumerated functions..."
	urls_to_parse = remaining_function_urls[0..additional]
	urls_to_parse.each do |h|
		#puts "Passing #{a.inspect} to parser"
		msdn_method = MsdnMethod.new(h[:url])
		inform "Parsing #{h[:url]}"
		msdn_method.parse
		msdn_methods << msdn_method
	end
end
# sort was broken, but I think it's fixed now and NO
#msdn_methods.sort!
# prep to display w/code grouped together by type/lang
c_disp, rg_disp, ruby_disp, yard_disp = [],[],[],[]
msdn_methods.each do |m|
	c_disp << m.c_code
	rg_disp << m.railgun_code
	total_ruby_disp = "#\n"
	# sometimes the description comes back w/embedded newlines so we need to add the leading # to all
	if m.description and not m.description.empty?
		total_ruby_disp += MsdnMethod.commentify(m.description)
	else
		total_ruby_disp += MsdnMethod.commentify "No description found"
	end
	total_ruby_disp += MsdnMethod.commentify "@see #{m.source} #{m.c_name}\n" if m.c_name # don't think this would ever not be
	total_ruby_disp += "#{m.ruby_yard_tags_comment_block}\n#\n#{m.ruby_code}" if (m.ruby_yard_tags_comment_block and m.ruby_code)
	ruby_disp << total_ruby_disp
end
# Final display
inform "Results:"
inform
# inform "C/C++ Code:"
# puts "---------------------------------------------------"
# c_disp.each {|str_block| puts str_block;puts} # str_block is a block of code string
puts
inform "Railgun Code:"
puts "---------------------------------------------------"
rg_disp.each {|str_block| puts str_block;puts} 
puts
inform "Ruby Code:"
puts "---------------------------------------------------"
ruby_disp.each {|str_block| puts str_block;puts} 
puts
puts orig_msdn_method.get_dll_dry_helper_function # this could be msdn_methods.first.get_blah too
puts
inform "********** All parsing complete.  Parsed #{msdn_methods.length} functions."
