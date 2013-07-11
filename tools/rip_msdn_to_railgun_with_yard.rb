#rip_msdn_to_railgun.rb
# e.g. http://msdn.microsoft.com/en-us/library/windows/desktop/aa385125(v=vs.85).aspx

# C++

# BOOL InternetCheckConnection(
#   _In_  LPCTSTR lpszUrl,
#   _In_  DWORD dwFlags,
#   _In_  DWORD dwReserved
# );

require 'nokogiri'
require 'open-uri'

url = nil
unless ARGV.length == 1
	puts "Usage: #{$0} url"
	exit 1
else
	url = ARGV[0]
end

def get_page(url)
	d = Nokogiri::HTML(open(url)) #, nil, 'ISO-8859-1'))
	#d.encoding = 'UTF-8'
end

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

def rubify_method_name(mname)
	tmp = mname.gsub(/::/, '/')
	tmp = tmp.gsub(/([A-Z]+)([A-Z][a-z])/,'\1_\2')
	tmp = tmp.gsub(/([a-z\d])([A-Z])/,'\1_\2')
	tmp.tr("-", "_").downcase
end

def get_code_from_nodeset(nodeset, start_index = 0, style = /C\+\+/)
	code_text = nil
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
					return cleanup_code(the_code)
				end
			end
		end
	end
end

def cleanup_code(str)
	#puts "Cleaning:\n#{str}"
	s = str.force_encoding("ASCII-8BIT")
	s.gsub!(/^\s*$/,'')
	s = clean_html(s)
	s.squeeze!(" ")
	s.strip!
end

def clean_html(str)
	# nuke all non-ascii chars for now (esp 0xA0 and 0xC2 etc)
	str.gsub(/\P{ASCII}/, ' ')
	# s.gsub!(194.chr, '') # "box char"
	# s.gsub!(160.chr, '') # nbsp
end

def get_yard_from_c_code(c_code)

end

def get_railgun_from_c(c_code)

end

CODE_SNIP_CONTAINER_XPATH = "//div[@class='codeSnippetContainer']" # e.g. id="code-snippet-1"
CODE_SNIP_CONTAINER_TABS_XPATH = "//div[@class='codeSnippetContainerTabs']"
CODE_SNIP_CONTAINER_TAB_SINGLE_XPATH = "//div[@class='codeSnippetContainerTabSingle']" # e.g. text=C++
CODE_SNIP_CONTAINER_CODE_XPATH = "//div[@class='codeSnippetContainerCode']" # the code itself

C_STRUCTS_TO_RAILGUN = {
	'ret' => {
				'bool'     => 'BOOL',
				'BOOL'     => 'BOOL',
				'handle'   => 'DWORD',
				'HANDLE'   => 'DWORD',
				'void'     => 'VOID',
				'VOID'     => 'VOID'
			},
	'in'  => { # NOTES:  LP = Pointer, C = Const, STR = String, W = Wide or Unicode
				# T = W if unicode is def, else regular, so TCHAR = WCHAR if unicode, else TCHAR = CHAR
				# Likewise, TSTR = WSTR if unicode, else TSTR = STR.
				# See http://www.codeproject.com/Articles/2995/The-Complete-Guide-to-C-Strings-Part-I-Win32-Chara
				# out params are always PBLOB's if they are pointer indicated like *so? or start with p?
				'HANDLE'   => 'DWORD',
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
	'out' => {
				'PBLOB'    => 'PBLOB',
				'PSECURITY_DESCRIPTOR' => 'PBLOB', # if thing is *thing
				'PSID'     => 'PBLOB',
				'LPDWORD'  => 'PBLOB',
				'LPTSTR'   => {'A' => 'PCHAR', 'W' => 'PWCHAR'},  # Regular  TCHAR String (wide char or char dep on unicode)
			},
	'inout' => {
				'HANDLE'   => 'DWORD',
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

page = get_page(url)
#_method_name = get_method_name(page)

all_code_snippet_containers = page.xpath(CODE_SNIP_CONTAINER_XPATH)
# until forced to do something fancier, we'll just take the first C++ style code snippet
cpp_code = get_code_from_nodeset(all_code_snippet_containers)
puts
puts "[*]  C++ Code:"
puts "---------------------------------------------------"
puts cpp_code
#puts cpp_code.unpack('U*').collect {|x| x.to_s 16}.join
# @todo:  get syntax from snippet
# @todo:  convert parameters to YARD doc
# @todo:  decide what to do w/the rest of the text, stuff like amplifications etc
# drop ret val type, start after FuncName( and stop at );
# @todo:  add comments to params using extra info in parameters section

def get_ret_type_and_func_name(line)
	#puts "Determining return type and function name from:\n#{line}"
	parts = line.split(/\s+/) # always returns an array, even an empty one

	ret_type = "UNK"
	func_name = "Unknown"
	unless parts.empty?
		type = parts[0] =~ /^H/ ? "HANDLE" : parts[0]
		ret_type = C_STRUCTS_TO_RAILGUN['ret'][type]
		ret_type = "UNK" unless ret_type
		func_name = parts[1].sub(/\($/,'')
		# if func_name still has () in it, it's probably a one-line (void) deal like
		# http://msdn.microsoft.com/en-us/library/windows/desktop/aa383938(v=vs.85).aspx
		if func_name =~ /\([A-Za-z]*\)/
			func_name = func_name.split(/\(/).first
		end
	end
	return [ret_type, func_name]
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
		interim_type = "LPDWORD"
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
	if cpp_type =~ /^P/ and name =~ /^\*/# ghetto, might have false pos
		interim_type = "LPDWORD"
	
	elsif cpp_type == "unsigned long"
		# Basic Rule (out):  If type is "unsigned long" and name starts w/ *, it's a PBLOB
		if name =~ /^\*/
			interim_type = "LPDWORD"
		# Basic Rule (out):  If type is "unsigned long" and name starts w/ dw, it's a DWORD
		elsif name =~ /^dw/
			interim_type = "DWORD"
		end
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
	return [rg_type, name, direction]
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
	direction = "unk"
	ret_type = "UNK"
	func_name = "Unknown"
	rg_type = "UNK"
	name = 'unknown'
	params = []

	cpp_code.lines do |line|
		next if line =~ /^\s*$/ or line =~ /^\s*\);/ # blank or last line
		line.strip!
		#puts "Analyzing line: #{line}"
		line.sub!("WINAPI ",'') # sometimes you get this WINAPI thing like in
		# http://msdn.microsoft.com/en-us/library/windows/desktop/aa384688(v=vs.85).aspx
		# I Don't know what it means, so I drop it for now.
		if line =~ /^[A-Z]{3,}\s+[A-Z]+[a-z]+.*\([A-Za-z);]*$/
			# this is the first line, we need to grab the ret type & name
			ret_type, func_name = get_ret_type_and_func_name(line)
		else
			# this is a regular param line
			params << get_param(line)
		end
	end
	return func_name, ret_type, params
end

def format_railgun_code(c_method_name, ret_type = 'DWORD', parameters = [])
	res = "dll.add_function(\'#{c_method_name}\', \'#{ret_type}\', [\n"
	parameters.each do |p|
		res += "\t[#{p.map {|x| "\'#{x}\'"}.join(", ")}],\n"
	end
	res += "])\n"
	res.lines.map { |line| "\t\t#{line}"}
end

def normalize_param_direction(cpp_code_dir)
	# @todo: what about _in_out_?
	case cpp_code_dir
	when /_inout/i
		res = 'inout'
	when /_in_/i
		res = 'in'
	when /_out_/i
		res = 'out'
	else
		res = 'unk'
	end
	return res
end

c_method_name, ret_type, params = analyze_cpp_code(cpp_code)
rg_code = format_railgun_code(c_method_name, ret_type, params)
# @todo:  here?  or when formatting railgun code? add comments

ruby_method_name = rubify_method_name(c_method_name)
puts
puts "[*]  Possible ruby method name:  #{ruby_method_name}"
puts
puts "[*]  Railgun Code:"
puts "---------------------------------------------------"
puts rg_code