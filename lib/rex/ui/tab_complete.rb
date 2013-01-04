module Rex
module Ui
module Tabs

#
# get tab completed filenames given +str+ as the word currently being typed and +words+ array
# containing the previously completed words as determined by Shellwords.
# Optionally, an array of +starting_locations+ may be given to set tab completion starting
# points and if +&block+ is given, only filenames which return true for the block will be
# returned
#

def tab_complete_simple_filenames(str, words, starting_locations=nil, &block)
	# caller can pass nil for starting_locations if default behavior of tab_complete_filenames
	# is desired, which uses ::Readline::FILENAME_COMPLETION_PROC
	# TODO: allow them to pass stuff like "install_root" and automatically try to prepend Msf::Config?
	tabs = []
	if not starting_locations
		tabs = tab_complete_filenames(str, words)
	else
		# in case we get a string instead of an Array
		starting_locations = ["#{starting_locations}"] if starting_locations.class = String
		starting_locations.each do |path|
			tabs << tab_complete_filenames(::File.join(path,str),words)
		end
	end
	if block_given?
		return tabs.select(&block)
	else
		return tabs
	end
end

# def find_tab_completed_file
#    for when you are trying to find a file to read that was tab completed
# end

# def tab_complete_simple_args(str, words, &block)
# 	tabs = []
# 	# get the command's arguments as an array and apply the block
# 	return tabs.each(&block)
# end

# def tab_complete_by_words_length(str, words, arr_of_procs)
# 	# TODO:  validate args
# 	# call the proc at words.length unless it doesn't exist
# 	# if there's nothing at words.length, call the last proc in the array
# 	# e.g., if there is one word in words, call the proc at arr_of_procs[1]
# 	# but if there are 4 words in words and only procs at 0,1,2, and 5 then
# 	# the proc at arr_of_procs[5] is called
# 	if arr_of_procs[words.length]
# 		return arr_of_procs[words.length].call(str,words)
# 	else
# 		return arr_of_procs.last.call(str,words)
# 	end
# end

private
#
# Provide a generic tab completion for file names.
#
# If the only completion is a directory, this descends into that directory
# and continues completions with filenames contained within.
#
def tab_complete_filenames(str, words)
	matches = ::Readline::FILENAME_COMPLETION_PROC.call(str)
	if matches and matches.length == 1 and File.directory?(matches[0])
		dir = matches[0]
		dir += File::SEPARATOR if dir[-1,1] != File::SEPARATOR
		matches = ::Readline::FILENAME_COMPLETION_PROC.call(dir)
	end
	matches
end

end # end Tabs module
end
end
