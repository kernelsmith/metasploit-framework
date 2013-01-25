# Module
# Module
require 'yaml'

class FaqManager
	attr_reader :faqs
	attr_reader :titles
	attr_reader :descriptions
	attr_reader :tags
	attr_reader :path

	def initialize(path = ::File.join(Msf::Config.install_root, 'data', 'faq', 'faq.yml'))
		@path = path
		@faqs = []
		unserialize_all_faqs
	end

	def add_faq(f)
		return @faqs << f if f.is_a?(Faq)
		return false
	end

	def delete_faq(f)
		return @faqs.delete(f) if f.is_a?(Faq)
		return false
	end

	#
	# unserialize all faqs from disk
	#
	def unserialize_all_faqs
		if File.readable?(@path)
			dlog("Loading faqs from \'#{@path}\'", "lib/faq")
			File.open(@path, "r") do |f|
				YAML.load_documents(f) {|faq| @faqs << faq}
			end
			return true
		else
			raise IOError.new("Unable to read the yaml faq file at \'#{@path}\'")
		end
		return false
	end
	alias :load :unserialize_all_faqs

	#
	# serialize all faqs to disk
	#
	def serialize_all_faqs
		if File.writable?(@path)
			dlog("Writing faqs to \'#{@path}\'", "lib/faq")
			return File.open(@path, "w") do |f|
				@faqs.each {|q| f.puts(q.to_yaml)}
			end
		else
			raise IOError.new("Unable to write the yaml faq file at \'#{@path}\'")
		end
		return false
	end
	alias :save :serialize_all_faqs

	# def unserialize_faq(path)
	# 	# @todo check that it exists and is readable first
	# 	begin
	# 		faq = YAML::load(File.open(path))
	# 	rescue
	# 		dlog("Badly formatted YAML in: '#{path}'")
	# 	end
	# end

	# def serialize_faq(f)
	# 	begin
	# 		File.open(f.path) { |x| x.write(f.to_yaml) }
	# 	rescue
	# 		dlog("Can't write YAML to: '#{f.path}'")
	# 	end
	# end

	def titles()
		t = []
		@faqs.each {|f| t << f.title}
		t
	end

	def tags()
		t = []
		@faqs.each {|f| t << f.tags}
		t
	end

	def descriptions()
		t = []
		@faqs.each {|f| t << f.description}
		t
	end

end # end class

class Faq

	attr_reader :title
	attr_reader :description
	attr_reader :tags
	alias :desc :description

	def initialize(title, desc = "", tags = [])
		@title = title
		@description = desc
		@tags = tags
	end

	def to_s
		return "Title:  #{@title}    Tags:  #{tags.join(',')}\nDescription:  #{desc}"
	end

end # end class