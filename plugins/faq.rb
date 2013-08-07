##
# $Id$
# $Revision$
##

require 'rex/ui/text/table'
require 'faq'

module Msf

class Plugin::Faq < Msf::Plugin
	class FaqCommandDispatcher
		include Msf::Ui::Console::CommandDispatcher

		def initialize(driver)
			super(driver)
			@faq_manager = FaqManager.new
		end

		def name
			"FAQ"
		end

		@@faq_opts = Rex::Parser::Arguments.new(
			"-h" => [ false, "Help banner."                             ],
			# "-a" => [ true, "Add an faq (title, description, tags"      ],
			"-t" => [ true, "Only search tags"                          ],
			"-a" => [ true, "Search all (title, descriptions, and tags)"],
			"-d" => [ true, "Only search descriptions"                  ],
		)
		#
		# Returns the hash of commands supported by this dispatcher.
		#
		def commands
			{
				"faq"        => "search for an faq (default is by title)",
				"faq_add"    => "add an faq.",
				"faq_delete" => "delete an faq (or all faqs)",
				"faq_save"   => "save the faqs to disk",
			}
		end

		def faqs
			@faq_manager.faqs
		end
		#
		# the main faq command handler
		#
		# usage: faq
		def cmd_faq(*args)
			if args.length < 1
				@faq_manager.faqs.each do |faq|
					print_line faq.to_s
					print_line
				end
			else
				if args.include?('-t')
					@faq_manager.titles.each do |title|
						print_line title.to_s
					end
				end
				if args.include?('-d')
					@faq_manager.descriptions.each do |desc|
						print_line desc.to_s
					end
				end
			end
			# we parse args manually instead of using @@faq.opts.parse to handle special cases
			# case args.length
			# when 0 # print the list of current faqs
			# 	if @faqes.length == 0
			# 		return print_status("No faqes currently defined")
			# 	else
			# 		tbl = Rex::Ui::Text::Table.new(
			# 			'Header'  => "Current Aliases",
			# 			'Prefix'  => "\n",
			# 			'Postfix' => "\n",
			# 			'Columns' => [ '', 'Alias Name', 'Alias Value' ]
			# 		)
			# 		# add 'faq' in front of each row so that the output can be copy pasted into an rc file if desired
			# 		@faqes.each_pair do |key,val|
			# 			tbl << ["faq",key,val]
			# 		end
			# 		return print(tbl.to_s)
			# 	end
			# when 1 # display the faq if one matches this name (or help)
			# 	return cmd_faq_help if args[0] == "-h" or args[0] == "--help"

			# else # let's see if we can assign or clear the faq

			# end
		end

		def cmd_faq_help
			print_line "Usage: faq regexp"
			print_line
			print(@@faq_opts.usage())
		end

		#
		# Tab completion for the faq command
		#
		def cmd_faq_tabs(str, words)
			if words.length <= 1
				#puts "1 word or less"
				return @@faq_opts.fmt.keys
			else
				#puts "more than 1 word"
				#return
			end
		end

		def cmd_faq_add(*args)
			cmd_faq_add_help if args.length < 4
			title = args.shift
			desc = args.shift
			tags = args.dup
			return @faq_manager.add_faq(Faq.new(title,desc,tags))
		end

		def cmd_faq_add_help
			print_line "Usage: faq_add title description tag1 [tag2]..."
			print_line "\t At least one tag is required"
			print_line
		end

		#
		# Delete one or more faqs
		#
		# @param args[Array<String>] List of FAQ's to delete, by title
		# @return [Boolean] Success(true) or failure(false)
		def cmd_faq_del(*args)
			cmd_faq_del_help if args.length < 1
			@faq_manager.faqs.each do |faq|
				return @faq_manager.del_faq(faq) if args.delete faq.title
			end
		end

		def cmd_faq_del_help
			print_line "Usage: faq_del title1 [title2] ..."
			print_line
		end

		#
		# Save the faqs
		#
		# @return [Boolean] Success(true) or failure(false)
		def cmd_faq_save
			return @faq_manager.save
		end

		def cmd_faq_save_help
			print_line "Usage: faq_save"
			print_line
		end

		# Helper methods

		def search_by_tags(regex)
			tags = @faq_manager.tags
			return matches
		end

		def search_by_title(regex)
			titles = @faq_manager.titles
			return matches
		end

		def search_by_description(regex)
			descriptions = @faq_manager.descriptions
			return matches
		end

	end # end AliasCommandDispatcher class

	#
	# The constructor is called when an instance of the plugin is created.  The
	# framework instance that the plugin is being associated with is passed in
	# the framework parameter.  Plugins should call the parent constructor when
	# inheriting from Msf::Plugin to ensure that the framework attribute on
	# their instance gets set.
	#
	def initialize(framework, opts)
		super

		## Register the commands above
		add_console_dispatcher(FaqCommandDispatcher)
	end


	#
	# The cleanup routine for plugins gives them a chance to undo any actions
	# they may have done to the framework.  For instance, if a console
	# dispatcher was added, then it should be removed in the cleanup routine.
	#
	def cleanup
		# If we had previously registered a console dispatcher with the console,
		# deregister it now.
		remove_console_dispatcher('FAQ')

		# we don't need to remove class methods we added because they were added to
		# AliasCommandDispatcher class
	end

	#
	# This method returns a short, friendly name for the plugin.
	#
	def name
		"faq"
	end

	#
	# This method returns a brief description of the plugin.  It should be no
	# more than 60 characters, but there are no hard limits.
	#
	def desc
		"Adds the ability to add, delete, or search the FAQs"
	end

end ## End Plugin Class
end ## End Module
