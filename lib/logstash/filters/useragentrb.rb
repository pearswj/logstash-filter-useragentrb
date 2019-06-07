# encoding: utf-8
require "logstash/filters/base"

# This  filter will replace the contents of the default
# message field with whatever you specify in the configuration.
#
# It is only intended to be used as an .
class LogStash::Filters::UserAgentRuby < LogStash::Filters::Base

  # Setting the config_name here is required. This is how you
  # configure this filter from your Logstash config.
  #
  # filter {
  #    {
  #     message => "My message..."
  #   }
  # }
  #
  config_name "useragentrb"

  # The field containing the user agent string. If this field is an
  # array, only the first value will be used.
  config :source, :validate => :string, :default => "message"

  # The name of the field to assign user agent data into.
  #
  # If not specified user agent data will be stored in the root of the event.
  config :target, :validate => :string, :default => "user_agent"

  # regexes.yaml file to use
  #
  # If not specified, this will default to the regexes.yaml that ships
  # with logstash.
  #
  # You can find the latest version of this here:
  # <https://github.com/tobie/ua-parser/blob/master/regexes.yaml>
  config :regexes, :validate => :string

  public
  def register
    # Add instance variables
    require 'user_agent_parser'
    if @regexes.nil?
      begin
        @parser = UserAgentParser::Parser.new()
      rescue Exception => e
        begin
          @parser = UserAgentParser::Parser.new(:patterns_path => "vendor/ua-parser/regexes.yaml")
        rescue => ex
          raise "Failed to cache, due to: #{ex}\n"
        end
      end
    else
      @logger.info("Using user agent regexes", :regexes => @regexes)
      @parser = UserAgentParser::Parser.new(:patterns_path => @regexes)
    end
  end #def register

  public
  def filter(event)
    return unless filter?(event)
    ua_data = nil

    useragent = event.get(@source)
    useragent = useragent.first if useragent.is_a? Array

    begin
      ua_data = @parser.parse(useragent)
    rescue Exception => e
      @logger.error("Uknown error while parsing user agent data", :exception => e, :field => @source, :event => event)
    end

    if !ua_data.nil?
      h = Hash.new

      # h["original"] = useragent
      h["name"] = ua_data.name

      unless ua_data.os.nil?
        h["os"] = Hash.new
        h["os"]["full"] = ua_data.os.to_s
        h["os"]["name"] = ua_data.os.name.to_s
        h["os"]["version"] = ua_data.os.version.to_s unless ua_data.os.version.nil?

        # not ECS
        h["os"]["major"] = ua_data.os.version.major.to_s unless ua_data.os.version.nil?
        h["os"]["minor"] = ua_data.os.version.minor.to_s unless ua_data.os.version.nil?
      end

      h["device"] = ua_data.device.to_s if not ua_data.device.nil?

      if not ua_data.version.nil?
        ua_version = ua_data.version
        h["major"] = ua_version.major if ua_version.major
        h["minor"] = ua_version.minor if ua_version.minor
        h["patch"] = ua_version.patch if ua_version.patch
        h["build"] = ua_version.patch_minor if ua_version.patch_minor
      end

      event.set(@target, h)

      # filter_matched should go in the last line of our successful code
      filter_matched(event)
    end

  end # def filter
end # class LogStash::Filters::Useragentrb
