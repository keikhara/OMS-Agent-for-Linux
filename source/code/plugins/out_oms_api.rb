module Fluent

  class OutputOMSApi < BufferedOutput

    Plugin.register_output('out_oms_api', self)

    def initialize
      super

      require 'base64'
      require 'digest'
      require 'json'
      require 'net/http'
      require 'net/https'
      require 'openssl'
      require 'socket'
      require 'time'
      require 'uri'
      require 'zlib'
      require_relative 'omslog'
      require_relative 'oms_configuration'
      require_relative 'oms_common'
    end

    config_param :omsadmin_conf_path, :string, :default => '/etc/opt/microsoft/omsagent/conf/omsadmin.conf'
    config_param :cert_path, :string, :default => '/etc/opt/microsoft/omsagent/certs/oms.crt'
    config_param :key_path, :string, :default => '/etc/opt/microsoft/omsagent/certs/oms.key'
    config_param :proxy_conf_path, :string, :default => '/etc/opt/microsoft/omsagent/conf/proxy.conf'
    config_param :api_version, :string, :default => '2016-04-01'
    config_param :compress, :bool, :default => true
    config_param :time_generated_field, :string, :default => ''

    def configure(conf)
      super
    end

    def start
      super
      @proxy_config = OMS::Configuration.get_proxy_config(@proxy_conf_path)
      @logtype_regex = Regexp.new('^[A-Za-z][A-Za-z0-9_]{1,100}$')
    end

    def shutdown
      super
    end

    ####################################################################################################
    # Methods
    ####################################################################################################

    # post data to the service
    # parameters:
    #   log_type: string. log type
    #   records: hash[]. an array of data
    def post_data(log_type, records)
      msg = OMS::Common.safe_dump_simple_hash_array(records)

      if msg.nil?
        return 0
      end

      headers = {}
      headers[OMS::CaseSensitiveString.new("Log-Type")] = log_type

      headers[OMS::CaseSensitiveString.new("x-ms-date")] = Time.now.utc.httpdate()
      headers["Content-Type"] = 'application/json'

      if @compress == true
        headers["Content-Encoding"] = "deflate"
      end

      if @time_generated_field != ''
        headers[OMS::CaseSensitiveString.new("time-generated-field")] = @time_generated_field
      end

      api_endpoint = OMS::Configuration.ods_endpoint.clone
      api_endpoint.query = "api-version=#{@api_version}"
      req = Net::HTTP::Post.new(api_endpoint.request_uri, headers)

      if @compress == true
        req.body = Zlib::Deflate.deflate(msg)
      else
        req.body = msg
      end

      http = OMS::Common.create_ods_http(api_endpoint, @proxy_config)
      OMS::Common.start_request(req, http)

      return req.body.bytesize
    end # post_data

    # parse the tag to get the settings and append the message to blob
    # parameters:
    #   tag: string. the tag of the item
    #   records: hash[]. an arrary of data
    def handle_records(tag, records)
      tags = tag.split('.')
      if tags.size >= 3
        # tag should have 6 parts at least:
        # tags[0]: oms
        # tags[1]: api
        # tags[2]: log type

        log_type = tags[2]

        if @logtype_regex =~ log_type
          start = Time.now
          dataSize = post_data(log_type, records)
          time = Time.now - start
          @log.trace "Success sending #{dataSize} bytes of data through API #{time.round(3)}s"
        else
          raise "The log type '#{log_type}' is not valid. it should match #{@logtype_regex}"
        end
      else
        raise "The tag does not have at least 3 parts #{tag}"
      end
    rescue OMS::RetryRequestException => e
      @log.info "Encountered retryable exception. Will retry sending data later."
      @log.debug "Error:'#{e}'"
      # Re-raise the exception to inform the fluentd engine we want to retry sending this chunk of data later.
      raise e.message
    rescue => e
      # We encountered something unexpected. We drop the data because
      # if bad data caused the exception, the engine will continuously
      # try and fail to resend it. (Infinite failure loop)
      OMS::Log.error_once("Unexpecting exception, dropping data. Error:'#{e}'")
    end # handle_record

    # This method is called when an event reaches to Fluentd.
    # Convert the event to a raw string.
    def format(tag, time, record)
      @log.trace "Buffering #{tag}"
      [tag, record].to_msgpack
    end

    # This method is called every flush interval. Send the buffer chunk to OMS. 
    # 'chunk' is a buffer chunk that includes multiple formatted
    # NOTE! This method is called by internal thread, not Fluentd's main thread. So IO wait doesn't affect other plugins.
    def write(chunk)
      # Quick exit if we are missing something
      if !OMS::Configuration.load_configuration(omsadmin_conf_path, cert_path, key_path)
        raise 'Missing configuration. Make sure to onboard. Will continue to buffer data.'
      end

      # Group records based on their datatype because OMS does not support a single request with multiple datatypes.
      datatypes = {}
      chunk.msgpack_each {|(tag, record)|
        if !datatypes.has_key?(tag)
          datatypes[tag] = []
        end
        datatypes[tag] << record
      }

      datatypes.each do |tag, records|
        handle_records(tag, records)
      end
    end

  end # Class

end # Module

