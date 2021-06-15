# encoding: utf-8
require "logstash/outputs/base"
require "logstash/namespace"
require "concurrent"
require "stud/buffer"
require "socket" # for Socket.gethostname
require "thread" # for safe queueing
require "uri" # for escaping user input
require 'json' # for converting event object to JSON for upload

require 'manticore'
require 'rbzip2'
require 'zlib'
require 'stringio'
require 'quantile'

require 'scalyr/common/client'
require "scalyr/common/util"
require "scalyr/constants"


#---------------------------------------------------------------------------------------------------------------------
# Implements the Scalyr output plugin
#---------------------------------------------------------------------------------------------------------------------
class LogStash::Outputs::Scalyr < LogStash::Outputs::Base

  config_name "scalyr"

  concurrency :shared

  # The Scalyr API write token, these are available at https://www.scalyr.com/keys.  This is the only compulsory configuration field required for proper upload
  config :api_write_token, :validate => :string, :required => true

  # If you have an EU-based Scalyr account, please use https://eu.scalyr.com/
  config :scalyr_server, :validate => :string, :default => "https://agent.scalyr.com/"

  # server_attributes is a dictionary of key value pairs that represents/identifies the logstash aggregator server
  # (where this plugin is running).  Keys are arbitrary except for the 'serverHost' key which holds special meaning to
  # Scalyr and is given special treatment in the Scalyr UI.  All of these attributes are optional (not required for logs
  # to be correctly uploaded)
  config :server_attributes, :validate => :hash, :default => nil

  # Related to the server_attributes dictionary above, if you do not define the 'serverHost' key in server_attributes,
  # the plugin will automatically set it, using the aggregator hostname as value, if this value is true.
  config :use_hostname_for_serverhost, :validate => :boolean, :default => false

  # Field that represents the origin of the log event.
  # (Warning: events with an existing 'serverHost' field, it will be overwritten)
  config :serverhost_field, :validate => :string, :default => 'serverHost'

  # The 'logfile' fieldname has special meaning for the Scalyr UI.  Traditionally, it represents the origin logfile
  # which users can search for in a dedicated widget in the Scalyr UI. If your Events capture this in a different field
  # you can specify that fieldname here and the Scalyr Output Plugin will rename it to 'logfile' before upload.
  # (Warning: events with an existing 'logfile' field, it will be overwritten)
  config :logfile_field, :validate => :string, :default => 'logfile'

  # The Scalyr Output Plugin expects the main log message to be contained in the Event['message'].  If your main log
  # content is contained in a different field, specify it here.  It will be renamed to 'message' before upload.
  # (Warning: events with an existing 'message' field, it will be overwritten)
  config :message_field, :validate => :string, :default => "message"

  # A list of fieldnames that are constant for any logfile. Any fields listed here will be sent to Scalyr as part of
  # the `logs` array instead of inside every event to save on transmitted bytes. What constitutes a single "logfile"
  # for correctness is a combination of logfile_field value and serverhost_field value. Only events with a serverHost
  # value with have fields moved.
  config :log_constants, :validate => :array, :default => nil

  # If true, nested values will be flattened (which changes keys to delimiter-separated concatenation of all
  # nested keys).
  config :flatten_nested_values, :validate => :boolean, :default => false
  config :flatten_nested_values_delimiter, :validate => :string, :default => "_" 

  # If true, the 'tags' field will be flattened into key-values where each key is a tag and each value is set to
  # :flat_tag_value
  config :flatten_tags, :validate => :boolean, :default => false
  config :flat_tag_prefix, :validate => :string, :default => 'tag_'
  config :flat_tag_value, :default => 1

  # Initial interval in seconds between bulk retries. Doubled on each retry up to `retry_max_interval`
  config :retry_initial_interval, :validate => :number, :default => 1

  # Set max interval in seconds between bulk retries.
  config :retry_max_interval, :validate => :number, :default => 64

  # Whether or not to verify the connection to Scalyr, only set to false for debugging.
  config :ssl_verify_peer, :validate => :boolean, :default => true

  # Path to SSL bundle file.
  config :ssl_ca_bundle_path, :validate => :string, :default => "/etc/ssl/certs/ca-bundle.crt"

  # If we should append our built-in Scalyr cert to the one we find at `ssl_ca_bundle_path`.
  config :append_builtin_cert, :validate => :boolean, :default => true

  config :max_request_buffer, :validate => :number, :default => 5500000  # echee TODO: eliminate?
  config :force_message_encoding, :validate => :string, :default => nil
  config :replace_invalid_utf8, :validate => :boolean, :default => false

  # Valid options are bz2, deflate, or none.
  config :compression_type, :validate => :string, :default => 'deflate'

  # An int containing the compression level of compression to use, from 1-9. Defaults to 6
  config :compression_level, :validate => :number, :default => 6

  # How often to log and report status metrics to Scalyr. Defaults to every 5
  # minutes.
  config :status_report_interval, :validate => :number, :default => 300

  # Set to true to also log status messages with various metrics to stdout in addition to sending
  # this data to Scalyr
  config :log_status_messages_to_stdout, :validate => :boolean, :default => false

  # Whether or not to count status event uploads in the statistics such as request latency etc.
  config :record_stats_for_status, :validate => :boolean, :default => false

  # Sample rate for event level metrics (flattening time, number of attributes per event, etc,).
  # It's important to set this in case there are many events coming in per seconds, because
  # instrumentation does add some overhead. By default, we sample 5% of the events. Keep in
  # mind that we use simple random based sampling. Maximum possible value is 1 (aka no sampling
  # - record metrics for every single event).
  # We use sampling since Quantile.observe() operation is more expensive than simple counter
  # based metric so we need to ensure recording a metric doesn't add too much overhead.
  # Based on micro benchmark, random based sampler is about 5x faster than quantile.observe()
  config :event_metrics_sample_rate, :validate => :number, :default => 0.05

  # Parser to attach to status events
  config :status_parser, :validate => :string, :default => "logstash_plugin_metrics"

  # Whether or not to create fresh quantile estimators after a status send. Depending on what you want to gather from
  # these stas this might be wanted or not.
  config :flush_quantile_estimates_on_status_send, :validate => :boolean, :default => false
  
  # Causes this plugin to act as if it successfully uploaded the logs, while actually returning as quickly as possible
  # after no work being done.
  config :noop_mode, :validate => :boolean, :default => false

  # Manticore related options
  config :http_connect_timeout, :validate => :number, :default => 10
  config :http_socket_timeout, :validate => :number, :default => 10
  config :http_request_timeout, :validate => :number, :default => 60
  config :http_pool_max, :validate => :number, :default => 50
  config :http_pool_max_per_route, :validate => :number, :default => 25

  def initialize(*params)
    super
    # Request statistics are accumulated across multiple threads and must be accessed through a mutex
    @stats_lock = Mutex.new
    @send_stats = Mutex.new
  end

  def close
    @running = false
    @client_session.close if @client_session
  end

  public
  def register
    # This prng is used exclusively to determine when to sample statistics and no security related purpose, for this
    # reason we do not ensure thread safety for it.
    @prng = Random.new

    if @event_metrics_sample_rate < 0 or @event_metrics_sample_rate > 1
      raise LogStash::ConfigurationError, "Minimum possible value for 'event_metrics_sample_rate' is 0 (dont sample any events) and maximum is 1 (sample every event)"
    end

    @node_hostname = Socket.gethostname

    if @log_constants and not @log_constants.all? { |x| x.is_a? String }
      raise LogStash::ConfigurationError, "All elements of 'log_constants' must be strings."
    end

    if @max_request_buffer > 6000000
      @logger.warn "Maximum request buffer > 6 MB.  This may result in requests being rejected by Scalyr."
    end

    @dlq_writer = dlq_enabled? ? execution_context.dlq_writer : nil

    @message_encoding = nil
    if @force_message_encoding.to_s != ''
      begin
        @message_encoding = Encoding.find(@force_message_encoding)
        @logger.debug "Forcing message encoding to '#{@force_message_encoding}'"
      rescue ArgumentError
        @logger.warn "Encoding '#{@force_message_encoding}' not found. Ignoring."
      end
    end

    #evaluate any statements in string value of the server_attributes object
    if @server_attributes
      new_attributes = {}
      @server_attributes.each do |key, value|
        if value.is_a?( String )
          m = /^\#{(.*)}$/.match( value )
          if m
            new_attributes[key] = eval( m[1] )
          else
            new_attributes[key] = value
          end
        end
      end
      @server_attributes = new_attributes
    end

    # See if we should use the hostname as the server_attributes.serverHost
    if @use_hostname_for_serverhost
      if @server_attributes.nil?
        @server_attributes = {}
      end

      # only set serverHost if it doesn't currently exist in server_attributes
      # Note: Use strings rather than symbols for the key, because keys coming
      # from the config file will be strings
      unless @server_attributes.key? 'serverHost'
        @server_attributes['serverHost'] = @node_hostname
      end
    end

    # Add monitor server attribute to identify this as coming from a plugin
    @server_attributes['monitor'] = 'pluginLogstash'

    @scalyr_server << '/' unless @scalyr_server.end_with?('/')

    @add_events_uri = URI(@scalyr_server) + "addEvents"

    @logger.info "Scalyr LogStash Plugin ID - #{self.id}"

    @session_id = SecureRandom.uuid
    @last_status_transmit_time_lock = Mutex.new
    @last_status_transmit_time = nil
    @last_status_ = false

    # Plugin level (either per batch or event level metrics). Other request
    # level metrics are handled by the HTTP Client class.
    @multi_receive_statistics = {
      :total_multi_receive_secs => 0
    }
    @plugin_metrics = get_new_metrics

    # create a client session for uploading to Scalyr
    @running = true
    @client_session = Scalyr::Common::Client::ClientSession.new(
        @logger, @add_events_uri,
        @compression_type, @compression_level, @ssl_verify_peer, @ssl_ca_bundle_path, @append_builtin_cert,
        @record_stats_for_status, @flush_quantile_estimates_on_status_send,
        @http_connect_timeout, @http_socket_timeout, @http_request_timeout, @http_pool_max, @http_pool_max_per_route
    )

    @logger.info(sprintf("Started Scalyr output plugin (%s)." % [PLUGIN_VERSION]), :class => self.class.name)

    # Finally, send a status line to Scalyr
    send_status

  end # def register

  # Convenience method to create a fresh quantile estimator
  def get_new_metrics
    return {
      :multi_receive_duration_secs => Quantile::Estimator.new,
      :multi_receive_event_count => Quantile::Estimator.new,
      :event_attributes_count => Quantile::Estimator.new,
      :flatten_values_duration_secs => Quantile::Estimator.new,
      :batches_per_multi_receive => Quantile::Estimator.new
    }
  end

  # Receive an array of events and immediately upload them (without buffering).
  # The Logstash framework will call this plugin method whenever there is a list of events to upload to Scalyr.
  # The plugin is expected to retry until success, or else to write failures to the Dead-letter Queue.
  # No buffering/queuing is done -- ie a synchronous upload to Scalyr is attempted and retried upon failure.
  #
  # If there are any network errors, exponential backoff occurs.
  #
  # Also note that event uploads are broken up into batches such that each batch is less than max_request_buffer.
  # Increasing max_request_buffer beyond 3MB will lead to failed requests.
  #
  public
  def multi_receive(events)
    # Just return and pretend we did something if running in noop mode
    return events if @noop_mode

    begin
      start_time = Time.now.to_f

      multi_event_request_array = build_multi_event_request_array(events)
      # Loop over all array of multi-event requests, sending each multi-event to Scalyr

      sleep_interval = @retry_initial_interval
      batch_num = 1
      total_batches = multi_event_request_array.length unless multi_event_request_array.nil?

      result = []
      records_count = events.to_a.length

      while !multi_event_request_array.to_a.empty?
        multi_event_request = multi_event_request_array.pop
        exc_data = nil
        exc_commonly_retried = false
        exc_retries = 0
        exc_sleep = 0
        begin
          # For some reason a retry on the multi_receive may result in the request array containing `nil` elements, we
          # ignore these.
          if !multi_event_request.nil?
            @client_session.post_add_events(multi_event_request[:body], false, multi_event_request[:serialization_duration])

            sleep_interval = @retry_initial_interval
            batch_num += 1
            result.push(multi_event_request)
          end

        rescue Scalyr::Common::Client::ServerError, Scalyr::Common::Client::ClientError => e
          sleep_interval = sleep_for(sleep_interval)
          exc_sleep += sleep_interval
          exc_retries += 1
          message = "Error uploading to Scalyr (will backoff-retry)"
          exc_data = {
              :url => e.url.to_s,
              :message => e.message,
              :batch_num => batch_num,
              :total_batches => total_batches,
              :record_count => multi_event_request[:record_count],
              :payload_size => multi_event_request[:body].bytesize,
              :will_retry_in_seconds => sleep_interval,
          }
          exc_data[:code] = e.code if e.code
          exc_data[:body] = e.body if @logger.debug? and e.body
          exc_data[:payload] = "\tSample payload: #{request[:body][0,1024]}..." if @logger.debug?
          if e.is_commonly_retried?
            # well-known retriable errors should be debug
            @logger.debug(message, exc_data)
            exc_commonly_retried = true
          else
            # all other failed uploads should be errors
            @logger.error(message, @exc_data)
            exc_commonly_retried = false
          end
          retry if @running

        rescue => e
          # Any unexpected errors should be fully logged
          @logger.error(
              "Unexpected error occurred while uploading to Scalyr (will backoff-retry)",
              :error_message => e.message,
              :error_class => e.class.name,
              :backtrace => e.backtrace
          )
          @logger.debug("Failed multi_event_request", :multi_event_request => multi_event_request)
          sleep_interval = sleep_for(sleep_interval)
          exc_data = {
            :error_message => e.message,
            :error_class => e.class.name,
            :backtrace => e.backtrace,
            :multi_event_request => multi_event_request
          }
          exc_sleep += sleep_interval
          exc_retries += 1
          retry if @running
        end

        if !exc_data.nil?
          message = "Retry successful after error."
          if exc_commonly_retried
            @logger.debug(message, :error_data => exc_data, :retries => exc_retries, :sleep_time => exc_sleep)
          else
            @logger.info(message, :error_data => exc_data, :retries => exc_retries, :sleep_time => exc_sleep)
          end
        end
      end

      if records_count > 0
        @stats_lock.synchronize do
          @multi_receive_statistics[:total_multi_receive_secs] += (Time.now.to_f - start_time)
          @plugin_metrics[:multi_receive_duration_secs].observe(Time.now.to_f - start_time)
          @plugin_metrics[:multi_receive_event_count].observe(records_count)
          @plugin_metrics[:batches_per_multi_receive].observe(total_batches)
        end
      end

      send_status
      return result

    rescue => e
      # Any unexpected errors should be fully logged
      @logger.error(
          "Unexpected error occurred while executing multi_receive.",
          :error_message => e.message,
          :error_class => e.class.name,
          :backtrace => e.backtrace
      )
    end
  end  # def multi_receive


  # Builds an array of multi-event requests from LogStash events
  # Each array element is a request that groups multiple events (to be posted to Scalyr's addEvents endpoint)
  #
  # This function also performs data transformations to support special fields and, optionally, flatten JSON values.
  #
  # Special fields are those that have special semantics to Scalyr, i.e. 'message' contains the main log message,
  # 'serverHost' and 'logfile' have a dedicated search boxes to facilitate filtering.  All Logstash event key/values will
  # be marshalled into a Scalyr addEvents `attr` key/value unless they are identified as alternate names for special
  # fields. The special fields ('message', 'serverHost', 'logfile') may be remapped from other fields (configured by setting
  # 'message_field', 'serverhost_field', 'logfile_field')
  #
  # Values that are nested JSON may be optionally flattened (See README.md for some examples).
  #
  # Certain fields are removed (e.g. @timestamp and @version)
  #
  # Tags are either propagated as a comma-separated string, or optionally transposed into key-values where the keys
  # are tag names and the values are 1 (may be configured.)
  def build_multi_event_request_array(logstash_events)
    if logstash_events.nil? or logstash_events.empty?
     return []
    end

    multi_event_request_array = Array.new
    total_bytes = 0
    # Set of unique scalyr threads for this chunk
    current_threads = Hash.new
    # Create a Scalyr event object for each record in the chunk
    scalyr_events = Array.new

    thread_ids = Hash.new
    next_id = 1 #incrementing thread id for the session

    # per-logfile attributes
    logs = Hash.new
    logs_ids = Hash.new
    next_log_id = 1

    logstash_events.each {|l_event|

      record = l_event.to_hash

      # Create optional threads hash if serverHost is non-nil
      # echee: TODO I don't think threads are necessary.  Too much info?
      # they seem to be a second level of granularity within a logfile
      serverHost = record.fetch(@serverhost_field, nil)

      if serverHost
        # get thread id or add a new one if we haven't seen this serverHost before
        if thread_ids.key? serverHost
          thread_id = thread_ids[serverHost]
        else
          thread_id = next_id
          thread_ids[serverHost] = thread_id
          next_id += 1
        end
        # then update the map of threads for this chunk
        current_threads[serverHost] = thread_id
      end

      rename = lambda do |renamed_field, standard_field|
        if standard_field != renamed_field
          if record.key? renamed_field
            if record.key? standard_field
              @logger.warn "Overwriting log record field '#{standard_field}'.  You are seeing this warning because in " +
              "your LogStash config file you have configured the '#{renamed_field}' field to be converted to the " +
              "'#{standard_field}' field, but the event already contains a field called '#{standard_field}' and "
              "this is now being overwritten."
            end
            record[standard_field] = record[renamed_field]
            record.delete(renamed_field)
          end
        end
      end

      # Rename user-specified message field -> 'message'
      rename.call(@message_field, 'message')
      # Fix message encoding
      if @message_encoding and !record['message'].to_s.empty?
        if @replace_invalid_utf8 and @message_encoding == Encoding::UTF_8
          record["message"] = record["message"].encode("UTF-8", :invalid => :replace,
                                                       :undef => :replace, :replace => "<?>").force_encoding('UTF-8')
        else
          record["message"].force_encoding(@message_encoding)
        end
      end

      # Rename user-specified serverHost field -> 'serverHost'
      rename.call(@serverhost_field, 'serverHost')

      # Rename user-specified logfile field -> 'logfile'
      rename.call(@logfile_field, 'logfile')

      # Set a default parser is none is present in the event
      if record['parser'].to_s.empty?
        record['parser'] = "logstashParser"
      end

      # Set logfile field if empty and serverHost is supplied
      if record['logfile'].to_s.empty? and serverHost
        record['logfile'] = "/logstash/#{serverHost}"
      end

      # Set a default if no serverHost value is present.
      if serverHost.nil?
        record['serverHost'] = "Logstash"
      end

      log_identifier = nil
      add_log = false
      if serverHost
       log_identifier = serverHost + record['logfile']
      end
      if log_identifier and not logs.key? log_identifier
        add_log = true
        logs[log_identifier] = {
          'id' => next_log_id,
          'attrs' => Hash.new
        }
        if not record['serverHost'].to_s.empty?
          logs[log_identifier]['attrs']['serverHost'] = record['serverHost']
          record.delete('serverHost')
        end
        if not record['logfile'].to_s.empty?
          logs[log_identifier]['attrs']['logfile'] = record['logfile']
          record.delete('logfile')
        end
        if @log_constants
          @log_constants.each {|log_constant|
            if record.key? log_constant
              logs[log_identifier]['attrs'][log_constant] = record[log_constant]
              record.delete(log_constant)
            end
          }
        end
        logs_ids[log_identifier] = next_log_id
        next_log_id += 1
      end

      # Delete unwanted fields from record
      record.delete('@version')
      record.delete('@timestamp')

      # flatten tags
      if @flatten_tags and record.key? 'tags'
        record['tags'].each do |tag|
          record["#{@flat_tag_prefix}#{tag}"] = @flat_tag_value
        end
        record.delete('tags')
      end

      # Record per-event level metrics (flatten duration, event attributes count). Doing this for every single
      # event would be somewhat expensive so we use sampling.
      should_sample_event_metrics = should_sample?

      # flatten record
      if @flatten_nested_values
        start_time = Time.now.to_f
        record = Scalyr::Common::Util.flatten(record, delimiter=@flatten_nested_values_delimiter)
        end_time = Time.now.to_f
        flatten_nested_values_duration = end_time - start_time
      end

      if should_sample_event_metrics
        @stats_lock.synchronize do
          @plugin_metrics[:event_attributes_count].observe(record.count)

          if @flatten_nested_values
            @plugin_metrics[:flatten_values_duration_secs].observe(flatten_nested_values_duration)
          end
        end
      end

      # Use LogStash event.timestamp as the 'ts' Scalyr timestamp.  Note that this may be overwritten by input
      # filters so may not necessarily reflect the actual originating timestamp.
      scalyr_event = {
        :ts => (l_event.timestamp.time.to_f * (10**9)).round,
        :attrs => record
      }

      # optionally set thread
      if serverHost
        scalyr_event[:thread] = thread_id.to_s
        scalyr_event[:log] = logs_ids[log_identifier]
      end

      # get json string of event to keep track of how many bytes we are sending
      begin
        event_json = scalyr_event.to_json
        log_json = nil
        if add_log
          log_json = logs[log_identifier].to_json
        end
      rescue JSON::GeneratorError, Encoding::UndefinedConversionError => e
        @logger.warn "#{e.class}: #{e.message}"

        # Send the faulty event to a label @ERROR block and allow to handle it there (output to exceptions file for ex)
        # TODO
        # atime = Fluent::EventTime.new( sec, nsec )
        # router.emit_error_event(serverHost, time, record, e)

        scalyr_event[:attrs].each do |key, value|
          @logger.debug "\t#{key} (#{value.encoding.name}): '#{value}'"
          scalyr_event[:attrs][key] = value.encode(
              "UTF-8", :invalid => :replace, :undef => :replace, :replace => "<?>"
          ).force_encoding('UTF-8')
        end
        event_json = scalyr_event.to_json
      end

      # generate new request if json size of events in the array exceed maximum request buffer size
      append_event = true
      add_bytes =  event_json.bytesize
      if log_json
        add_bytes = add_bytes + log_json.bytesize
      end
      if total_bytes + add_bytes > @max_request_buffer
        # make sure we always have at least one event
        if scalyr_events.size == 0
          scalyr_events << scalyr_event
          append_event = false
        end
        multi_event_request = self.create_multi_event_request(scalyr_events, current_threads, logs)
        multi_event_request_array << multi_event_request

        total_bytes = 0
        current_threads = Hash.new
        logs = Hash.new
        logs_ids = Hash.new
        scalyr_events = Array.new
      end

      # if we haven't consumed the current event already
      # add it to the end of our array and keep track of the json bytesize
      if append_event
        scalyr_events << scalyr_event
        total_bytes += add_bytes
      end

    }

    # create a final request with any left over events
    multi_event_request = self.create_multi_event_request(scalyr_events, current_threads, logs)
    multi_event_request_array << multi_event_request
    multi_event_request_array
  end


  # Helper method that adds a client_timestamp to a batch addEvents request body
  def add_client_timestamp_to_body(body)
    current_time_millis = DateTime.now.strftime('%Q').to_i
    # echee TODO scalyr_agent code suggests this should be "client_time", not "client_timestamp"
    # however, I cannot find any documentation anywhere. Is it even used?
    body[:client_timestamp] = current_time_millis.to_s
  end


  # A request comprises multiple Scalyr Events.  This function creates a request hash for
  # final upload to Scalyr (from an array of events, and an optional hash of current threads)
  # Note: The request body field will be json-encoded.
  def create_multi_event_request(scalyr_events, current_threads, current_logs)

    body = {
      :session => @session_id + Thread.current.object_id.to_s,
      :token => @api_write_token,
      :events => scalyr_events,
    }

    add_client_timestamp_to_body body

    # build the scalyr thread JSON object
    if current_threads
      threads = Array.new
      current_threads.each do |thread_name, id|
        threads << { :id => id.to_s, :name => "LogStash: #{thread_name}" }
      end
      body[:threads] = threads
    end

    # build the scalyr thread logs object
    if current_logs
      logs = Array.new
      current_logs.each do |identifier, log|
        logs << log
      end
      body[:logs] = logs
    end

    # add serverAttributes
    body[:sessionInfo] = @server_attributes if @server_attributes

    # We time serialization to get some insight on how long it takes to serialize the request body
    start_time = Time.now.to_f
    serialized_body = body.to_json
    end_time = Time.now.to_f
    serialization_duration = end_time - start_time
    { :body => serialized_body, :record_count => scalyr_events.size, :serialization_duration => serialization_duration }

  end  # def create_multi_event_request


  # Retrieve batch and other event level metric values
  def get_stats
    @stats_lock.synchronize do
      current_stats = @multi_receive_statistics.clone

      current_stats[:multi_receive_duration_p50] = @plugin_metrics[:multi_receive_duration_secs].query(0.5)
      current_stats[:multi_receive_duration_p90] = @plugin_metrics[:multi_receive_duration_secs].query(0.9)
      current_stats[:multi_receive_duration_p99] = @plugin_metrics[:multi_receive_duration_secs].query(0.99)

      current_stats[:multi_receive_event_count_p50] = @plugin_metrics[:multi_receive_event_count].query(0.5)
      current_stats[:multi_receive_event_count_p90] = @plugin_metrics[:multi_receive_event_count].query(0.9)
      current_stats[:multi_receive_event_count_p99] = @plugin_metrics[:multi_receive_event_count].query(0.99)

      current_stats[:event_attributes_count_p50] = @plugin_metrics[:event_attributes_count].query(0.5)
      current_stats[:event_attributes_count_p90] = @plugin_metrics[:event_attributes_count].query(0.9)
      current_stats[:event_attributes_count_p99] = @plugin_metrics[:event_attributes_count].query(0.99)

      current_stats[:batches_per_multi_receive_p50] = @plugin_metrics[:batches_per_multi_receive].query(0.5)
      current_stats[:batches_per_multi_receive_p90] = @plugin_metrics[:batches_per_multi_receive].query(0.9)
      current_stats[:batches_per_multi_receive_p99] = @plugin_metrics[:batches_per_multi_receive].query(0.99)

      if @flatten_nested_values
        # We only return those metrics in case flattening is enabled
        current_stats[:flatten_values_duration_secs_p50] = @plugin_metrics[:flatten_values_duration_secs].query(0.5)
        current_stats[:flatten_values_duration_secs_p90] = @plugin_metrics[:flatten_values_duration_secs].query(0.9)
        current_stats[:flatten_values_duration_secs_p99] = @plugin_metrics[:flatten_values_duration_secs].query(0.99)
      end

      if @flush_quantile_estimates_on_status_send
        @logger.debug "Recreating / reseting quantile estimator classes for plugin metrics"
        @plugin_metrics = get_new_metrics
      end

      current_stats
    end
  end


  # Sends a status update to Scalyr by posting a log entry under the special logfile of 'logstash_plugin.log'
  # Instead of creating a separate thread, let this method be invoked once at startup and then every 5 minutes
  # at most.  (If no events are received, no status update will be sent even if 5 minutes has elapsed).
  # Finally, note that there could be multiple instances of this plugin (one per worker), in which case each worker
  # thread sends their own status updates.  This is intentional so that we know how much data each worker thread is
  # uploading to Scalyr over time.
  def send_status

    status_event = {
      :ts => (Time.now.to_f * (10**9)).round,
      :attrs => {
        'logfile' => "scalyr_logstash.log",
        'plugin_id' => self.id,
      }
    }
    @send_stats.synchronize do
      if !@last_status_transmit_time
        status_event[:attrs]['message'] = sprintf("Started Scalyr LogStash output plugin (%s)." % [PLUGIN_VERSION])
        status_event[:attrs]['serverHost'] = @node_hostname
      else
        cur_time = Time.now()
        return if (cur_time.to_i - @last_status_transmit_time.to_i) < @status_report_interval
        # echee TODO: get instance stats from session and create a status log line
        msg = 'plugin_status: '
        cnt = 0
        @client_session.get_stats.each do |k, v|
          val = v.instance_of?(Float) ? sprintf("%.4f", v) : v
          val = val.nil? ? 0 : val
          msg << ' ' if cnt > 0
          msg << "#{k.to_s}=#{val}"
          cnt += 1
        end
        get_stats.each do |k, v|
          val = v.instance_of?(Float) ? sprintf("%.4f", v) : v
          val = val.nil? ? 0 : val
          msg << ' ' if cnt > 0
          msg << "#{k.to_s}=#{val}"
          cnt += 1
        end
        status_event[:attrs]['message'] = msg
        status_event[:attrs]['serverHost'] = @node_hostname
        status_event[:attrs]['parser'] = @status_parser
      end
    end
    multi_event_request = create_multi_event_request([status_event], nil, nil)
    begin
      @client_session.post_add_events(multi_event_request[:body], true, 0)
    rescue => e
      @logger.warn(
        "Unexpected error occurred while uploading status to Scalyr",
        :error_message => e.message,
        :error_class => e.class.name
      )
      return
    end
    @last_status_transmit_time = Time.now()

    if @log_status_messages_to_stdout
      @logger.info msg
    end
    status_event
  end

  # Returns true if we should sample and record metrics for a specific event based on the sampling
  # rate and random value
  def should_sample?
    return @prng.rand(0.0..1.0) < @event_metrics_sample_rate
  end


  # Returns true if it is time to transmit status
  def should_transmit_status?
    @last_status_transmit_time_lock.synchronize do
      saved_last_time = @last_status_transmit_time
      if Time.now.to_i - saved_last_time.to_i > @status_report_interval
        @last_status_transmit_time = Float::INFINITY
        return saved_last_time
      end
    end
  end


  # Helper method that performs synchronous sleep for a certain time interval
  def sleep_for(sleep_interval)
    Stud.stoppable_sleep(sleep_interval) { !@running }
    get_sleep_sec(sleep_interval)
  end


  # Helper method that gets the next sleep time for exponential backoff, capped at a defined maximum
  def get_sleep_sec(current_interval)
    doubled = current_interval * 2
    doubled > @retry_max_interval ? @retry_max_interval : doubled
  end


  # Helper method to check if the dead-letter queue is enabled
  def dlq_enabled?
    # echee TODO submit to DLQ
    respond_to?(:execution_context) && execution_context.respond_to?(:dlq_writer) &&
        !execution_context.dlq_writer.inner_writer.is_a?(::LogStash::Util::DummyDeadLetterQueueWriter)
  end
end
