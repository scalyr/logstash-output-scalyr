# encoding: utf-8
require "logstash/outputs/base"
require "logstash/namespace"
require "concurrent"
require "stud/buffer"
require "socket" # for Socket.gethostname
require "thread" # for safe queueing
require "uri" # for escaping user input
require 'json' # for converting event object to JSON for upload

require 'net/http'
require 'net/http/persistent'
require 'net/https'
require 'rbzip2'
require 'zlib'
require 'stringio'



# Represents a Scalyr server-side error that occurs during upload attempt
class ServerError < StandardError

  attr_reader :code, :url, :body

  def initialize(msg=nil, code=nil, url=nil, body=nil)
    super(msg)
    @code = code.to_i
    @url = url
    @body = body
  end

  def is_commonly_retried?
    [503, 502, 409].include? @code
  end
end

class RequestDroppedError < ServerError;
  # Signifies that Scalyr server received the upload request but dropped it
end

class ClientError < StandardError

  attr_reader :code, :url, :body

  def initialize(msg=nil, url=nil)
    super(msg)
    @code = nil  # currently no way to get this from Net::HTTP::Persistent::Error
    @url = url
    @body = nil
  end

  def is_commonly_retried?
    false
  end
end



class LogStash::Outputs::Scalyr < LogStash::Outputs::Base

  config_name "scalyr"
  config :api_write_token, :validate => :string, :required => true
  config :scalyr_server, :validate => :string, :default => "https://agent.scalyr.com/"
  config :server_attributes, :validate => :hash, :default => nil
  config :use_hostname_for_serverhost, :validate => :boolean, :default => true
  config :ssl_ca_bundle_path, :validate => :string, :default =>  "/etc/ssl/certs/ca-bundle.crt"
  config :ssl_verify_peer, :validate => :boolean, :default => true
  config :ssl_verify_depth, :validate => :number, :default => 5

  # Field that represents the origin of the log event.  By knowing which field this is, the Scalyr plugin can
  # use this field to create the Scalyr "thread" attribute
  config :origin_field, :validate => :string, :default => 'origin'

  # The 'logfile' fieldname has special meaning for the Scalyr UI.  Traditionally, it represents the origin logfile
  # which users can search for in a dedicated widget in the Scalyr UI. If your Events capture this in a different field
  # you can specify that fieldname here and the Scalyr Output Plugin will rename it to 'logfile' before upload.
  # (Warning: events with an existing 'logfile' field, it will be overwritten)
  config :logfile_field, :validate => :string, :default => 'logfile'

  # The Scalyr Output Plugin expects the main log message to be contained in the Event['message'].  If your main log
  # content is contained in a different field, specify it here.  It will be renamed to 'message' before upload.
  # (Warning: events with an existing 'message' field, it will be overwritten)
  config :message_field, :validate => :string, :default => "message"

  config :max_request_buffer, :validate => :number, :default => 1024*1024
  config :force_message_encoding, :validate => :string, :default => nil
  config :replace_invalid_utf8, :validate => :boolean, :default => false

  # Valid options are bz2, deflate or None. Defaults to None.
  config :compression_type, :validate => :string, :default => 'bz2'

  # An int containing the compression level of compression to use, from 1-9. Defaults to 9 (max)
  config :compression_level, :validate => :number, :default => 9

  # Initial interval in seconds between bulk retries. Doubled on each retry up to `retry_max_interval`
  config :retry_initial_interval, :validate => :number, :default => 1

  # Set max interval in seconds between bulk retries.
  config :retry_max_interval, :validate => :number, :default => 64

  def close
    @running = false
    @client_session.close if @client_session
  end

  public
  def register

    if @max_request_buffer > (1024*1024*3)
      @logger.warn "Maximum request buffer > 3 MB.  This may result in requests being rejected by Scalyr."
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
        @server_attributes['serverHost'] = Socket.gethostname
      end
    end

    # Add monitor server attribute to identify this as coming from a plugin
    @server_attributes['monitor'] = 'pluginLogstash'

    @scalyr_server << '/' unless @scalyr_server.end_with?('/')

    @add_events_uri = URI(@scalyr_server) + "addEvents"

    @logger.info "Scalyr LogStash Plugin ID - #{self.id}"
    @thread_ids = Hash.new #hash of tags -> id
    @next_id = 1 #incrementing thread id for the session

    @session_id = SecureRandom.uuid
    @last_status_transmit_time_lock = Mutex.new
    @last_status_transmit_time = nil
    @last_status_ = false

    # create a client session for uploading to Scalyr
    @running = true
    @client_session = ClientSession.new(
        @logger, @add_events_uri,
        @compression_type, @compression_level,
        @ssl_verify_peer, @ssl_ca_bundle_path, @ssl_verify_depth
    )

    @logger.info("Started Scalyr output plugin", :class => self.class.name)

    # Finally, send a status line to Scalyr
    send_status

  end # def register




  # Receive an array of events and immediately upload them (without buffering)
  public
  def multi_receive(events)

    # Initially we submit the full array of events
    events_to_send = events

    sleep_interval = @retry_initial_interval

    multi_event_request_array = build_multi_event_request_array(events)
    # Loop over all array of multi-event requests, sending each multi-event to Scalyr

    sleep_interval = @retry_initial_interval
    batch_num = 1
    total_batches = multi_event_request_array.length unless multi_event_request_array.nil?

    result = []
    while !multi_event_request_array.to_a.empty?
      begin
        multi_event_request = multi_event_request_array.pop
        @client_session.post_add_events(multi_event_request[:body])
        sleep_interval = 0
        result.push(multi_event_request)

      rescue OpenSSL::SSL::SSLError => e
        # cannot rely on exception message, so we always log the following warning
        @logger.error "SSL certificate verification failed.  "
        "Please make sure your certificate bundle is configured correctly and points to a valid file.  "
        "You can configure this with the ssl_ca_bundle_path configuration option.  "
        "The current value of ssl_ca_bundle_path is '#{@ssl_ca_bundle_path}'"
        @logger.error e.message
        @logger.error "Discarding buffer chunk without retrying."

      rescue ServerError, ClientError => e
        sleep_interval = sleep_for(sleep_interval)
        message = "Error uploading to Scalyr (will backoff-retry)"
        exc_data = {
            :url => e.url.sanitized.to_s,
            :message => e.message,
            :batch_num => batch_num,
            :total_batches => total_batches,
            :record_count => multi_event_request[:record_count],
            :payload_size => multi_event_request[:body].bytesize,
            :will_retry_in_seconds => sleep_interval,
        }
        exc_data[:code] = e.response_code if e.code
        exc_data[:body] = e.response_body if @logger.debug? and e.body
        exc_data[:payload] = "\tSample payload: #{request[:body][0,1024]}..." if @logger.debug?
        if e.is_commonly_retried?
          # well-known retriable errors should be debug
          @logger.debug(message, exc_data)
        else
          # all other failed uploads should be errors
          @logger.error(message, exc_data)
        end
        retry if @running.true?

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
        retry if @running.true?
      end
    end

    send_status
    return result
  end  # def multi_receive





  # Builds an array of multi-Scalyr events from LogStash events
  # Each array element is a request that groups multiple events (to be posted to Scalyr's addEvents endpoint)
  def build_multi_event_request_array(logstash_events)

    multi_event_request_array = Array.new
    total_bytes = 0
    # Set of unique scalyr threads for this chunk
    current_threads = Hash.new
    # Create a Scalyr event object for each record in the chunk
    scalyr_events = Array.new

    logstash_events.each {|l_event|

      record = l_event.to_hash

      # Create optional threads hash if origin is non-nil
      # echee: TODO I don't think threads are necessary.  Too much info?
      # they seem to be a second level of granularity within a logfile
      origin = record.fetch(@origin_field, nil)
      if origin
        # get thread id or add a new one if we haven't seen this origin before
        if @thread_ids.key? origin
          thread_id = @thread_ids[origin]
        else
          thread_id = @next_id
          @thread_ids[origin] = thread_id
          @next_id += 1
        end
        # then update the map of threads for this chunk
        current_threads[origin] = thread_id
      end

      rename = lambda do |renamed_field, standard_field|
        if standard_field != renamed_field
          if record.key? renamed_field
            if record.key? standard_field
              @logger.warn "Overwriting log record field '#{standard_field}'.  You are seeing this warning because in "
              "your LogStash config file you have configured the '#{renamed_field}' field to be converted to the "
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
          record["message"] = record["message"].encode("UTF-8", :invalid => :replace, :undef => :replace, :replace => "<?>").force_encoding('UTF-8')
        else
          record["message"].force_encoding(@message_encoding)
        end
      end

      # Rename user-specified origin field -> 'origin'
      rename.call(@origin_field, 'origin')

      # Rename user-specified logfile field -> 'logfile'
      rename.call(@logfile_field, 'logfile')
      # Set logfile field if empty and origin is supplied
      if record['logfile'].to_s.empty? and origin
        record['logfile'] = "/logstash/#{origin}"
      end

      # Use LogStash event.timestamp as the 'ts' Scalyr timestamp.  Note that this may be overwritten by input
      # filters so may not necessarily reflect the actual originating timestamp.
      scalyr_event = {
          :ts => (l_event.timestamp.time.to_f * (10**9)).round,
          :attrs => record
      }

      # Delete unwanted fields from record
      record.delete('@version')
      record.delete('@timestamp')

      # optionally set thread
      if origin
        scalyr_event[:thread] = thread_id.to_s
      end

      # get json string of event to keep track of how many bytes we are sending
      begin
        event_json = scalyr_event.to_json
      rescue JSON::GeneratorError, Encoding::UndefinedConversionError => e
        @logger.warn "#{e.class}: #{e.message}"

        # Send the faulty event to a label @ERROR block and allow to handle it there (output to exceptions file for ex)
        # TODO
        # atime = Fluent::EventTime.new( sec, nsec )
        # router.emit_error_event(origin, time, record, e)

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
      if total_bytes + event_json.bytesize > @max_request_buffer
        # make sure we always have at least one event
        if scalyr_events.size == 0
          scalyr_events << scalyr_event
          append_event = false
        end
        multi_event_request = self.create_multi_event_request(scalyr_events, current_threads)
        multi_event_request_array << multi_event_request

        total_bytes = 0
        current_threads = Hash.new
        scalyr_events = Array.new
      end

      # if we haven't consumed the current event already
      # add it to the end of our array and keep track of the json bytesize
      if append_event
        scalyr_events << scalyr_event
        total_bytes += event_json.bytesize
      end

    }

    # create a final request with any left over events
    multi_event_request = self.create_multi_event_request(scalyr_events, current_threads)
    multi_event_request_array << multi_event_request
    multi_event_request_array
  end



  def add_client_timestamp_to_body(body)
    current_time_millis = DateTime.now.strftime('%Q').to_i
    # echee TODO scalyr_agent code suggests this should be "client_time", not "client_timestamp"
    # however, I cannot find any documentation anywhere. Is it even used?
    body[:client_timestamp] = current_time_millis.to_s
  end




  # A request comprises multiple Scalyr Events.  This function creates a request hash for
  # final upload to Scalyr ()given an Array of events and an optional hash of current threads)
  # Note: The request body field will be json-encoded.
  def create_multi_event_request(scalyr_events, current_threads)

    body = {
        :session => @session_id,
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

    # add serverAttributes
    body[:sessionInfo] = @server_attributes if @server_attributes

    { :body => body.to_json, :record_count => scalyr_events.size }

  end  # def create_multi_event_request




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

    if !@last_status_transmit_time
      status_event[:attrs]['message'] = "Started Scalyr LogStash output plugin."
    else
      cur_time = Time.now()
      return if (cur_time.to_i - @last_status_transmit_time.to_i) < 300
      # echee TODO: get instance stats from session and create a status log line
      msg = 'plugin_status: '
      cnt = 0
      @client_session.get_stats.each do |k, v|
        val = v.instance_of?(Float) ? sprintf("%.1f", v) : v
        msg << ', ' if cnt > 0
        msg << "#{k.to_s}=#{val}"
        cnt += 1
      end
      status_event[:attrs]['message'] = msg
    end
    multi_event_request = create_multi_event_request([status_event], nil)
    @client_session.post_add_events(multi_event_request[:body])
    @last_status_transmit_time = Time.now()
  end



  # Returns true if it is time to transmit status
  def should_transmit_status?
    @last_status_transmit_time_lock.synchronize do
      saved_last_time = @last_status_transmit_time
      if Time.now.to_i - saved_last_time.to_i > 300
        @last_status_transmit_time = Float::INFINITY
        return saved_last_time
      end
    ensure

    end
  end


  def sleep_for(sleep_interval)
    Stud.stoppable_sleep(sleep_interval) { @running.false? }
    get_sleep_sec(sleep_interval)
  end




  def get_sleep_sec(current_interval)
    doubled = current_interval * 2
    doubled > @retry_max_interval ? @retry_max_interval : doubled
  end




  def dlq_enabled?
    # echee TODO submit to DLQ
    respond_to?(:execution_context) && execution_context.respond_to?(:dlq_writer) &&
        !execution_context.dlq_writer.inner_writer.is_a?(::LogStash::Util::DummyDeadLetterQueueWriter)
  end

end





# Encapsulates the connection between the agent and the Scalyr server, thus shielding the implementation (which may
# create a new connection for every post or use a persistent connection)
class ClientSession

  def initialize(logger, add_events_uri, compression_type, compression_level,
                 ssl_verify_peer, ssl_ca_bundle_path, ssl_verify_depth)
    @logger = logger
    @add_events_uri = add_events_uri  # typically /addEvents
    @compression_type = compression_type
    @compression_level = compression_level
    @ssl_verify_peer = ssl_verify_peer
    @ssl_ca_bundle_path = ssl_ca_bundle_path
    @ssl_verify_depth = ssl_verify_depth

    @stats_lock = Mutex.new
    @stats = {
      :total_requests_sent => 0, # The total number of RPC requests sent.
      :total_requests_failed => 0, # The total number of RPC requests that failed.
      :total_request_bytes_sent => 0, # The total number of bytes sent over the network.
      :total_compressed_request_bytes_sent => 0,  # The total number of compressed bytes sent over the network
      :total_response_bytes_received => 0,  # The total number of bytes received.
      :total_request_latency_secs => 0, #  The total number of secs spent waiting for a responses (so average latency
                                        # can be calculated by dividing this number by @total_requests_sent).
                                        # This includes connection establishment time.
      :total_connections_created => 0, # The total number of HTTP connections successfully created.
    }

    @http = Net::HTTP::Persistent.new

    # verify peers to prevent potential MITM attacks
    if @ssl_verify_peer
      @http.ca_file = @ssl_ca_bundle_path
      @http.verify_mode = OpenSSL::SSL::VERIFY_PEER
      @http.verify_depth = @ssl_verify_depth
    end
  end  # def initialize



  # Get a clone of current statistics
  def get_stats
    @stats.clone
  end



  # Upload data to Scalyr. Assumes that the body size complies with Scalyr limits
  def post_add_events(body)
    post = prepare_post_object @add_events_uri.path, body
    fail_count = 1  # putative assume failure
    start_time = Time.now
    uncompressed_bytes_sent = 0
    compressed_bytes_sent = 0
    bytes_received = 0
    begin

      response = @http.request(@add_events_uri, post)
      handle_response(response)

      fail_count -= 1  # success means we negate the putative failure
      uncompressed_bytes_sent = (body.bytesize + @add_events_uri.path.bytesize)
      compressed_bytes_sent = (post.body.bytesize + @add_events_uri.path.bytesize)
      bytes_received = response.body.bytesize  # echee: double check
      # echee TODO add more statistics

    rescue Net::HTTP::Persistent::Error => e
      # The underlying persistent-connection library automatically retries when there are network-related errors.
      # Eventually, it will give up and raise this generic error, at which time, we convert it to a ClientError
      raise ClientError.new(e.message, @add_events_uri)

    ensure
      @stats_lock.synchronize do
        @stats[:total_requests_sent] += 1
        @stats[:total_requests_failed] += fail_count
        @stats[:total_request_bytes_sent] += uncompressed_bytes_sent
        @stats[:total_compressed_request_bytes_sent] += compressed_bytes_sent
        @stats[:total_response_bytes_received] += bytes_received
        end_time = Time.now
        @stats[:total_request_latency_secs] += (end_time - start_time)
      end

    end
  end  # def post_request



  def close
    @http.shutdown
  end  # def close



  # Prepare a post object to be sent, compressing it if necessary
  private
  def prepare_post_object(uri_path, body)
    # use compression if enabled
    encoding = nil
    if @compression_type
      if @compression_type == 'deflate'
        encoding = 'deflate'
        compressed_body = Zlib::Deflate.deflate(body, @compression_level)
      elsif @compression_type == 'bz2'
        encoding = 'bz2'
        io = StringIO.new
        bz2 = RBzip2.default_adapter::Compressor.new io
        bz2.write body
        bz2.close
        compressed_body = io.string
      end
    end

    post = Net::HTTP::Post.new uri_path
    post.add_field('Content-Type', 'application/json')

    if @compression_type
      post.add_field('Content-Encoding', encoding)
    end
    post.body = compressed_body
    post
  end  # def prepare_post_object




  def handle_response(response)
    @logger.debug "Response Code: #{response.code}"
    @logger.debug "Response Body: #{response.body}"

    response_hash = Hash.new

    begin
      response_hash = LogStash::Json.load(response.body)
    rescue
      response_hash["status"] = "Invalid JSON response from server"
    end

    # make sure the JSON response has a "status" field
    if !response_hash.key? "status"
      @logger.debug "JSON response does not contain status message"
      raise ServerError.new "JSON response does not contain status message"
    end

    status = response_hash["status"]

    if status != "success"
      if status =~ /discardBuffer/
        raise RequestDroppedError.new(status, response.code, @add_events_uri, response.body)
      else
        raise ServerError.new(status, response.code, @add_events_uri, response.body)
      end
    else
      code = response.code.to_s.strip.to_i
      if code < 200 or code > 299
        raise ServerError.new(status, response.code, @add_events_uri, response.body)
      end
    end

    response
  end  # def handle_response


end  # class ClientSession



