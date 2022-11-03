require "scalyr/constants"
require "logstash-core"

module Scalyr; module Common; module Client

#---------------------------------------------------------------------------------------------------------------------
# An exception representing a Scalyr server-side error that occurs during upload attempt
#---------------------------------------------------------------------------------------------------------------------
class ServerError < StandardError

  attr_reader :code, :url, :body, :e_class

  def initialize(msg=nil, code=nil, url=nil, body=nil, e_class="Scalyr::Common::Client::ServerError")
    super(msg)
    @code = code.to_i
    @url = url
    @body = body
    @e_class = e_class
  end

  def is_commonly_retried?
    [503, 502, 409].include? @code
  end
end

#---------------------------------------------------------------------------------------------------------------------
# An exception that signifies the Scalyr server received the upload request but dropped it
#---------------------------------------------------------------------------------------------------------------------
class RequestDroppedError < ServerError;
  def initialize(msg=nil, code=nil, url=nil, body=nil, e_class="Scalyr::Common::Client::RequestDroppedError")
    super(msg, code, url, body, e_class)
  end
end

#---------------------------------------------------------------------------------------------------------------------
# An exception that signifies the Scalyr server received the upload request but dropped it due to it being too large.
#---------------------------------------------------------------------------------------------------------------------
class PayloadTooLargeError < ServerError;
  def initialize(msg=nil, code=nil, url=nil, body=nil, e_class="Scalyr::Common::Client::PayloadTooLargeError")
    super(msg, code, url, body, e_class)
  end
end

#---------------------------------------------------------------------------------------------------------------------
# An exception that signifies an error which occured during Scalyr deploy window
#---------------------------------------------------------------------------------------------------------------------
class DeployWindowError < ServerError;
  def initialize(msg=nil, code=nil, url=nil, body=nil, e_class="Scalyr::Common::Client::DeployWindowError")
    super(msg, code, url, body, e_class)
  end
end

#---------------------------------------------------------------------------------------------------------------------
# An exception that signifies that the client has been throttled by the server
#---------------------------------------------------------------------------------------------------------------------
class ClientThrottledError < ServerError;
  def initialize(msg=nil, code=nil, url=nil, body=nil, e_class="Scalyr::Common::Client::ClientThrottledError")
    super(msg, code, url, body, e_class)
  end
end

#---------------------------------------------------------------------------------------------------------------------
# An exception representing failure of the http client to upload data to Scalyr (in contrast to server-side errors
# where the POST api succeeds, but the Scalyr server then responds with an error)
#---------------------------------------------------------------------------------------------------------------------
class ClientError < StandardError

  attr_reader :code, :url, :body, :e_class

  def initialize(msg=nil, url=nil, e_class="Scalyr::Common::Client::ClientError")
    super(msg)
    @code = nil  # currently no way to get this from Net::HTTP::Persistent::Error
    @url = url
    @body = nil
    @e_class = e_class
  end

  def is_commonly_retried?
    false
  end
end

#---------------------------------------------------------------------------------------------------------------------
# Encapsulates the connection between the agent and the Scalyr server, thus shielding the implementation (which may
# create a new connection for every post or use a persistent connection)
#---------------------------------------------------------------------------------------------------------------------
class ClientSession

  def initialize(logger, add_events_uri, compression_type, compression_level,
                 ssl_verify_peer, ssl_ca_bundle_path,
                 record_stats_for_status, flush_quantile_estimates_on_status_send,
                 connect_timeout, socket_timeout, request_timeout, pool_max, pool_max_per_route)
    @logger = logger
    @add_events_uri = add_events_uri  # typically /addEvents
    @compression_type = compression_type
    @compression_level = compression_level
    @ssl_verify_peer = ssl_verify_peer
    @ssl_ca_bundle_path = ssl_ca_bundle_path
    @record_stats_for_status = record_stats_for_status
    @flush_quantile_estimates_on_status_send = flush_quantile_estimates_on_status_send
    @connect_timeout = connect_timeout
    @socket_timeout = socket_timeout
    @request_timeout = request_timeout
    @pool_max = pool_max
    @pool_max_per_route = pool_max_per_route

    # Request statistics are accumulated across multiple threads and must be accessed through a mutex
    @stats_lock = Mutex.new
    @latency_stats = get_new_latency_stats
    @stats = {
        :total_requests_sent => 0, # The total number of RPC requests sent.
        :total_requests_failed => 0, # The total number of RPC requests that failed.
        :total_request_bytes_sent => 0, # The total number of bytes sent over the network.
        :total_compressed_request_bytes_sent => 0,  # The total number of compressed bytes sent over the network
        :total_response_bytes_received => 0,  # The total number of bytes received.
        :total_request_latency_secs => 0, #  The total number of secs spent waiting for a responses (so average latency
        # can be calculated by dividing this number by @total_requests_sent).
        # This includes connection establishment time.
        :total_serialization_duration_secs => 0, # The total duration (in seconds) it took to serialize (JSON dumos) all the request bodies.
        # You can calculate avg compression duration by diving this value with total_requests_sent
        :total_compression_duration_secs => 0, # The total duration (in seconds) it took to compress all the request bodies.
        # You can calculate avg compression duration by diving this value with total_requests_sent
        :compression_type => @compression_type,
        :compression_level => @compression_level,
    }
  end  # def initialize

  def client_config
    # TODO: Eventually expose some more of these as config options, though nothing here really needs tuning normally
    # besides SSL
    c = {
      connect_timeout: @connect_timeout,
      socket_timeout: @socket_timeout,
      request_timeout: @request_timeout,
      follow_redirects: true,
      automatic_retries: 1,
      retry_non_idempotent: false,
      check_connection_timeout: 200,
      pool_max: @pool_max,
      pool_max_per_route: @pool_max_per_route,
      cookies: true,
      keepalive: true,
      ssl: {}
    }

    # verify peers to prevent potential MITM attacks
    if @ssl_verify_peer
      c[:ssl][:verify] = :strict
      @logger.info("Using CA bundle from #{@ssl_ca_bundle_path} to validate the server side certificate")

      if not File.file?(@ssl_ca_bundle_path)
        raise Errno::ENOENT.new("Invalid path for ssl_ca_bundle_path config option - file doesn't exist or is not readable")
      end

      c[:ssl][:ca_file] = @ssl_ca_bundle_path
    else
      @logger.warn("SSL certificate validation has been disabled. You are strongly encouraged to enable it to prevent possible MITM and similar attacks.")
      c[:ssl][:verify] = :disable
    end

    c
  end

  def client
    @client ||= Manticore::Client.new(client_config)
  end

  # Convenience method to create a fresh quantile estimator
  def get_new_latency_stats
    return {
      # The total number of HTTP connections successfully created.
      :serialization_duration_secs => Quantile::Estimator.new, # The duration (in seconds) it took to serialize (JSON dumos) all the request bodies.
      :compression_duration_secs => Quantile::Estimator.new, # The duration (in seconds) it took to compress all the request bodies.
      :request_latency_secs => Quantile::Estimator.new, #  Secs spent waiting for a responses. This includes connection establishment time.
      :bytes_sent => Quantile::Estimator.new  # The number of bytes sent over the network. Batch size with a bit more overhead.
    }
  end

  # Get a clone of current statistics hash and calculate percentiles
  def get_stats
    @stats_lock.synchronize do
      current_stats = @stats.clone

      current_stats[:request_latency_p50] = @latency_stats[:request_latency_secs].query(0.5)
      current_stats[:request_latency_p90] = @latency_stats[:request_latency_secs].query(0.9)
      current_stats[:request_latency_p99] = @latency_stats[:request_latency_secs].query(0.99)
      current_stats[:serialization_duration_secs_p50] = @latency_stats[:serialization_duration_secs].query(0.5)
      current_stats[:serialization_duration_secs_p90] = @latency_stats[:serialization_duration_secs].query(0.9)
      current_stats[:serialization_duration_secs_p99] = @latency_stats[:serialization_duration_secs].query(0.99)
      current_stats[:compression_duration_secs_p50] = @latency_stats[:compression_duration_secs].query(0.5)
      current_stats[:compression_duration_secs_p90] = @latency_stats[:compression_duration_secs].query(0.9)
      current_stats[:compression_duration_secs_p99] = @latency_stats[:compression_duration_secs].query(0.99)
      current_stats[:bytes_sent_p50] = @latency_stats[:bytes_sent].query(0.5)
      current_stats[:bytes_sent_p90] = @latency_stats[:bytes_sent].query(0.9)
      current_stats[:bytes_sent_p99] = @latency_stats[:bytes_sent].query(0.99)

      if @flush_quantile_estimates_on_status_send
        @logger.debug "Recreating / reseting quantile estimator classes for plugin metrics"
        @latency_stats = get_new_latency_stats
      end
      current_stats
    end
  end

  # Send "ping" request to the API. This is mostly used to test the connecting with Scalyr API
  # and verify that the API key is valid.
  def send_ping(body)
    post_body, post_headers, _ = prepare_post_object @add_events_uri.path, body
    response = client.send(:post, @add_events_uri, body: post_body, headers: post_headers)
    handle_response(response)

    response
  end

  # Upload data to Scalyr. Assumes that the body size complies with Scalyr limits
  def post_add_events(body, is_status, body_serialization_duration = 0)
    post_body, post_headers, compression_duration = prepare_post_object @add_events_uri.path, body
    fail_count = 1  # putative assume failure
    start_time = Time.now
    uncompressed_bytes_sent = 0
    compressed_bytes_sent = 0
    bytes_received = 0
    begin
      response = client.send(:post, @add_events_uri, body: post_body, headers: post_headers)
      handle_response(response)

      fail_count -= 1  # success means we negate the putative failure
      uncompressed_bytes_sent = (body.bytesize + @add_events_uri.path.bytesize)
      compressed_bytes_sent = (post_body.bytesize + @add_events_uri.path.bytesize)
      bytes_received = response.body.bytesize  # echee: double check
        # echee TODO add more statistics

    rescue Manticore::ManticoreException => e
      # The underlying persistent-connection library automatically retries when there are network-related errors.
      # Eventually, it will give up and raise this generic error, at which time, we convert it to a ClientError
      raise ClientError.new(e.message, @add_events_uri, e.class.name)

    ensure
      if @record_stats_for_status or !is_status
        @stats_lock.synchronize do
          @stats[:total_requests_sent] += 1
          @stats[:total_requests_failed] += fail_count
          @stats[:total_request_bytes_sent] += uncompressed_bytes_sent
          @stats[:total_compressed_request_bytes_sent] += compressed_bytes_sent
          @stats[:total_response_bytes_received] += bytes_received
          @stats[:total_serialization_duration_secs] += body_serialization_duration
          @stats[:total_compression_duration_secs] += compression_duration
          end_time = Time.now
          @stats[:total_request_latency_secs] += (end_time - start_time)
          @latency_stats[:request_latency_secs].observe(end_time - start_time)
          @latency_stats[:serialization_duration_secs].observe(body_serialization_duration)
          @latency_stats[:compression_duration_secs].observe(compression_duration)
          @latency_stats[:bytes_sent].observe(uncompressed_bytes_sent)
        end
      end
    end
  end  # def post_request



  def close
    @client.close if @client
  end  # def close



  # Prepare a post object to be sent, compressing it if necessary
  private
  def prepare_post_object(_uri_path, body)
    # use compression if enabled
    encoding = nil
    compression_duration = 0
    if @compression_type
      start_time = Time.now.to_f
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
      elsif @compression_type == "zstandard"
        # NOTE: zstandard requires libzstd to be installed on the system and
        # zstandard gem. Since libzstd may not be installed out of the box, we
        # don't directly depend on this gem and it's up to the user to install
        # both dependencies manually in case they want to use zstandard.
        begin
          require 'zstandard'
        rescue LoadError
          raise SystemExit, "zstandard gem is missing. If you want to use zstandard compression you need to make sure zstandard and and libzstd dependency is installed. See TODO for more information."
        end

        encoding = 'zstandard'
        compressed_body = Zstandard.deflate(body)
      end
      end_time = Time.now.to_f
      compression_duration = end_time - start_time
    end

    version = sprintf('output-logstash-scalyr %s' % [PLUGIN_VERSION])
    post_headers = {
      'Content-Type': 'application/json',
      'User-Agent': version + ';' + RUBY_VERSION + ';' + RUBY_PLATFORM + ';' + LOGSTASH_VERSION
    }

    post_body = nil
    if not encoding.nil?
      post_headers['Content-Encoding'] = encoding
      post_body = compressed_body
    else
      post_body = body
    end
    return post_body, post_headers, compression_duration
  end  # def prepare_post_object



  # Process responses from Scalyr, raising appropriate exceptions if needed
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
    code = response.code.to_s.strip.to_i

    if status != "success"
      if code == 413
        raise PayloadTooLargeError.new(status, response.code, @add_events_uri, response.body)
      elsif [530, 500].include?(code)
        raise DeployWindowError.new(status, response.code, @add_events_uri, response.body)
      elsif code == 429
        raise ClientThrottledError.new(status, response.code, @add_events_uri, response.body)
      elsif status =~ /discardBuffer/
        raise RequestDroppedError.new(status, response.code, @add_events_uri, response.body)
      else
        raise ServerError.new(status, response.code, @add_events_uri, response.body)
      end
    else
      if code < 200 or code > 299
        raise ServerError.new(status, response.code, @add_events_uri, response.body)
      end
    end

    response
  end  # def handle_response


end  # class ClientSession

end; end; end;
