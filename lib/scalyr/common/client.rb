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
                 ssl_verify_peer, ssl_ca_bundle_path, append_builtin_cert,
                 record_stats_for_status, flush_quantile_estimates_on_status_send,
                 connect_timeout, socket_timeout, request_timeout, pool_max, pool_max_per_route)
    @logger = logger
    @add_events_uri = add_events_uri  # typically /addEvents
    @compression_type = compression_type
    @compression_level = compression_level
    @ssl_verify_peer = ssl_verify_peer
    @ssl_ca_bundle_path = ssl_ca_bundle_path
    @append_builtin_cert = append_builtin_cert
    @record_stats_for_status = record_stats_for_status
    @flush_quantile_estimates_on_status_send = flush_quantile_estimates_on_status_send
    @connect_timeout = connect_timeout
    @socket_timeout = socket_timeout
    @request_timeout = request_timeout
    @pool_max = pool_max
    @pool_max_per_route = pool_max_per_route

    # A cert to use by default to avoid issues caused by the OpenSSL library not validating certs according to standard
    @cert_string = "" \
        "-----BEGIN CERTIFICATE-----\n" \
        "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\n" \
        "-----END CERTIFICATE-----"

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
      @ca_cert = Tempfile.new("ca_cert")
      if File.file?(@ssl_ca_bundle_path)
        @ca_cert.write(File.read(@ssl_ca_bundle_path))
        @ca_cert.flush
      end
      if @append_builtin_cert
        open(@ca_cert.path, 'a') do |f|
          f.puts @cert_string
        end
      end
      @ca_cert.flush
      c[:ssl][:ca_file] = @ca_cert.path
    else
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
  def prepare_post_object(uri_path, body)
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

end; end; end;
