module Scalyr; module Common; module Client

#---------------------------------------------------------------------------------------------------------------------
# An exception representing a Scalyr server-side error that occurs during upload attempt
#---------------------------------------------------------------------------------------------------------------------
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

#---------------------------------------------------------------------------------------------------------------------
# Encapsulates the connection between the agent and the Scalyr server, thus shielding the implementation (which may
# create a new connection for every post or use a persistent connection)
#---------------------------------------------------------------------------------------------------------------------
class ClientSession

  def initialize(logger, add_events_uri, compression_type, compression_level,
                 record_stats_for_status, flush_quantile_estimates_on_status_send)
    @logger = logger
    @add_events_uri = add_events_uri  # typically /addEvents
    @compression_type = compression_type
    @compression_level = compression_level
    @record_stats_for_status = record_stats_for_status
    @flush_quantile_estimates_on_status_send = flush_quantile_estimates_on_status_send

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
  def post_add_events(client, body, is_status, body_serialization_duration = 0)
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

    rescue OpenSSL::SSL::SSLError => e
      raise e

    # TODO: we shouldn't be seeing this anymore, figure out what to replace it with
    rescue Net::HTTP::Persistent::Error => e
      # The underlying persistent-connection library automatically retries when there are network-related errors.
      # Eventually, it will give up and raise this generic error, at which time, we convert it to a ClientError
      raise ClientError.new(e.message, @add_events_uri)

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

    version = 'output-logstash-scalyr 0.1.9'
    post_headers = {
      'Content-Type': 'application/json',
      'User-Agent': version + ';' + RUBY_VERSION + ';' + RUBY_PLATFORM
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
