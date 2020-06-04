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
                 ssl_verify_peer, ssl_ca_bundle_path, ssl_verify_depth)
    @logger = logger
    @add_events_uri = add_events_uri  # typically /addEvents
    @compression_type = compression_type
    @compression_level = compression_level
    @ssl_verify_peer = ssl_verify_peer
    @ssl_ca_bundle_path = ssl_ca_bundle_path
    @ssl_verify_depth = ssl_verify_depth

    # Request statistics are accumulated across multiple threads and must be accessed through a mutex
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
    else
      @http.verify_mode = OpenSSL::SSL::VERIFY_NONE
    end
  end  # def initialize



  # Get a clone of current statistics hash
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
    version = 'output-logstash-scalyr 0.1.3'
    post.add_field('User-Agent', version + ';' + RUBY_VERSION + ';' + RUBY_PLATFORM)

    if not encoding.nil?
      post.add_field('Content-Encoding', encoding)
      post.body = compressed_body
    else
      post.body = body
    end
    post
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
