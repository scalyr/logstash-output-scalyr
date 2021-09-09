module Scalyr; module Common; module Util;

class MaxKeyCountError < StandardError
  attr_reader :message, :sample_keys

  def initialize(message, sample_keys)
    @message = message
    @sample_keys = sample_keys
  end
end

# Flattens a hash or array, returning a hash where keys are a delimiter-separated string concatenation of all
# nested keys.  Returned keys are always strings.  If a non-hash or array is provided, raises TypeError.
# Please see rspec util_spec.rb for expected behavior.
# Includes a known bug where defined delimiter will not be used for nesting levels past the first, this is kept
# because some queries and dashboards already rely on the broken functionality.
def self.flatten(hash_obj, delimiter='_', flatten_arrays=true, fix_deep_flattening_delimiters=false, max_key_count=-1)

  # base case is input object is not enumerable, in which case simply return it
  if !hash_obj.respond_to?(:each)
    raise TypeError.new('Input must be a hash or array')
  end
  # case where we pass in a valid array, but don't want to flatten arrays
  if !hash_obj.respond_to?(:has_key?) and !flatten_arrays
    return hash_obj
  end

  stack = []
  stack << hash_obj
  key_stack = []
  key_stack << ""
  key_list = []
  key_list_width = []
  result = Hash.new
  test_key = 0
  #Debugging
  #require 'pry'
  #binding.pry

  until stack.empty?
    obj = stack.pop
    key_list << key_stack.pop

    # Case when object is a hash
    if obj.respond_to?(:has_key?) and obj.keys.count > 0
      key_list_width << obj.keys.count
      obj.each do |key, value|
        key_stack << key
        stack << value
      end

    # Case when object is an array we intend to flatten
    elsif flatten_arrays and obj.respond_to?(:each) and obj.count > 0
        key_list_width << obj.count
        obj.each_with_index do |value, index|
          key_stack << index
          stack << value
        end

    else
      result_key = ""
      delim = delimiter
      key_list.each_with_index do |key, index|
        # We have a blank key at the start of the key list to avoid issues with calling pop, so we ignore delimiter
        # for the first two keys
        if index > 1
          result_key += "#{delim}#{key}"
          if not fix_deep_flattening_delimiters
            delim = "_"
          end
        else
          result_key += "#{key}"
        end
      end
      result[result_key] = obj

      if max_key_count > -1 and result.keys.count > max_key_count
        raise MaxKeyCountError.new(
          "Resulting flattened object will contain more keys than the configured flattening_max_key_count of #{max_key_count}",
          result.keys[0..6]
        )
      end

      throw_away = key_list.pop
      until key_list_width.empty? or key_list_width[-1] > 1
        throw_away = key_list_width.pop
        throw_away = key_list.pop
      end
      if not key_list_width.empty?
        key_list_width[-1] -= 1
      end

    end
  end

  return result
end

def self.truncate(content, max)
  if content.length > max
    return "#{content[0...(max-3)]}..."
  end
  return content
end

def self.convert_bignums(obj)
  if obj.respond_to?(:has_key?) and obj.respond_to?(:each)
    # input object is a hash
    obj.each do |key, value|
      obj[key] = convert_bignums(value)
    end

  elsif obj.respond_to?(:each)
    # input object is an array or set
    obj.each_with_index do |value, index|
      obj[index] = convert_bignums(value)
    end

  elsif obj.is_a? Bignum
    return obj.to_s

  else
    return obj
  end
end


# Function which sets special serverHost attribute on the events without this special attribute
# to session level serverHost value
# NOTE: This method mutates scalyr_events in place.
def self.set_session_level_serverhost_on_events(session_server_host, scalyr_events, logs, batch_has_event_level_server_host = false)
  # Maps log id (number) to logfile attributes for more efficient lookups later on
  logs_ids_to_attrs = Hash.new

  logs.each {|_, log|
    logs_ids_to_attrs[log["id"]] = log["attrs"]
  }

  if batch_has_event_level_server_host
    scalyr_events.each {|s_event|
      log_id = s_event[:log]
      logfile_attrs = logs_ids_to_attrs[log_id]

      if logfile_attrs.nil?
        logfile_attrs = Hash.new
      end

      if s_event[:attrs][EVENT_LEVEL_SERVER_HOST_ATTRIBUTE_NAME].nil? and logfile_attrs[EVENT_LEVEL_SERVER_HOST_ATTRIBUTE_NAME].nil?
        s_event[:attrs][EVENT_LEVEL_SERVER_HOST_ATTRIBUTE_NAME] = session_server_host
      end
    }
  end
end

end; end; end;
