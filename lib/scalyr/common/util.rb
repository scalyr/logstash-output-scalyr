module Scalyr; module Common; module Util;


# Flattens a hash or array, returning a hash where keys are a delimiter-separated string concatenation of all
# nested keys.  Returned keys are always strings.  If a non-hash or array is provided, raises TypeError.
# Please see rspec util_spec.rb for expected behavior.
# Includes a known bug where defined delimiter will not be used for nesting levels past the first, this is kept
# because some queries and dashboards already rely on the broken functionality.
def self.flatten(obj, delimiter='_', flatten_arrays=true, fix_deep_flattening_delimiters=false)

  # base case is input object is not enumerable, in which case simply return it
  if !obj.respond_to?(:each)
    raise TypeError.new('Input must be a hash or array')
  end

  result = Hash.new
  # require 'pry'
  # binding.pry

  if obj.respond_to?(:has_key?)

    # input object is a hash
    obj.each do |key, value|
      if (flatten_arrays and value.respond_to?(:each)) or value.respond_to?(:has_key?)
        flatten(value, fix_deep_flattening_delimiters ? delimiter : '_', flatten_arrays).each do |subkey, subvalue|
          result["#{key}#{delimiter}#{subkey}"] = subvalue
        end
      else
        result["#{key}"] = value
      end
    end

  elsif flatten_arrays

    # input object is an array or set
    obj.each_with_index do |value, index|
      if value.respond_to?(:each)
        flatten(value, fix_deep_flattening_delimiters ? delimiter : '_', flatten_arrays).each do |subkey, subvalue|
          result["#{index}#{delimiter}#{subkey}"] = subvalue
        end
      else
        result["#{index}"] = value
      end
    end

  else

    result = obj

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

end; end; end;

