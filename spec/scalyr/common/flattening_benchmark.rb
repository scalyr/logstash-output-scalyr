require 'benchmark'
require 'json'

require_relative '../../../lib/scalyr/common/util'

# NOTE: When using jRuby using multiple iterations with the same dataset doesn't make
# sense since it will just use JITed version of the code which will be very fast. If we
# wanted to accurately measure using multiple iterations we would need te different
# input data for each iteration.
ITERATIONS = 800

def rand_str(len)
  return (0...len).map { (65 + rand(26)).chr }.join
end

def generate_hash(widths)
  result = {}
  if widths.empty?
    return rand_str(20)
  else
    widths[0].times do
      result[rand_str(9)] = generate_hash(widths[1..widths.length])
    end
    return result
  end
end

def generate_data_array_for_spec(spec)
  data = []
  ITERATIONS.times do
    data << generate_hash(spec)
  end

  data
end

def run_benchmark_and_print_results(data, run_benchmark_func)
  puts ""
  puts "Using %s total keys in a hash" % [Scalyr::Common::Util.flatten(data[0]).count]
  puts ""

  result = []
  ITERATIONS.times do |i|
    result << Benchmark.measure { run_benchmark_func.(data[0]) }
  end

  sum = result.inject(nil) { |sum, t| sum.nil? ? sum = t : sum += t }
  avg = sum / result.size

  Benchmark.bm(7, "sum:", "avg:") do |b|
    [sum, avg]
  end
  puts ""
end

def flatten_data_func(data)
end

def json_serialize_data(data)
  data.to_json
end

DATASETS = {
  :keys_50 => generate_data_array_for_spec([3, 3, 3, 2]),
  :keys_200 => generate_data_array_for_spec([4, 4, 3, 4]),
  :keys_200_flat => generate_data_array_for_spec([200]),
  :keys_512 => generate_data_array_for_spec([8, 4, 4, 4]),
  :keys_960 => generate_data_array_for_spec([12, 5, 4, 4]),
  :keys_2700 => generate_data_array_for_spec([14, 8, 6, 4])
}


puts "Using %s iterations" % [ITERATIONS]
puts ""

puts "Scalyr::Common::Util.flatten()"
puts "==============================="

# Around ~50 keys in a hash
data = DATASETS[:keys_50]
run_benchmark_and_print_results(data, method(:flatten_data_func))

# Around ~200 keys in a hash
data = DATASETS[:keys_200]
run_benchmark_and_print_results(data, method(:flatten_data_func))

# Around ~200 keys in a hash (single level)
data = DATASETS[:keys_200_flat]
run_benchmark_and_print_results(data, method(:flatten_data_func))

# Around ~512 keys in a hash
data = DATASETS[:keys_512]
run_benchmark_and_print_results(data, method(:flatten_data_func))

# Around ~960 keys in a hash
data = DATASETS[:keys_960]
run_benchmark_and_print_results(data, method(:flatten_data_func))

# Around ~2700 keys in a hash
data = DATASETS[:keys_2700]
run_benchmark_and_print_results(data, method(:flatten_data_func))

puts "JSON.dumps (hash.to_dict)"
puts "==============================="

# Around ~200 keys in a hash
data = generate_data_array_for_spec([4, 4, 3, 4])
run_benchmark_and_print_results(data, method(:json_serialize_data))

# Around ~200 keys in a hash (single level)
data = DATASETS[:keys_200_flat]
run_benchmark_and_print_results(data, method(:json_serialize_data))

# Around ~512 keys in a hash
data = generate_data_array_for_spec([8, 4, 4, 4])
run_benchmark_and_print_results(data, method(:json_serialize_data))

# Around ~960 keys in a hash
data = generate_data_array_for_spec([12, 5, 4, 4])
run_benchmark_and_print_results(data, method(:json_serialize_data))

# Around ~2700 keys in a hash
data = generate_data_array_for_spec([14, 8, 6, 4])
run_benchmark_and_print_results(data, method(:json_serialize_data))
