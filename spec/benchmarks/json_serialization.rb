require 'benchmark'
require 'json'
require 'jrjackson'

require_relative '../../lib/scalyr/common/util'
require_relative './util'

ITERATIONS = 500

def json_serialize_data_native(data)
  data.to_json
end

def json_serialize_data_jrjackson(data)
  JrJackson::Json.dump(data)
end

DATASETS = {
  :keys_50 => generate_data_array_for_spec([3, 3, 3, 2]),
  :keys_200 => generate_data_array_for_spec([4, 4, 3, 4]),
  :keys_200_flat => generate_data_array_for_spec([200]),
  :keys_512 => generate_data_array_for_spec([8, 4, 4, 4]),
  :keys_960 => generate_data_array_for_spec([12, 5, 4, 4]),
  :keys_2700 => generate_data_array_for_spec([14, 8, 6, 4])
}

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

puts "Using %s iterations" % [ITERATIONS]
puts ""

puts "native"
puts "==============================="

# Around ~50 keys in a hash
data = DATASETS[:keys_50]
run_benchmark_and_print_results(data, method(:json_serialize_data_native))

# Around ~200 keys in a hash
data = DATASETS[:keys_200]
run_benchmark_and_print_results(data, method(:json_serialize_data_native))

# Around ~200 keys in a hash (single level)
data = DATASETS[:keys_200_flat]
run_benchmark_and_print_results(data, method(:json_serialize_data_native))

# Around ~2700 keys in a hash
data = DATASETS[:keys_2700]
run_benchmark_and_print_results(data, method(:json_serialize_data_native))

puts "jrjackson"
puts "==============================="

# Around ~50 keys in a hash
data = DATASETS[:keys_50]
run_benchmark_and_print_results(data, method(:json_serialize_data_jrjackson))

# Around ~200 keys in a hash
data = DATASETS[:keys_200]
run_benchmark_and_print_results(data, method(:json_serialize_data_jrjackson))

# Around ~200 keys in a hash (single level)
data = DATASETS[:keys_200_flat]
run_benchmark_and_print_results(data, method(:json_serialize_data_jrjackson))

# Around ~2700 keys in a hash
data = DATASETS[:keys_2700]
run_benchmark_and_print_results(data, method(:json_serialize_data_jrjackson))
