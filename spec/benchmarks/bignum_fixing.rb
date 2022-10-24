require 'benchmark'
require 'quantile'

require_relative '../../lib/scalyr/common/util'
require_relative './util'

# Micro benchmark which measures how long it takes to find all the Bignums in a record and convert them to strings

ITERATIONS = 500

def rand_bignum()
  return 200004000020304050300 + rand(999999)
end

def generate_hash(widths)
  result = {}
  if widths.empty?
    return rand_bignum()
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
    result << Benchmark.measure { run_benchmark_func.(data[i]) }
  end

  sum = result.inject(nil) { |sum, t| sum.nil? ? sum = t : sum += t } # rubocop:disable Lint/UselessAssignment
  avg = sum / result.size

  Benchmark.bm(7, "sum:", "avg:") do |_b|
    [sum, avg]
  end
  puts ""
end


puts "Using %s iterations" % [ITERATIONS]
puts ""

@value = Quantile::Estimator.new
@prng = Random.new

def convert_bignums(record)
  Scalyr::Common::Util.convert_bignums(record)
end

puts "Util.convert_bignums()"
puts "==============================="

# Around ~200 keys in a hash
data = generate_data_array_for_spec([4, 4, 3, 4])
run_benchmark_and_print_results(data, method(:convert_bignums))

# Around ~200 keys in a hash (single level)
data = generate_data_array_for_spec([200])
run_benchmark_and_print_results(data, method(:convert_bignums))

# Around ~512 keys in a hash
data = generate_data_array_for_spec([8, 4, 4, 4])
run_benchmark_and_print_results(data, method(:convert_bignums))

# Around ~960 keys in a hash
data = generate_data_array_for_spec([12, 5, 4, 4])
run_benchmark_and_print_results(data, method(:convert_bignums))

# Around ~2700 keys in a hash
data = generate_data_array_for_spec([14, 8, 6, 4])
run_benchmark_and_print_results(data, method(:convert_bignums))
