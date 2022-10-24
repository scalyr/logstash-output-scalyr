require 'benchmark'
require 'quantile'

require_relative '../../lib/scalyr/common/util'

# Micro benchmark which measures how much overhead Quantile.observe adds vs random sampling to see
# where making sampling (e.g. on event level metrics) is desired

ITERATIONS = 10000

def run_benchmark_and_print_results(run_benchmark_func)
  result = []
  ITERATIONS.times do |_i|
    result << Benchmark.measure { run_benchmark_func.() }
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

def quantile_observe()
  @value.observe(5)
end

def random_sample()
  return @prng.rand(0.0..1.0) < 0.5
end

puts "Quartile.observe()"
puts "==============================="

run_benchmark_and_print_results(method(:quantile_observe))

puts "random sample"
puts "==============================="
run_benchmark_and_print_results(method(:random_sample))
