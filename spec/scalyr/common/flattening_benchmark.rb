require 'benchmark'
require 'json'
require_relative '../../../lib/scalyr/common/util'

# NOTE: When using jRuby using multiple iterations with the same dataset doesn't make
# sense since it will just use JITed version of the code which will be very fast. If we
# wanted to accurately measure using multiple iterations we would need te different
# input data for each iteration.

ITERATIONS = 1

file = File.read('./spec/fixtures/rows.json')
data = JSON.parse(file)

result = []
ITERATIONS.times {
  result << Benchmark.measure { Scalyr::Common::Util.flatten(data) }
}

sum = result.inject(nil) { |sum, t| sum.nil? ? sum = t : sum += t }
avg = sum / result.size

puts "Using %s iterations" % [ITERATIONS]

Benchmark.bm(7, "sum:", "avg:") do |b|
  [sum, avg]
end