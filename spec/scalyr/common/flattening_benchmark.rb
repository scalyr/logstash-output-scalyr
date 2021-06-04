require 'benchmark'
require 'json'

require_relative '../../../lib/scalyr/common/util'

# NOTE: When using jRuby using multiple iterations with the same dataset doesn't make
# sense since it will just use JITed version of the code which will be very fast. If we
# wanted to accurately measure using multiple iterations we would need te different
# input data for each iteration.

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

ITERATIONS = 500

puts "Using %s iterations" % [ITERATIONS]
puts ""

# Around ~512 keys in a hash
data = []
ITERATIONS.times do
  data << generate_hash([8, 4, 4, 4])
end

puts "Using %s total keys in a hash" % [Scalyr::Common::Util.flatten(data[0]).count]
puts ""

result = []
ITERATIONS.times do |i|
  result << Benchmark.measure { Scalyr::Common::Util.flatten(data[i]) }
end

sum = result.inject(nil) { |sum, t| sum.nil? ? sum = t : sum += t }
avg = sum / result.size

Benchmark.bm(7, "sum:", "avg:") do |b|
  [sum, avg]
end

# Around ~960 keys in a hash
data = []
ITERATIONS.times do
  data << generate_hash([12, 5, 4, 4])
end

puts ""
puts "Using %s total keys in a hash" % [Scalyr::Common::Util.flatten(data[0]).count]
puts ""

result = []
ITERATIONS.times do |i|
  result << Benchmark.measure { Scalyr::Common::Util.flatten(data[i]) }
end

sum = result.inject(nil) { |sum, t| sum.nil? ? sum = t : sum += t }
avg = sum / result.size

Benchmark.bm(7, "sum:", "avg:") do |b|
  [sum, avg]
end

# Around ~2700 keys in a hash
data = []
ITERATIONS.times do
  data << generate_hash([14, 8, 6, 4])
end

puts ""
puts "Using %s total keys in a hash" % [Scalyr::Common::Util.flatten(data[0]).count]
puts ""

result = []
ITERATIONS.times do |i|
  result << Benchmark.measure { Scalyr::Common::Util.flatten(data[i]) }
end

sum = result.inject(nil) { |sum, t| sum.nil? ? sum = t : sum += t }
avg = sum / result.size

Benchmark.bm(7, "sum:", "avg:") do |b|
  [sum, avg]
end
