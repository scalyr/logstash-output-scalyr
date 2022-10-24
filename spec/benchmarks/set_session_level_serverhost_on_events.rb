require 'benchmark'
require 'quantile'

require_relative '../../lib/scalyr/constants'
require_relative '../../lib/scalyr/common/util'
require_relative './util'

# Micro benchmark which measures how long "set_session_level_serverhost_on_events" takes

ITERATIONS = 100

def run_benchmark_and_print_results(data, run_benchmark_func)
  puts ""
  puts "Using %s total events in a batch" % [data[0].size]
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

# Generate random event with only single event having special server host attribute set which
# represents a worst case scenario since we need to backfill rest of the events.
def generate_events(count)
  result = []

  ITERATIONS.times do |_iteration|
    events = []

    count.times do |index|
      event = generate_hash([2])
      event[:attrs] = Hash.new
      event[:log] = 1

      if index == count - 1
        event[:attrs][EVENT_LEVEL_SERVER_HOST_ATTRIBUTE_NAME] = format("test-host-%s", index)
      end

      events << event
    end

    raise "Assertion failed" unless events.size == count

    result << events
  end

  raise "Assertion failed" unless result.size == ITERATIONS
  result
end

def run_func(events)
  # NOTE: This function manipulates events in place
  events.each_with_index do |event, index|
    if index < events.size - 1
      # Last event will have _origServerHost set, but others won't
      raise "Assertion failed" unless event[:attrs][EVENT_LEVEL_SERVER_HOST_ATTRIBUTE_NAME].nil?
    end
  end

  Scalyr::Common::Util.set_session_level_serverhost_on_events("session-server-host-dummy", events, {}, true)

  events.each do |event|
    raise "Assertion failed" unless event[:attrs][EVENT_LEVEL_SERVER_HOST_ATTRIBUTE_NAME].nil? == false
  end
end


puts "Using %s iterations" % [ITERATIONS]
puts ""

@value = Quantile::Estimator.new

puts "Util.set_session_level_serverhost_on_events()"
puts "==============================="

# 100 events in a batch
data = generate_events(100)
run_benchmark_and_print_results(data, method(:run_func))

# 500 events in a batch
data = generate_events(500)
run_benchmark_and_print_results(data, method(:run_func))

# 1000 events in a batch
data = generate_events(1000)
run_benchmark_and_print_results(data, method(:run_func))

# 2000 events in a batch
data = generate_events(2000)
run_benchmark_and_print_results(data, method(:run_func))

# 3000 events in a batch
data = generate_events(3000)
run_benchmark_and_print_results(data, method(:run_func))

# 5000 events in a batch
data = generate_events(5000)
run_benchmark_and_print_results(data, method(:run_func))
