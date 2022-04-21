# NOTE: Micro benchmark which measures compression operation duration + compression ratio for
# various algorithms
require 'benchmark'

require 'zlib'
require 'rbzip2'
require 'zstandard'

require_relative '../../lib/scalyr/common/util'
require_relative './util'

# NOTE: bz2 can be extremly slow on large datasets
ITERATIONS = 5

def compress_data_deflate_level_6(data)
    Zlib::Deflate.deflate(data, 6)
end

def compress_data_deflate_level_3(data)
    Zlib::Deflate.deflate(data, 3)
end

def compress_data_bz2(data)
    io = StringIO.new
    bz2 = RBzip2.default_adapter::Compressor.new io
    bz2.write data
    bz2.close
    io.string
end

def compress_data_zstandard(data)
  Zstandard.deflate(data)
end

DIRECTORY = File.expand_path(File.dirname(__FILE__))
FIXTURES_DIRECTORY = File.join(DIRECTORY, "../../codespeed-agent-fixtures/fixtures/logs/")

# We read dataset in memory so we don't include file read in the timings

DATASETS = {
  :access_log_5_mb => File.read(File.join(FIXTURES_DIRECTORY, "access_log_5mb.log")),
  :json_log_5_mb => File.read(File.join(FIXTURES_DIRECTORY, "json_log_5_mb.log")),
  :rfc3164_syslog_log_5_mb => File.read(File.join(FIXTURES_DIRECTORY, "rfc3164_syslog_log_5_mb.log")),
}

def run_benchmark_and_print_results(file_name, data, run_benchmark_func)
  puts ""
  puts "Using dataset / input file: %s" % [file_name]
  puts ""

  uncompressed_size = data.length
  compressed_size = 0

  result = []
  ITERATIONS.times do |i|
    result << Benchmark.measure { compressed_size = run_benchmark_func.(data).length }
  end

  sum = result.inject(nil) { |sum, t| sum.nil? ? sum = t : sum += t }
  avg = sum / result.size

  puts ""
  puts "Durations"
  puts ""

  Benchmark.bm(7, "sum:", "avg:") do |b|
    [sum, avg]
  end

  puts ""
  puts "Compression ratio: %.2f" % ([uncompressed_size / compressed_size])
  puts ""
end

puts "Using %s iterations" % [ITERATIONS]
puts ""

puts "deflate level 6 (default)"
puts "==============================="

file_name = "access_log_5_mb.txt"
data = DATASETS[:access_log_5_mb]
run_benchmark_and_print_results(file_name, data, method(:compress_data_deflate_level_6))

file_name = "json_log_5_mb"
data = DATASETS[:json_log_5_mb]
run_benchmark_and_print_results(file_name, data, method(:compress_data_deflate_level_6))

file_name = "rfc3164_syslog_log_5_mb"
data = DATASETS[:rfc3164_syslog_log_5_mb]
run_benchmark_and_print_results(file_name, data, method(:compress_data_deflate_level_6))

puts "deflate level 3"
puts "==============================="

file_name = "access_log_5_mb.txt"
data = DATASETS[:access_log_5_mb]
run_benchmark_and_print_results(file_name, data, method(:compress_data_deflate_level_3))

file_name = "json_log_5_mb"
data = DATASETS[:json_log_5_mb]
run_benchmark_and_print_results(file_name, data, method(:compress_data_deflate_level_3))

file_name = "rfc3164_syslog_log_5_mb"
data = DATASETS[:rfc3164_syslog_log_5_mb]
run_benchmark_and_print_results(file_name, data, method(:compress_data_deflate_level_3))

puts "bz2"
puts "==============================="

file_name = "access_log_5_mb.txt"
data = DATASETS[:access_log_5_mb]
run_benchmark_and_print_results(file_name, data, method(:compress_data_bz2))

file_name = "json_log_5_mb"
data = DATASETS[:json_log_5_mb]
run_benchmark_and_print_results(file_name, data, method(:compress_data_bz2))

file_name = "rfc3164_syslog_log_5_mb"
data = DATASETS[:rfc3164_syslog_log_5_mb]
run_benchmark_and_print_results(file_name, data, method(:compress_data_bz2))

puts "zstandard"
puts "==============================="

file_name = "access_log_5_mb.txt"
data = DATASETS[:access_log_5_mb]
run_benchmark_and_print_results(file_name, data, method(:compress_data_zstandard))

file_name = "json_log_5_mb"
data = DATASETS[:json_log_5_mb]
run_benchmark_and_print_results(file_name, data, method(:compress_data_zstandard))

file_name = "rfc3164_syslog_log_5_mb"
data = DATASETS[:rfc3164_syslog_log_5_mb]
run_benchmark_and_print_results(file_name, data, method(:compress_data_zstandard))
