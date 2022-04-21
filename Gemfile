source 'https://rubygems.org'

gemspec

logstash_path = ENV["LOGSTASH_PATH"] || "../../logstash"
use_logstash_source = ENV["LOGSTASH_SOURCE"] && ENV["LOGSTASH_SOURCE"].to_s == "1"

if Dir.exist?(logstash_path) && use_logstash_source
  gem 'logstash-core', :path => "#{logstash_path}/logstash-core"
  gem 'logstash-core-plugin-api', :path => "#{logstash_path}/logstash-core-plugin-api"
end

group :test do
  gem "webmock"

  # Require the specific version of `json` used in logstash while testing
  gem 'json', '1.8.6'
end

gem 'pry'
gem 'pry-nav'
gem 'quantile', '~> 0.2.1'
gem 'manticore', '~> 0.8.0', platform: :jruby
gem 'jrjackson', '~> 0.4.14', platform: :jruby
