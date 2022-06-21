Gem::Specification.new do |s|
  s.name = 'logstash-output-scalyr'
  s.version         = '0.2.5.beta'
  s.licenses = ['Apache-2.0']
  s.summary = "Scalyr output plugin for Logstash"
  s.description     = "Sends log data collected by Logstash to Scalyr (https://www.scalyr.com)"
  s.authors = ["Edward Chee"]
  s.email = "echee@scalyr.com"
  s.homepage = "https://www.scalyr.com/help/data-sources#logstash"
  s.require_paths = ["lib"]

  # Files
  s.files = Dir['lib/**/*','spec/**/*','*.gemspec','*.md','CONTRIBUTORS','Gemfile','LICENSE','NOTICE.TXT']
  # Tests
  s.test_files = s.files.grep(%r{^(test|spec|features)/})

  # Special flag to let us know this is actually a logstash plugin
  s.metadata = { "logstash_plugin" => "true", "logstash_group" => "output" }

  # Gem dependencies
  s.add_runtime_dependency 'net-http-persistent'
  s.add_runtime_dependency 'logstash-core-plugin-api', '>= 1.60', '<= 2.99'
  s.add_runtime_dependency 'logstash-codec-plain'
  s.add_runtime_dependency 'quantile'
  s.add_runtime_dependency 'jrjackson'
  s.add_runtime_dependency 'manticore'
  s.add_runtime_dependency 'ffi', '>= 1.9.18'
  s.add_runtime_dependency 'rbzip2', '0.3.0'
  s.add_development_dependency 'logstash-devutils'
end
