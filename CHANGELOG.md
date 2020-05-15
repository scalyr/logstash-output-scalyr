# Beta
## 0.1.2
 - Remove special treatment of `origin` field in favor of `serverHost`
 - Change concurrency type to `single` to help guarantee one-time ordered delivery in Scalyr
 - Change default compression to `deflate`
 - Don't use aggregator hostname as `serverHost` by default
 - Update upload request format to match latest Scalyr API
 - Add `User-Agent` header to Scalyr requests

# Alpha
## 0.0.4
  - Docs: Set the default_codec doc attribute.
## 0.0.3
 - Docs: Add documentation template
## 0.0.2
 - Add encoding: utf-8 to spec files. This can help prevent issues during testing.
## 0.0.1
 - Plugins were updated to follow the new shutdown semantic, this mainly allows Logstash to instruct input plugins to terminate gracefully, 
   instead of using Thread.raise on the plugins' threads. Ref: https://github.com/elastic/logstash/pull/3895
 - Dependency on logstash-core update to 2.0

