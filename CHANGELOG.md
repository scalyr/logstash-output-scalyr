# Beta

## TBD
- Log truncated error body for all errors to help with debugging.

## 0.1.13
- Fix synchronization of status message sending code to avoid duplicate logs.

## 0.1.12
- Add logging of successful request retries after an error for additional clarity.
- Add debug level logging of request body on error.

## 0.1.11.beta
- Fixes to retry mechanisms.
- More thorough catching of events, preferring to retry requests rather than crashing the plugin.

## 0.1.10.beta

- Switch to shared concurrency to allow the use of multiple worker threads for increased
  throughput.
- Switch HTTP client library to `manticore` to work better with new shared concurrency.

## 0.1.9

- Add support for logging status messages with metrics to stdout in addition to sending this
  data to Scalyr by setting ``log_status_messages_to_stdout`` config option. By default those
  lines are logged under INFO log level and you may need to enable / configure pluggin logging
  as per https://www.elastic.co/guide/en/logstash/current/logging.html.
- Update metric reporting code to round float values to 4 decimal points so we also record sub
  millisecond values for per event metrics.

## 0.1.8

- Add additional metrics.
- Correctly handle flatten_nested_values_duration metric
- Add support for setting sampling rate for per event level metrics. It defaults to %5 (``0.05``.)
- Status log line format has been updated so it doesn't include comma between key=value pair to
  make parser definition a bit simpler.

## 0.1.7
 - Tracking of new statistics such as `multi_receive` method duration and batch sizes.
 - Addition of percentiles for both existing and new stats.
 - Add ability to define a parser name for status messages using the `status_parser` configuration option.

## 0.1.6
 - Allow for a customer delimiter when flattening values using the `flatten_nested_values_delimiter` configuration option

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

