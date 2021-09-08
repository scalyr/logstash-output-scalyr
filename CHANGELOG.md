# Beta

## 0.2.0.beta

- Fix a bug and correctly handle ``serverHost`` event level attribute. Now if an event contains ``serverHost`` attribute, this attribute will be correctly set on the event level and available for "Sources" filtering in the UI.
- Plugin doesn't set ``serverHost`` attribute with a fixed value of ``Logstash`` on each event level anymore. If you still want this behavior, you can achieve that with logstash mutate filter.
- Session level ``serverHost`` value now defaults to logstash aggregator node hostname (``use_hostname_for_serverhost`` config option now defaults to true).

## 0.1.26.beta
- Add support for new ``json_library`` config option. Valid values are ``stdlib`` (default) are ``jrjackson``. The later may offer 2-4x faster JSON serialization.

## 0.1.23.beta
- Add testing support for disabling estimation of serialized event size for each event in the batch.

## 0.1.22.beta
- Add new plugin metric for tracking the duration of ``build_multi_event_request_array`` method.
- Update internal dependencies (``manticore``) to latest stable version.

## 0.1.21.beta
- Fix issue with iterative flattening function when dealing with empty collections.

## 0.1.20.beta
- Rewrite flattening function to no longer be recursive, to help avoid maxing out the stack.
- Added a configurable value `flattening_max_key_count` to create a limit on how large of a record we can flatten.
It limits the maximum amount of keys we can have in the final flattened record. Defaults to unlimited.

## 0.1.19.beta
- Undo a change to nested value flattening functionality to keep existing formatting. This change can be re-enabled
by setting the `fix_deep_flattening_delimiters` configuration option to true.

## 0.1.18.beta
- Add metrics for successfully sent and failed logstash events, and retries.
- Make array flattening optional during nested value flattening with the `flatten_nested_arrays` configuration option.

## 0.1.17.beta
- Catch errors relating to Bignum conversions present in the ``json`` library and manually convert to string as
a workaround.

## 0.1.16.beta
- Fix race condition in ``register()`` method.

## 0.1.15.beta
- Only call ``send_status`` method at the end of ``multi_receive()`` if there is at least one
  record in the batch when ``report_status_for_empty_batches`` config option is set to ``false``.
- Update ``register()`` method to use a separate short-lived client session for sending initial
  client status.

## 0.1.14.beta
- Add configurable max retries for requests when running into errors.
- Add ability to send messages to the dead letter queue if we exhaust all retries and if it is configured.
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

