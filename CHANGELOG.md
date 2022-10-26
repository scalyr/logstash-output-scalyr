# Beta

## 0.2.9.beta

* Update context which is logged with errors which represent HTTP requests which are retried
  to also include ``total_retries_so_far`` and ``total_sleep_time_so_far`` attribute.

## 0.2.8.beta

* Update ``.gemspec`` gem metadata to not include ``spec/`` directory with the tests and tests
  fixtures with the actual production gem file.

* Do not retry requests that will never be accepted by the server.
  Specifically, any request that returns HTTP Status code 413 is too large, and
  will never be accepted. Instead of simply retrying for 10 minutes before
  sending the request to the DLQ, skip the retries go directly to sending the
  request to the DLQ.

  To be notified when an event fails to be ingested for whatever reason, create
  an alert using the query: ``parser='logstash_plugin_metrics'
  failed_events_processed > 0``. Instructions on how to create an alert can be
  found in our docs here: https://scalyr.com/help/alerts

## 0.2.7.beta

* SSL cert validation code has been simplified. Now ``ssl_ca_bundle_path`` config option
  defaults to the CA bundle path which is vendored / bundled with the RubyGem and includes CA
  certs of the authorities which are used for DataSet API endpoint certificates.

  In addition to that, ``append_builtin_cert`` config option has been removed and the code now
  throws error in case invalid / inexistent path is specified for the ``ssl_ca_bundle_path``
  config option - this represents a fatal config error.

## 0.2.6.beta, 0.2.6

* Update default value of ``ssl_ca_bundle_path`` config option to
  ``/etc/ssl/certs/ca-certificates.crt``. This way it works out of the box with the default
  upstream logstash OSS Docker Image.
* Update default bundled root CA certs to contain all the root CA certs used by the DataSet API
  endpoints.

  In case you are encountering connectivity issues and SSL / TLS errors in the logstash log with
  previous versions of the client you should upgrade to this release.

## 0.2.5.beta

* Allow user to specify value for the DataSet event severity  (``sev``) field. "sev" field is a
  special top level event field which denotes the event severity (log level).

  To enable this functionality, user needs to configure ``severity_field`` plugin config option and
  set it to the logstash event field which carries the severity field value. This field value
  needs to be an integer and contain a value from 0 to 6 (inclusive).
* Upgrade dependencies (manticore -> 0.9.1, jrjackson -> 0.4.15).
* Fix experimental ``zstandard`` support.

  NOTE: For zstandard compression to be used zstd / libstd system package needs to be installed
  (https://github.com/msievers/zstandard-ruby/#examples-for-installing-libzstd) and ``zstandard``
  gem needs to be installed inside the Logstash jRuby environment
  (e.g. ``/usr/share/logstash/bin/ruby -S /usr/share/logstash/vendor/jruby/bin/gem install 
  zstandard ; echo 'gem "zstandard"' >> /opt/logstash/Gemfile``).

## 0.2.4.beta

* Experimental zstandard support - in development, not to be used in production.

## 0.2.3

- Increase default number of maximum retry attempts on failure from `5` to `15`.
- Change "Unexpected error occurred while uploading to Scalyr (will backoff-retry)" message to
  be logged under WARNING and not ERROR log level. This error is not fatal and simply indicates
  client will retry a failed request. We use WARNING and not INFO so we still have visibility into
  those messages (since most deployments have log level set to WARNING or above).

## 0.2.2

- No longer vendor dependencies in the gem. This gem used to vendor a vulnerable log4j version
  but because logstash uses the system log4j this should not make earlier versions of this gem
  vulnerable. This brings the additional benefit of reducing the file size of this gem.

## 0.2.1.beta

- Update plugin to fail fast on register and throw more user-friendly error on invalid URL for
  ``scalyr_server`` configuration option value and other fatal server errors (e.g. invalid
  hostname).
- On plugin init / register we now perform connectivity check and verify that we can talk to
  Scalyr API and validate that the API key is valid. This ensures that the plugin doesn't start and
  start consuming events until we can successfully perform a connectivity check. This means
  we can't end up in situation when we could potentially drop some events to the ground in case of
  an invalid API key or similar when reaching retry limit and DLQ disabled. If you want to disable
  this check on register, you can set ``perform_connectivity_check`` config option to ``false``.

## 0.2.0.beta, 0.2.0

- Fix a bug and correctly handle ``serverHost`` event level attribute. Now if an event contains
``serverHost`` attribute, this attribute will be correctly set on the event level and available for
 "Sources" filtering in the UI.
- Plugin doesn't set ``serverHost`` attribute with a fixed value of ``Logstash`` on each event
level anymore. If you still want this behavior, you can achieve that with logstash mutate filter.
 - Session level ``serverHost`` value now defaults to logstash aggregator node hostname
 (``use_hostname_for_serverhost`` config option now defaults to true).
- ``host`` attribute is not removed by default from all the events. By default, logstash adds
  ``host`` attribute which contains logstash aggregator host to each event. This is now redundant
  and unncessary with the fixed and improved serverHost behavior (host and serverHost would contain
  the same value by default). If you want to change this behavior and and still include ``host``
  attribute on each event you can do that by setting ``remove_host_attribute_from_events`` config
  option to false.

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

