[![Unit Tests & Lint](https://github.com/scalyr/logstash-output-scalyr/actions/workflows/unit_tests.yml/badge.svg)](https://github.com/scalyr/logstash-output-scalyr/actions/workflows/unit_tests.yml) [![Smoke Tests](https://github.com/scalyr/logstash-output-scalyr/actions/workflows/smoke_tests.yml/badge.svg)](https://github.com/scalyr/logstash-output-scalyr/actions/workflows/smoke_tests.yml) [![Micro Benchmarks](https://github.com/scalyr/logstash-output-scalyr/actions/workflows/microbenchmarks.yml/badge.svg)](https://github.com/scalyr/logstash-output-scalyr/actions/workflows/microbenchmarks.yml) [![Gem Version](https://badge.fury.io/rb/logstash-output-scalyr.svg)](https://badge.fury.io/rb/logstash-output-scalyr)

# [Scalyr output plugin for Logstash]

This plugin implements a Logstash output plugin that uploads data to [Scalyr](http://www.scalyr.com).

You can view documentation for this plugin [on the Scalyr website](https://app.scalyr.com/solutions/logstash).

NOTE: If you are encountering connectivity issues and see SSL / TLS erros such as an example below,
you should upgrade to version 0.2.6 or higher.

```javascript
{"message":"Error uploading to Scalyr (will backoff-retry)",
"error_class":"Manticore::ClientProtocolException","url":"https://agent.scalyr.com/addEvents",
"message":"PKIX path validation failed: java.security.cert.CertPathValidatorException: validity check failed"
}
```

# Quick start

1. Build the gem, run `gem build logstash-output-scalyr.gemspec` 
2. Install the gem into a Logstash installation, run `/usr/share/logstash/bin/logstash-plugin install logstash-output-scalyr-0.2.6.gem` 
   or follow the latest official instructions on working with plugins from Logstash. As an alternative, you can directly install latest
   stable version from RubyGems - ``/usr/share/logstash/bin/logstash-plugin --version 0.2.6 logstash-output-scalyr``
3. Configure the output plugin (e.g. add it to a pipeline .conf)
4. Restart Logstash 

# Configuration

The Scalyr output plugin has a number of sensible defaults so the minimum configuration only requires your `api_write_token` for upload access.

Plugin configuration is achieved by adding an output section to the appropriate config file for your Logstash event pipeline: 

```
my_pipeline.conf

input {   
  file {  
    path => "/var/log/messages"  
  }  
}

output {
 scalyr {
   api_write_token => 'SCALYR_API_KEY'
   serverhost_field => 'host'
   logfile_field => 'path'
 }
}
```

In the above example, the Logstash pipeline defines a file input that reads from `/var/log/messages`.  Log events from this source have the `host` and `path` fields.  The pipeline then outputs to the scalyr plugin, which in this example is configured to remap `host`->`serverHost` and `path`->`logfile`, thus facilitating filtering in the Scalyr UI.

## Notes on serverHost attribute handling

> Some of this functionality has been fixed and changed in the v0.2.0 release. In previous
  versions, plugin added ``serverHost`` attribute with a value of ``Logstash`` to each event and
  this attribute was not handled correctly - it was treated as a regular event level attribute
  and not a special attribute which can be used for Source functionality and filtering.

By default this plugin will set ``serverHost`` for all the events in a batch to match hostname of
the logstash node where the output plugin is running.

You can change that either by setting ``serverHost`` attribute in the ``server_attributes`` config
option hash or by setting ``serverHost`` attribute on the event level via logstash record attribute.

In both scenarios, you will be able to utilize this value for "Sources" functionality and filterin
in the Scalyr UI.

For example:

1. Define static value for all the events handled by specific plugin instance

```
output {
 scalyr {
   api_write_token => 'SCALYR_API_KEY'
   server_attributes => {'serverHost' => 'my-host-1'}
 }
}
```

2. Define static value on the event level which is set via logstash filter

```
  mutate {
    add_field => { "serverHost" => "my hostname" }
  }
```

3. Define dynamic value on the event level which is set via logstash filter

```
  mutate {
    add_field => { "serverHost" => "%{[host][name]}" }
  }
```

## Notes on severity (sev) attribute handling

``sev`` is a special top level DataSet event field which denotes the event severity / log level.

To enable this functionality, user needs to define ``severity_field`` plugin config option. This
config option tells the plugin which Logstash event field carries the value for the severity field.

The actual value needs to be an integer between 0 and 6 inclusive. Those values are mapped to
different severity / log levels on DataSet server side as shown below:

- 0 -> finest
- 1 -> trace
- 2 -> debug
- 3 -> info
- 4 -> warning
- 5 -> error
- 6 -> fatal / emergency / critical

```
output {
 scalyr {
   api_write_token => 'SCALYR_API_KEY'
   ...
   severity_field => 'severity'
 }
}
```

In the example above, value for the DataSet severity field should be included in the ``severity``
Logstash event field.

In case the field value doesn't contain a valid severity number (0 - 6), ``sev`` field won't be
set on the event object to prevent API from rejecting an invalid request.

## Note On Server SSL Certificate Validation

By default when validating DataSet endpoint server SSL certificate, logstash uses CA certificate
bundles which is vendored / bundled with the RubyGem / plugin. This bundle includes CA certificate
files of authoried which are used to issue DataSet API endpoint certificates.

If you want to use system CA bundle, you should update ``ssl_ca_bundle_path`` to system CA bundle
path (e.g. ``/etc/ssl/certs/ca-certificates.crt``), as shown in the example below:

```
output {
 scalyr {
   api_write_token => 'SCALYR_API_KEY'
   ...
   ssl_ca_bundle_path => "/etc/ssl/certs/ca-certificates.crt"
 }
}
```


## Options

- The Scalyr API write token, these are available at https://www.scalyr.com/keys.  This is the only compulsory configuration field required for proper upload

`config :api_write_token, :validate => :string, :required => true`

---

- If you have an EU-based Scalyr account, please use https://eu.scalyr.com/

`config :scalyr_server, :validate => :string, :default => "https://agent.scalyr.com/"`

---

- Path to SSL CA bundle file which is used to verify the server certificate.

`config :ssl_ca_bundle_path, :validate => :string, :default => CA_CERTS_PATH`

If for some reason you need to disable server cert validation (you are strongly recommended to
not disable it unless specifically instructed to do so or have a valid reason for it), you can do
that by setting ``ssl_verify_peer`` config option to false.

---

- server_attributes is a dictionary of key value pairs that represents/identifies the logstash aggregator server
 (where this plugin is running).  Keys are arbitrary except for the 'serverHost' key which holds special meaning to
 Scalyr and is given special treatment in the Scalyr UI.  All of these attributes are optional (not required for logs
 to be correctly uploaded)

`config :server_attributes, :validate => :hash, :default => nil`

---

- Related to the server_attributes dictionary above, if you do not define the 'serverHost' key in server_attributes,
 the plugin will automatically set it, using the aggregator hostname as value, if this value is true.
 
`config :use_hostname_for_serverhost, :validate => :boolean, :default => true`

---

- Field that represents the origin of the log event. (Warning: events with an existing 'serverHost' field, it will be overwritten)

`config :serverhost_field, :validate => :string, :default => 'serverHost'`

---

- The 'logfile' fieldname has special meaning for the Scalyr UI.  Traditionally, it represents the origin logfile
 which users can search for in a dedicated widget in the Scalyr UI. If your Events capture this in a different field
 you can specify that fieldname here and the Scalyr Output Plugin will rename it to 'logfile' before upload.
 (Warning: events with an existing 'logfile' field, it will be overwritten)

`config :logfile_field, :validate => :string, :default => 'logfile'`

---

- The Scalyr Output Plugin expects the main log message to be contained in the Event['message'].  If your main log
 content is contained in a different field, specify it here.  It will be renamed to 'message' before upload.
 (Warning: events with an existing 'message' field, it will be overwritten)

`config :message_field, :validate => :string, :default => "message"`

---

- A list of fieldnames that are constant for any logfile. Any fields listed here will be sent to Scalyr as part of
 the `logs` array instead of inside every event to save on transmitted bytes. What constitutes a single "logfile"
 for correctness is a combination of logfile_field value and serverhost_field value. Only events with a serverHost
 value with have fields moved.

`config :log_constants, :validate => :array, :default => nil`

---

- If true, nested values will be flattened (which changes keys to underscore-separated concatenation of all
 nested keys).

`config :flatten_nested_values, :validate => :boolean, :default => false`

---

- If set, this will change the delimiter used when concatenating nested keys

`config :flatten_nested_values_delimiter, :validate => :string, :default => "_"`

---

- If true, the 'tags' field will be flattened into key-values where each key is a tag and each value is set to
 :flat_tag_value

`config :flatten_tags, :validate => :boolean, :default => false`

`config :flat_tag_prefix, :validate => :string, :default => 'tag_'`

`config :flat_tag_value, :default => 1`

---

- Initial interval in seconds between bulk retries. Doubled on each retry up to `retry_max_interval`

`config :retry_initial_interval, :validate => :number, :default => 1`

---

- Set max interval in seconds between bulk retries.

`config :retry_max_interval, :validate => :number, :default => 64`

---

- Valid options are bz2, deflate, or none.

`config :compression_type, :validate => :string, :default => 'deflate'`

---

- An int containing the compression level of compression to use, from 1-9. Defaults to 6

`config :compression_level, :validate => :number, :default => 6`

---

# Conceptual Overview

## Persistence

Logstash itself supports [Persistent Queues](https://www.elastic.co/guide/en/logstash/current/persistent-queues.html) with at-least-once delivery semantics.  It expects output plugins to retry uploads until success or else to write failures into a Dead-Letter Queue (DLQ). Since Logstash offers Persistent Queues, the Scalyr plugin does not perform its own buffering or persistence.  More specifically, invocation of `multi_receive` is synchronously retried until success or written to the DLQ upon failure.  Note: the `multi_receive` interface does not provide a feedback mechanism (outcome codes etc).

## Concurrency

The plugin does not manage its own internal concurrency - no threads are started to increase parallelism. To ensure correct ordering of events in Scalyr configure your pipeline with `pipeline.workers: 1`.

## Data model

Logstash Events are arbitrary nested JSON.  Scalyr, however, supports a flat key-value model.  Users are encouraged to pay attention to the mapping of Logstash Events to Scalyr key-values.

### Special fields

Scalyr assigns semantics to certain fields. These semantics allow Scalyr to know which field contains the main message, and also facilitates searching of data. For example, a user may restrict searches to specific combination of `serverHost` and `logfile` in the [Scalyr UI](https://www.scalyr.com/help/log-overview), whereby these 2 fields have dedicated input widgets in the UI.

Mapping/renaming of Logstash event fields to these special fields an important configuration step. For example, if the main message is contained in a field named `text_msg`, then you should configure the plugin's `message_field`  parameter to `text_msg`. This instructs the plugin to rename event `text_msg` to `message`, thus enabling the Scalyr backend to correctly receive the main log message.

Here is the Scalyr API data shape and a description of the special fields:
```
{
  "ts": <Time as epoch nanoseconds>
  "attrs": 
  {
    "message": <The main log message>
    "logfile": <Log file name (at the originating server) for the message>
    "serverHost": <The originating source/server for the message>
    "parser": <What Scalyr parser will be used for server side parsing>
    <Any other keys / values>
    ...
  }
}
```

You can use the `mutate` filter to add these fields or rename existing fields to them. Here is an example of a filter configuration you can use to add these fields:

```
filter {
    mutate {
        add_field => { "parser" => "logstash_parser" }
        add_field => { "serverHost" => "my hostname" }
        rename => { "path" => "logfile" }
        rename => { "data" => "message" }
    }
}
```

Note: the only required fields above are `ts` and `attrs/message`.  Omitting optional fields such as `serverHost` or `logfile` merely precludes ability to filter on these fields, but you are still able to search for the log event by any of the event's key/values including the main message field.


### Flattening nested values

By default, event attribute values that are nested JSON are converted into strings when uploaded to Scalyr.  However, flattening of nested values is supported. For example, the Logstash Event shape might be as follows:

```
{
  "message": "Some log line",
  "k1": "Key 1 value",
  "k2": {
    "A": 100,
    "B": "Some text",
  }
}
```

Without flattening, the event uploads to Scalyr as a log entry with 3 string values as follows:
```
{
  "message": "Some log line",
  "k1": "Key 1 value",
  "k2": "{ \"A\": 100, \"B\": \"Some text\" }"  
}
```

Whereas flattening will result in the following data shape:
```
{
  "message": "Some log line",
  "k1": "Key 1 value",
  "k2_A": 100,
  "k2_B": "Some text",
}
```

(Notice that multi-level keys are transformed to a flat key by concatenation with a separator.  The default separator is `-`, but is configurable to any character.)


## Flattening of nested arrays

Consider the following event where "key2" has a JSON array as its value:

```
{
  "message": "Some log line",
  "k1": "Key 1 value",
  "k2": [
    {
      "A": 100,
    }, 
    {
      "A": 200,
      "B": 300,
    }
  ] 
}
```

Without flattening, the event uploads to Scalyr as a log entry with 3 string values as follows:
```
{
  `message`: `Some log line`,
  "k1": "Key 1 value",
  "k2": "[{ 'A': 100 }, { 'A': 200, 'B': 300 }]"
}
```

Whereas flattening will result in the following data shape:
```
{
  "message": "Some log line",
  "k1": "Key 1 value",
  "k2_0_A: 100,
  "k2_1_A": 200,
  "k2_1_B": 300,
}
```

## Log attributes

If every message that comes from the same `logfile` and `serverHost` has fields that stay constant for that logfile and serverHost you can define this as a log constant. 
Any fields marked as such will be sent only once per request to scalyr for a serverhost and logfile, which can result in better throughput due to fewer bytes sent.

# Testing

## Smoke test

This repo has been configured to run a full-cycle smoketest on CircleCI as follows:

1. Build the gem
2. Configure a logstash docker image with pipeline that has file input & Scalyr output
3. Launch a lightweight "Uploader" docker container that verifies the plugin is active, then writes to a bind-mounted file.  (The bind-mounted file is configured as the input source to Logstash.)
4. Launch a lightweight "Verifier" docker container that verifies the plugin is active, then executes queries against Scalyr to verify that the Logstash/Scalyr output plugin had uploaded events from the bind-mounted input file to Scalyr. 

## Unit tests

This repo has unit tests that can be run by running:

```
sudo bundle exec rspec
```

in the root of the repo.

By default this will run all the tests (including integration ones which require sudo access and
may not pass everywhere).

If you want to run just the unit tests, you can run the command displayed below.


```bash
bundle exec rspec spec/logstash/outputs/scalyr_spec.rb spec/scalyr/common/util_spec.rb
```

Or to run a single test function defined on line XXX

```bash
bundle exec rspec spec/scalyr/common/util_spec.rb:XXX
```

Or using more verbose output mode:

```bash
bundle exec rspec -fd spec/scalyr/common/util_spec.rb
```

## Instrumentation and metrics

By default, plugin logs a special line with metrics to Scalyr every 5 minutes. This line contains
various batch, request and event level metrics.

Example line is shown below:

```bash
plugin_status: total_requests_sent=6 total_requests_failed=0 total_request_bytes_sent=240586 total_compressed_request_bytes_sent=6396 total_response_bytes_received=222 total_request_latency_secs=1.018 total_serialization_duration_secs=0.024 total_compression_duration_secs=0.046 compression_type=deflate compression_level=6 request_latency_p50=0.048 request_latency_p90=0.104 request_latency_p99=0.104 serialization_duration_secs_p50=0.003 serialization_duration_secs_p90=0.005 serialization_duration_secs_p99=0.005 compression_duration_secs_p50=0.006 compression_duration_secs_p90=0.013 compression_duration_secs_p99=0.013 bytes_sent_p50=40116 bytes_sent_p90=40116 bytes_sent_p99=40116 total_multi_receive_secs=1.404 multi_receive_duration_p50=0.083 multi_receive_duration_p90=0.192 multi_receive_duration_p99=0.192 multi_receive_event_count_p50=100 multi_receive_event_count_p90=100 multi_receive_event_count_p99=100 event_attributes_count_p50=8 event_attributes_count_p90=8 event_attributes_count_p99=8 flatten_values_duration_secs_p50=0 flatten_values_duration_secs_p90=0 flatten_values_duration_secs_p99=0
```

Those lines also have ``logstash_plugin_metrics`` ``parser`` attribute defined which means you
can easily parse them using a parser definition similar to the one below.

```javascript
{
    patterns: {
      nonQuoted: "[^\"\n ]+"
  },

  formats: [
    {
      format: ".* $_=identifier$=$_=nonQuoted$", repeat: true
    }
  ]
}
```

Do keep in mind that this line contains quite a lot of metrics so parsing it may make it more likely
to hit server side defined per 5 minute period unique number of attributes limit in case you are already
very close to tke limit.

For various request level metrics we track totals (either counts or duration). Those metrics names start
with ``total_`` (e.g. ``total_requests_failed``). To be able to derive average per request values you
can do that by dividing the total value with the value of ``total_requests_sent`` metrics.

Because averages are not all that useful we also track percentiles for various request, batch and
event level metrics. Those metrics names end with ``_p{percentile}``. For example ``_p50`` represents
50th percentile and ``_p99`` represents 99th percentile (e.g. ``request_latency_p99``).

If you want to change status reporting interval you can do that by changing the
``status_report_interval`` config option (in seconds).

# Releasing

## Updating version

Currently references to the version need to be manually updated, files to look in for this are `logstash-putput-scalyr.gemspec`,
 `lib/scalyr/constants.rb`, and under "Quick Start" in this `README.md`.

The changelog should also be updated with the latest version and changes of note.

## Releasing to RubyGems.org

To deploy the current code on your machine run these commands:

```
rm -rf vendor/
bundle install
curl -u RUBY_USER:RUBY_PASSWORD https://rubygems.org/api/v1/api_key.yaml > ~/.gem/credentials
chmod 0600 ~/.gem/credentials
bundle exec rspec
bundle exec rake publish_gem
```

Or as an alternative if ``rake publish_gem`` task doesn't appear to work for whatever reason
(``publish_gem`` logstash Rake task silently swallows all the errors):

```
rm -rf vendor/
bundle install
curl -u RUBY_USER:RUBY_PASSWORD https://rubygems.org/api/v1/api_key.yaml > ~/.gem/credentials
chmod 0600 ~/.gem/credentials
bundle exec rspec
rvm use jruby
bundle exec gem build logstash-output-scalyr.gemspec
bundle exec gem push logstash-output-scalyr-<version>.gem
```

`RUBY_USER` and `RUBY_PASSWORD` should be replaced with the username and password to the RubyGems.org account you wish to release to,
 these credentials should be found in Keeper.

# Testing Plugin Changes

This section describes how to test the plugin and changes using docker compose setup from
lostash-config-tester repo available at https://github.com/Kami/logstash-config-tester.

This repo has been forked and already contains some changes which make testing the plugin
easier.

The logstash configuration in that repo is set up to receive records encoded as JSON via
standard input, decode the JSON into the event object and print it to stdout + send it
to the Scalyr output.

```bash
# 0. Clone the tester repo
git clone https://github.com/Kami/logstash-config-tester ~/

# 1. Build the plugin
gem build logstash-output-scalyr.gemspec

# 2. Copy it to the config test repo
cp logstash-output-scalyr-0.2.6.gem ~/logstash-config-test/logstash-output-scalyr.gem

# 3. Build docker image with the latest dev version of the plugin (may take a while)
docker-compose build

# 4. Configure API key in docker-compose.yml and make any changes to plugin config in
# pipeline/scalyr_output.conf.j2, if necessary
vim docker-compose.yml

vim pipeline/scalyr_output.conf.j2

# 4. Run logstash with the stdin input and stdout + scalyr output
docker-compose run logstash
```

A couple of things to keep in mind:

1. Logstash log level is set to debug which is quite verbose, but it makes troubleshooting and
  testing easier.
2. Plugin accepts records (events) as JSON via standard input. This means to inject the mock
   event you can simply copy the JSON event representation string to stdin and press enter. If you
   want to submit multiples events to be handled as a single batch, paste each event one at a time
   and press enter at the end. Logstash pipeline has been configured to wait up to 5 seconds before
   handling the batch which should give you enough time to test batches with multiple events (this
   setting can be adjusted in ``config/logstash.yml`` - ``pipeline.batch.delay``, if needed)

Example values you can enter into stdin:

1. Single event batch

```javascript
{"foo": "bar", "message": "test logstash"}
```

2. Batch with 3 events

```javascript
{"serverHost": "host-1", "bar": "baz", "message": "test logstash 1"}
{"serverHost": "host-2", "bar": "baz", "message": "test logstash 2"}
{"bar": "baz", "message": "test logstash 3"}
```
