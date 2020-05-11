
[![CircleCI](https://circleci.com/gh/scalyr/logstash-output-scalyr.svg?style=svg)](https://circleci.com/gh/scalyr/logstash-output-scalyr)

# [Scalyr output plugin for Logstash (Alpha release)]

This plugin implements a Logstash output plugin that uploads data to [Scalyr](http://www.scalyr.com).

# Quick start

1. Build the gem, run `gem build logstash-output-scalyr.gemspec` 
2. Install the gem into a Logstash installation, run `/usr/share/logstash/bin/logstash-plugin install logstash-output-scalyr-1.0.0.pre.alpha.gem` or follow the latest official instructions on working with plugins from Logstash.
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
    <Any other keys / values>
    ...
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
bundle exec rspec
```

in the root of the repo.
