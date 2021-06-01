# encoding: utf-8
require "logstash/devutils/rspec/spec_helper"
require "logstash/outputs/scalyr"
require "logstash/codecs/plain"
require "logstash/event"
require "json"


class MockClientSession
  DEFAULT_STATS = {
    :total_requests_sent => 20,
    :total_requests_failed => 10,
    :total_request_bytes_sent => 100,
    :total_compressed_request_bytes_sent => 50,
    :total_response_bytes_received => 100,
    :total_request_latency_secs => 100,
    :total_connections_created => 10,
    :total_serialization_duration_secs => 100.5,
    :total_compression_duration_secs => 10.20,
    :total_flatten_values_duration_secs => 33.3,
    :compression_type => "deflate",
    :compression_level => 9,
  }

  def initialize(stats = DEFAULT_STATS)
    @stats = stats
    @sent_events = []
  end

  def get_stats
    @stats.clone
  end

  def post_add_events(body, body_serialization_duration = 0)
    @sent_events << body
  end
end


describe LogStash::Outputs::Scalyr do
  let(:sample_events) {
    events = []
    for i in 1..3 do
      e = LogStash::Event.new
      e.set('source_host', "my host #{i}")
      e.set('source_file', "my file #{i}")
      e.set('seq', i)
      e.set('nested', {'a'=>1, 'b'=>[3,4,5]})
      e.set('tags', ['t1', 't2', 't3'])
      events.push(e)
    end
    events
  }

  describe "#build_multi_event_request_array" do

    context "test get_stats and send_status" do
      plugin = LogStash::Outputs::Scalyr.new({
                                                     'api_write_token' => '1234',
                                                     'serverhost_field' => 'source_host',
                                                     'log_constants' => ['tags'],
                                                 })

      mock_client_session = MockClientSession.new

      it "returns correct stats on get_stats" do
        stats = mock_client_session.get_stats
        expect(stats[:total_requests_sent]).to eq(20)
      end

      it "returns and sends correct status event on send_stats on initial and subsequent send" do
        # 1. Initial send
        plugin.instance_variable_set(:@last_status_transmit_time, nil)
        plugin.instance_variable_set(:@client_session, mock_client_session)
        status_event = plugin.send_status
        expect(status_event[:attrs]["message"]).to eq("Started Scalyr LogStash output plugin.")

        # 2. Second send
        plugin.instance_variable_set(:@last_status_transmit_time, 100)
        plugin.instance_variable_set(:@client_session, mock_client_session)
        status_event = plugin.send_status
        puts
        expect(status_event[:attrs]["message"]).to eq("plugin_status: total_requests_sent=20, total_requests_failed=10, total_request_bytes_sent=100, total_compressed_request_bytes_sent=50, total_response_bytes_received=100, total_request_latency_secs=100, total_connections_created=10, total_serialization_duration_secs=100.5, total_compression_duration_secs=10.2, total_flatten_values_duration_secs=33.3, compression_type=deflate, compression_level=9")
      end
    end

    context "when a field is configured as a log attribute" do
      it "creates logfile from serverHost" do
        plugin = LogStash::Outputs::Scalyr.new({
                                                   'api_write_token' => '1234',
                                                   'serverhost_field' => 'source_host',
                                                   'log_constants' => ['tags'],
                                               })
        allow(plugin).to receive(:send_status).and_return(nil)
        plugin.register
        result = plugin.build_multi_event_request_array(sample_events)
        body = JSON.parse(result[0][:body])
        expect(body['events'].size).to eq(3)
        logattrs2 = body['logs'][2]['attrs']
        expect(logattrs2.fetch('serverHost', nil)).to eq('my host 3')
        expect(logattrs2.fetch('logfile', nil)).to eq('/logstash/my host 3')
        expect(logattrs2.fetch('tags', nil)).to eq(['t1', 't2', 't3'])
      end
    end

    context "when serverhost_field is missing" do
      it "does not contain log file" do
        plugin = LogStash::Outputs::Scalyr.new({'api_write_token' => '1234'})
        allow(plugin).to receive(:send_status).and_return(nil)
        plugin.register
        result = plugin.build_multi_event_request_array(sample_events)
        body = JSON.parse(result[0][:body])
        expect(body['events'].size).to eq(3)
        expect(body['events'][2]['attrs'].fetch('logfile', nil)).to eq(nil)
      end
    end

    context "when serverhost_field is present (or mapped)" do
      it "creates logfile from serverHost" do
        plugin = LogStash::Outputs::Scalyr.new({
                                                   'api_write_token' => '1234',
                                                   'serverhost_field' => 'source_host',
                                               })
        allow(plugin).to receive(:send_status).and_return(nil)
        plugin.register
        result = plugin.build_multi_event_request_array(sample_events)
        body = JSON.parse(result[0][:body])
        expect(body['events'].size).to eq(3)
        logattrs2 = body['logs'][2]['attrs']
        expect(logattrs2.fetch('serverHost', nil)).to eq('my host 3')
        expect(logattrs2.fetch('logfile', nil)).to eq('/logstash/my host 3')
      end
    end

    context "when serverhost_field and logfile are present (or mapped)" do
      it "does not contain log file" do
        plugin = LogStash::Outputs::Scalyr.new({
                                                   'api_write_token' => '1234',
                                                   'serverhost_field' => 'source_host',
                                                   'logfile_field' => 'source_file',
                                               })
        allow(plugin).to receive(:send_status).and_return(nil)
        plugin.register
        result = plugin.build_multi_event_request_array(sample_events)
        body = JSON.parse(result[0][:body])
        expect(body['events'].size).to eq(3)
        logattrs2 = body['logs'][2]['attrs']
        expect(logattrs2.fetch('serverHost', nil)).to eq('my host 3')
        expect(logattrs2.fetch('logfile', nil)).to eq('my file 3')
      end
    end

    context "when configured to flatten values with custom delimiter" do
      config = {
          'api_write_token' => '1234',
          'flatten_tags' => true,
          'flat_tag_value' => 'true',
          'flat_tag_prefix' => 'tag_prefix_',
          'flatten_nested_values' => true,  # this converts into string 'true'
          'flatten_nested_values_delimiter' => ".",
      }
      plugin = LogStash::Outputs::Scalyr.new(config)
      it "flattens nested values with a period" do
        allow(plugin).to receive(:send_status).and_return(nil)
        plugin.register
        result = plugin.build_multi_event_request_array(sample_events)
        body = JSON.parse(result[0][:body])
        expect(body['events'].size).to eq(3)
        expect(body['events'][2]['attrs']).to eq({
                                                     "nested.a" => 1,
                                                     "nested.b_0" => 3,
                                                     "nested.b_1" => 4,
                                                     "nested.b_2" => 5,
                                                     'seq' => 3,
                                                     'source_file' => 'my file 3',
                                                     'source_host' => 'my host 3',
                                                     'serverHost' => 'Logstash',
                                                     "tag_prefix_t1" => "true",
                                                     "tag_prefix_t2" => "true",
                                                     "tag_prefix_t3" => "true",
                                                     "parser" => "logstashParser",
                                                 })
      end
    end

    context "when configured to flatten values and tags" do
      config = {
          'api_write_token' => '1234',
          'flatten_tags' => true,
          'flat_tag_value' => 'true',
          'flat_tag_prefix' => 'tag_prefix_',
          'flatten_nested_values' => true,  # this converts into string 'true'
      }
      plugin = LogStash::Outputs::Scalyr.new(config)
      it "flattens nested values and flattens tags" do
        allow(plugin).to receive(:send_status).and_return(nil)
        plugin.register
        result = plugin.build_multi_event_request_array(sample_events)
        body = JSON.parse(result[0][:body])
        expect(body['events'].size).to eq(3)
        expect(body['events'][2]['attrs']).to eq({
                                                     "nested_a" => 1,
                                                     "nested_b_0" => 3,
                                                     "nested_b_1" => 4,
                                                     "nested_b_2" => 5,
                                                     'seq' => 3,
                                                     'source_file' => 'my file 3',
                                                     'source_host' => 'my host 3',
                                                     'serverHost' => 'Logstash',
                                                     "tag_prefix_t1" => "true",
                                                     "tag_prefix_t2" => "true",
                                                     "tag_prefix_t3" => "true",
                                                     "parser" => "logstashParser",
                                                 })
      end
    end

    context "when not configured to flatten values and tags" do
      config = {
          'api_write_token' => '1234',
      }
      plugin = LogStash::Outputs::Scalyr.new(config)
      it "does not flatten" do
        allow(plugin).to receive(:send_status).and_return(nil)
        plugin.register
        result = plugin.build_multi_event_request_array(sample_events)
        body = JSON.parse(result[0][:body])
        expect(body['events'].size).to eq(3)
        expect(body['events'][2]['attrs']).to eq({
                                                     "nested" => {'a'=>1, 'b'=>[3,4,5]},
                                                     'seq' => 3,
                                                     'source_file' => 'my file 3',
                                                     'source_host' => 'my host 3',
                                                     'serverHost' => 'Logstash',
                                                     "tags" => ["t1", "t2", "t3"],
                                                     "parser" => "logstashParser",
                                                 })
      end
    end
  end
end
