# encoding: utf-8
require "logstash/devutils/rspec/spec_helper"
require "logstash/outputs/scalyr"
require "logstash/codecs/plain"
require "logstash/event"
require "json"
require "quantile"

# Require the specific version of `json` used in logstash
gem 'json', '2.6.2'

JSON_GEM_VERSION = Gem.loaded_specs["json"].version.to_s

NODE_HOSTNAME = Socket.gethostname

class MockClientSession
  DEFAULT_STATS = {
    :total_requests_sent => 20,
    :total_requests_failed => 10,
    :total_request_bytes_sent => 100,
    :total_compressed_request_bytes_sent => 50,
    :total_response_bytes_received => 100,
    :total_request_latency_secs => 100,
    :total_serialization_duration_secs => 100.5,
    :total_compression_duration_secs => 10.20,
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

  def post_add_events(body, _is_status, body_serialization_duration = 0)
    @sent_events << { :body => body, :body_serialization_duration => body_serialization_duration }
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

  let(:sample_events_with_severity) {
    events = []
    for i in 0..6 do
      # valid severity - integer
      e = LogStash::Event.new
      e.set('source_host', "my host #{i}")
      e.set('source_file', "my file #{i}")
      e.set('severity', i)
      e.set('seq', i)
      e.set('nested', {'a'=>1, 'b'=>[3,4,5]})
      e.set('tags', ['t1', 't2', 't3'])
      events.push(e)
    end
    for i in 0..6 do
      # valid severity - string
      e = LogStash::Event.new
      e.set('source_host', "my host #{i}")
      e.set('source_file', "my file #{i}")
      e.set('severity', i.to_s)
      e.set('seq', i)
      e.set('nested', {'a'=>1, 'b'=>[3,4,5]})
      e.set('tags', ['t1', 't2', 't3'])
      events.push(e)
    end

    # invalid severity values
    e = LogStash::Event.new
    e.set('source_host', "my host a")
    e.set('severity', -1)
    events.push(e)

    e = LogStash::Event.new
    e.set('source_host', "my host a")
    e.set('severity', 7)
    events.push(e)

    e = LogStash::Event.new
    e.set('source_host', "my host a")
    e.set('severity', "invalid")
    events.push(e)

    events
  }

  let(:sample_events_with_level) {
    events = []
    for i in 0..6 do
      e = LogStash::Event.new
      e.set('source_host', "my host #{i}")
      e.set('source_file', "my file #{i}")
      e.set('level', i)
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
                                                     'perform_connectivity_check' => false,
                                                     'serverhost_field' => 'source_host',
                                                     'log_constants' => ['tags'],
                                                     'flatten_nested_values' => true,
                                                 })
      plugin.register

      mock_client_session = MockClientSession.new

      it "returns correct stats on get_stats" do
        stats = mock_client_session.get_stats
        expect(stats[:total_requests_sent]).to eq(20)
      end

      it "it doesnt include flatten metrics if flattening is disabled" do
        plugin1 = LogStash::Outputs::Scalyr.new({
                                                     'api_write_token' => '1234',
                                                     'perform_connectivity_check' => false,
                                                     'serverhost_field' => 'source_host',
                                                     'log_constants' => ['tags'],
                                                     'flatten_nested_values' => false,
                                                 })
        plugin1.register()
        mock_client_session = MockClientSession.new
        plugin1.instance_variable_set(:@last_status_transmit_time, 100)
        plugin1.instance_variable_set(:@client_session, mock_client_session)
        plugin1.instance_variable_set(:@session_id, "some_session_id")
        plugin1.instance_variable_set(:@plugin_metrics, {
          :build_multi_duration_secs => Quantile::Estimator.new,
          :multi_receive_duration_secs => Quantile::Estimator.new,
          :multi_receive_event_count => Quantile::Estimator.new,
          :event_attributes_count =>  Quantile::Estimator.new,
          :flatten_values_duration_secs => Quantile::Estimator.new,
          :batches_per_multi_receive => Quantile::Estimator.new
        })
        plugin1.instance_variable_get(:@plugin_metrics)[:multi_receive_duration_secs].observe(1)
        plugin1.instance_variable_get(:@plugin_metrics)[:build_multi_duration_secs].observe(1)
        plugin1.instance_variable_set(:@multi_receive_statistics, {:total_multi_receive_secs => 0})

        status_event = plugin1.send_status
        expect(status_event[:attrs]["message"]).to eq("plugin_status: total_requests_sent=20 total_requests_failed=10 total_request_bytes_sent=100 total_compressed_request_bytes_sent=50 total_response_bytes_received=100 total_request_latency_secs=100 total_serialization_duration_secs=100.5000 total_compression_duration_secs=10.2000 compression_type=deflate compression_level=9 total_multi_receive_secs=0 build_multi_duration_secs_p50=1 build_multi_duration_secs_p90=1 build_multi_duration_secs_p99=1 multi_receive_duration_p50=1 multi_receive_duration_p90=1 multi_receive_duration_p99=1 multi_receive_event_count_p50=0 multi_receive_event_count_p90=0 multi_receive_event_count_p99=0 event_attributes_count_p50=0 event_attributes_count_p90=0 event_attributes_count_p99=0 batches_per_multi_receive_p50=0 batches_per_multi_receive_p90=0 batches_per_multi_receive_p99=0")
      end

      it "returns and sends correct status event on send_stats on initial and subsequent send" do
        # 1. Initial send
        plugin.instance_variable_set(:@last_status_transmit_time, nil)
        plugin.instance_variable_set(:@client_session, mock_client_session)
        plugin.instance_variable_set(:@session_id, "some_session_id")
        status_event = plugin.send_status
        expect(status_event[:attrs]["message"]).to eq("Started Scalyr LogStash output plugin %s (compression_type=deflate,compression_level=deflate,json_library=stdlib)." % [PLUGIN_VERSION])

        # 2. Second send
        plugin.instance_variable_set(:@last_status_transmit_time, 100)
        plugin.instance_variable_set(:@client_session, mock_client_session)
        # Setup one quantile calculation to make sure at least one of them calculates as expected
        plugin.instance_variable_set(:@plugin_metrics, {
          :build_multi_duration_secs => Quantile::Estimator.new,
          :multi_receive_duration_secs => Quantile::Estimator.new,
          :multi_receive_event_count => Quantile::Estimator.new,
          :event_attributes_count =>  Quantile::Estimator.new,
          :flatten_values_duration_secs => Quantile::Estimator.new,
          :batches_per_multi_receive => Quantile::Estimator.new
        })

        (1..20).each do |n|
          plugin.instance_variable_get(:@plugin_metrics)[:multi_receive_duration_secs].observe(n)
        end

        plugin.instance_variable_set(:@multi_receive_statistics, {:total_multi_receive_secs => 0})
        status_event = plugin.send_status
        expect(status_event[:attrs]["message"]).to eq("plugin_status: total_requests_sent=20 total_requests_failed=10 total_request_bytes_sent=100 total_compressed_request_bytes_sent=50 total_response_bytes_received=100 total_request_latency_secs=100 total_serialization_duration_secs=100.5000 total_compression_duration_secs=10.2000 compression_type=deflate compression_level=9 total_multi_receive_secs=0 build_multi_duration_secs_p50=0 build_multi_duration_secs_p90=0 build_multi_duration_secs_p99=0 multi_receive_duration_p50=10 multi_receive_duration_p90=18 multi_receive_duration_p99=19 multi_receive_event_count_p50=0 multi_receive_event_count_p90=0 multi_receive_event_count_p99=0 event_attributes_count_p50=0 event_attributes_count_p90=0 event_attributes_count_p99=0 batches_per_multi_receive_p50=0 batches_per_multi_receive_p90=0 batches_per_multi_receive_p99=0 flatten_values_duration_secs_p50=0 flatten_values_duration_secs_p90=0 flatten_values_duration_secs_p99=0")
      end

      it "send_stats is called when events list is empty, but otherwise is noop" do
        quantile_estimator = Quantile::Estimator.new
        plugin.instance_variable_set(:@plugin_metrics, {
          :build_multi_duration_secs => Quantile::Estimator.new,
          :multi_receive_duration_secs => Quantile::Estimator.new,
          :multi_receive_event_count => Quantile::Estimator.new,
          :event_attributes_count => Quantile::Estimator.new,
          :flatten_values_duration_secs => Quantile::Estimator.new
        })
        plugin.instance_variable_set(:@client_session, mock_client_session)
        expect(plugin).to receive(:send_status)
        expect(quantile_estimator).not_to receive(:observe)
        expect(mock_client_session).not_to receive(:post_add_events)
        plugin.multi_receive([])
      end

      it "send_stats is not called when events list is empty and report_status_for_empty_batches is false" do
        plugin2 = LogStash::Outputs::Scalyr.new({
                                                     'api_write_token' => '1234',
                                                     'perform_connectivity_check' => false,
                                                     'serverhost_field' => 'source_host',
                                                     'log_constants' => ['tags'],
                                                     'flatten_nested_values' => false,
                                                     'report_status_for_empty_batches' => false,
                                                 })

        mock_client_session = MockClientSession.new
        quantile_estimator = Quantile::Estimator.new
        plugin2.instance_variable_set(:@plugin_metrics, {
          :build_multi_duration_secs => Quantile::Estimator.new,
          :multi_receive_duration_secs => Quantile::Estimator.new,
          :multi_receive_event_count => Quantile::Estimator.new,
          :event_attributes_count => Quantile::Estimator.new,
          :flatten_values_duration_secs => Quantile::Estimator.new
        })
        plugin2.instance_variable_set(:@client_session, mock_client_session)
        expect(plugin2).not_to receive(:send_status)
        expect(quantile_estimator).not_to receive(:observe)
        expect(mock_client_session).not_to receive(:post_add_events)
        plugin2.multi_receive([])
      end

      # Kind of a weak test but I don't see a decent way to write a stronger one without a live client session
      it "send_status only sends posts with is_status = true" do
        # 1. Initial send
        plugin.instance_variable_set(:@last_status_transmit_time, nil)
        plugin.instance_variable_set(:@client_session, mock_client_session)
        plugin.instance_variable_set(:@session_id, "some_session_id")
        expect(mock_client_session).to receive(:post_add_events).with(anything, true, anything)
        plugin.send_status

        # 2. Second send
        plugin.instance_variable_set(:@last_status_transmit_time, 100)
        plugin.instance_variable_set(:@client_session, mock_client_session)
        plugin.instance_variable_set(:@plugin_metrics, {
          :build_multi_duration_secs => Quantile::Estimator.new,
          :multi_receive_duration_secs => Quantile::Estimator.new,
          :multi_receive_event_count => Quantile::Estimator.new,
          :event_attributes_count =>  Quantile::Estimator.new,
          :flatten_values_duration_secs => Quantile::Estimator.new,
          :batches_per_multi_receive => Quantile::Estimator.new
        })
        (1..20).each do |n|
          plugin.instance_variable_get(:@plugin_metrics)[:multi_receive_duration_secs].observe(n)
        end
        plugin.instance_variable_set(:@multi_receive_statistics, {:total_multi_receive_secs => 0})
        expect(mock_client_session).to receive(:post_add_events).with(anything, true, anything)
        plugin.send_status
      end
    end

    context "when a field is configured as a log attribute" do
      it "creates logfile from serverHost" do
        plugin = LogStash::Outputs::Scalyr.new({
                                                   'api_write_token' => '1234',
                                                   'perform_connectivity_check' => false,
                                                   'serverhost_field' => 'source_host',
                                                   'log_constants' => ['tags'],
                                               })
        allow(plugin).to receive(:send_status).and_return(nil)
        plugin.register
        result = plugin.build_multi_event_request_array(sample_events)
        body = JSON.parse(result[0][:body])
        expect(body['events'].size).to eq(3)
        logattrs2 = body['logs'][2]['attrs']
        expect(logattrs2.fetch(EVENT_LEVEL_SERVER_HOST_ATTRIBUTE_NAME, nil)).to eq('my host 3')
        expect(logattrs2.fetch('logfile', nil)).to eq('/logstash/my host 3')
        expect(logattrs2.fetch('tags', nil)).to eq(['t1', 't2', 't3'])
      end
    end

    context "when severity field is configured" do
      it "works correctly when severity event attribute is specified" do
        plugin = LogStash::Outputs::Scalyr.new({
                                                   'api_write_token' => '1234',
                                                   'perform_connectivity_check' => false,
                                                   'severity_field' => 'severity',
                                               })
        allow(plugin).to receive(:send_status).and_return(nil)
        plugin.register
        result = plugin.build_multi_event_request_array(sample_events_with_severity)
        body = JSON.parse(result[0][:body])
        expect(body['events'].size).to eq(7 + 7 + 3)

        (0..6).each do |index|
          expect(body['events'][index]['attrs'].fetch('severity', nil)).to eq(nil)
          expect(body['events'][index]['attrs'].fetch('sev', nil)).to eq(nil)
          expect(body['events'][index]['sev']).to eq(index)
        end

        (7..13).each do |index|
          expect(body['events'][index]['attrs'].fetch('severity', nil)).to eq(nil)
          expect(body['events'][index]['attrs'].fetch('sev', nil)).to eq(nil)
          expect(body['events'][index]['sev']).to eq(index - 7)
        end

        expect(body['events'][14]['attrs'].fetch('severity', nil)).to eq(-1)
        expect(body['events'][14].key?("sev")).to eq(false)
        expect(body['events'][14]['sev']).to eq(nil)
        expect(body['events'][15]['attrs'].fetch('severity', nil)).to eq(7)
        expect(body['events'][15].key?("sev")).to eq(false)
        expect(body['events'][15]['sev']).to eq(nil)
        expect(body['events'][16]['attrs'].fetch('severity', nil)).to eq("invalid")
        expect(body['events'][16].key?("sev")).to eq(false)
        expect(body['events'][16]['sev']).to eq(nil)
      end

      it "works correctly when level event attribute is specified" do
        plugin = LogStash::Outputs::Scalyr.new({
                                                   'api_write_token' => '1234',
                                                   'perform_connectivity_check' => false,
                                                   'severity_field' => 'level',
                                               })
        allow(plugin).to receive(:send_status).and_return(nil)
        plugin.register
        result = plugin.build_multi_event_request_array(sample_events_with_level)
        body = JSON.parse(result[0][:body])
        expect(body['events'].size).to eq(7)

        (0..6).each do |index|
          expect(body['events'][index]['attrs'].fetch('level', nil)).to eq(nil)
          expect(body['events'][index]['attrs'].fetch('severity', nil)).to eq(nil)
          expect(body['events'][index]['attrs'].fetch('sev', nil)).to eq(nil)
          expect(body['events'][index]['sev']).to eq(index)
        end
      end

      it "works correctly when severity event attribute is not specified" do
        plugin = LogStash::Outputs::Scalyr.new({
                                                   'api_write_token' => '1234',
                                                   'perform_connectivity_check' => false,
                                                   'severity_field' => 'severity',
                                               })
        allow(plugin).to receive(:send_status).and_return(nil)
        plugin.register
        result = plugin.build_multi_event_request_array(sample_events)
        body = JSON.parse(result[0][:body])
        expect(body['events'].size).to eq(3)

        (0..2).each do |index|
          expect(body['events'][index]['attrs'].fetch('severity', nil)).to eq(nil)
          expect(body['events'][index]['attrs'].fetch('sev', nil)).to eq(nil)
          expect(body['events'][index]['sev']).to eq(nil)
        end
      end

      it "works correctly when severity event attribute is not specified but severity field is not set" do
        # Since severity_field config option is not set, severity field should be treated as a
        # regular event attribute and not as s a special top level Event.sev field
        plugin = LogStash::Outputs::Scalyr.new({
                                                   'api_write_token' => '1234',
                                                   'perform_connectivity_check' => false,
                                                   'severity_field' => nil,
                                               })
        allow(plugin).to receive(:send_status).and_return(nil)
        plugin.register
        result = plugin.build_multi_event_request_array(sample_events_with_severity)
        body = JSON.parse(result[0][:body])
        expect(body['events'].size).to eq(7 + 7 + 3)

        (0..6).each do |index|
          expect(body['events'][index]['attrs'].fetch('severity', nil)).to eq(index)
          expect(body['events'][index]['sev']).to eq(nil)
        end

        (7..13).each do |index|
          expect(body['events'][index]['attrs'].fetch('severity', nil)).to eq((index - 7).to_s)
          expect(body['events'][index]['sev']).to eq(nil)
        end

        expect(body['events'][14]['attrs'].fetch('severity', nil)).to eq(-1)
        expect(body['events'][14].key?("sev")).to eq(false)
        expect(body['events'][14]['sev']).to eq(nil)
        expect(body['events'][15]['attrs'].fetch('severity', nil)).to eq(7)
        expect(body['events'][15].key?("sev")).to eq(false)
        expect(body['events'][15]['sev']).to eq(nil)
        expect(body['events'][16]['attrs'].fetch('severity', nil)).to eq("invalid")
        expect(body['events'][16].key?("sev")).to eq(false)
        expect(body['events'][16]['sev']).to eq(nil)
      end
    end

    context "when serverhost_field is missing" do
      it "does not contain log file" do
        plugin = LogStash::Outputs::Scalyr.new({'api_write_token' => '1234', 'perform_connectivity_check' => false})
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
                                                   'perform_connectivity_check' => false,
                                                   'serverhost_field' => 'source_host',
                                               })
        allow(plugin).to receive(:send_status).and_return(nil)
        plugin.register
        result = plugin.build_multi_event_request_array(sample_events)
        body = JSON.parse(result[0][:body])
        expect(body['events'].size).to eq(3)
        logattrs2 = body['logs'][2]['attrs']
        expect(logattrs2.fetch(EVENT_LEVEL_SERVER_HOST_ATTRIBUTE_NAME, nil)).to eq('my host 3')
        expect(logattrs2.fetch('logfile', nil)).to eq('/logstash/my host 3')
      end
    end

    context "when serverhost_field and logfile are present (or mapped)" do
      it "does not contain log file" do
        plugin = LogStash::Outputs::Scalyr.new({
                                                   'api_write_token' => '1234',
                                                   'perform_connectivity_check' => false,
                                                   'serverhost_field' => 'source_host',
                                                   'logfile_field' => 'source_file',
                                               })
        allow(plugin).to receive(:send_status).and_return(nil)
        plugin.register
        result = plugin.build_multi_event_request_array(sample_events)
        body = JSON.parse(result[0][:body])
        expect(body['events'].size).to eq(3)
        logattrs2 = body['logs'][2]['attrs']
        expect(logattrs2.fetch(EVENT_LEVEL_SERVER_HOST_ATTRIBUTE_NAME, nil)).to eq('my host 3')
        expect(logattrs2.fetch('logfile', nil)).to eq('my file 3')
      end
    end

    context "when configured to flatten values with custom delimiter" do
      config = {
          'api_write_token' => '1234',
          'perform_connectivity_check' => false,
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
                                                     "tag_prefix_t1" => "true",
                                                     "tag_prefix_t2" => "true",
                                                     "tag_prefix_t3" => "true",
                                                     "parser" => "logstashParser",
                                                 })
      end
    end

    context "when configured to flatten values with custom delimiter and deep delimiter fix" do
      config = {
          'api_write_token' => '1234',
          'perform_connectivity_check' => false,
          'flatten_tags' => true,
          'flat_tag_value' => 'true',
          'flat_tag_prefix' => 'tag_prefix_',
          'flatten_nested_values' => true,  # this converts into string 'true'
          'flatten_nested_values_delimiter' => ".",
          'fix_deep_flattening_delimiters' => true,
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
                                                     "nested.b.0" => 3,
                                                     "nested.b.1" => 4,
                                                     "nested.b.2" => 5,
                                                     'seq' => 3,
                                                     'source_file' => 'my file 3',
                                                     'source_host' => 'my host 3',
                                                     "tag_prefix_t1" => "true",
                                                     "tag_prefix_t2" => "true",
                                                     "tag_prefix_t3" => "true",
                                                     "parser" => "logstashParser",
                                                 })
      end
    end

    context "when configured to flatten values with custom delimiter, no array flattening" do
      config = {
          'api_write_token' => '1234',
          'perform_connectivity_check' => false,
          'flatten_tags' => true,
          'flat_tag_value' => 'true',
          'flat_tag_prefix' => 'tag_prefix_',
          'flatten_nested_values' => true,  # this converts into string 'true'
          'flatten_nested_arrays' => false,
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
                                                     "nested.b" => [3, 4, 5],
                                                     'seq' => 3,
                                                     'source_file' => 'my file 3',
                                                     'source_host' => 'my host 3',
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
          'perform_connectivity_check' => false,
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
                                                     "tag_prefix_t1" => "true",
                                                     "tag_prefix_t2" => "true",
                                                     "tag_prefix_t3" => "true",
                                                     "parser" => "logstashParser",
                                                 })
      end
    end

    context "split large batches into multiple scalyr requests" do
      it "estimate_each_event_size is true explicit (default) batch split into 3 scalyr requests" do
        config = {
            'api_write_token' => '1234',
            'perform_connectivity_check' => false,
            'flatten_tags' => true,
            'flat_tag_value' => 'true',
            'flat_tag_prefix' => 'tag_prefix_',
            'flatten_nested_values' => true,  # this converts into string 'true'
            'max_request_buffer' => 10,
            'estimate_each_event_size' => true
        }
        plugin = LogStash::Outputs::Scalyr.new(config)

        allow(plugin).to receive(:send_status).and_return(nil)
        plugin.register
        result = plugin.build_multi_event_request_array(sample_events)
        expect(result.size).to eq(3)

        body = JSON.parse(result[0][:body])
        expect(body['events'].size).to eq(1)

        body = JSON.parse(result[1][:body])
        expect(body['events'].size).to eq(1)

        body = JSON.parse(result[2][:body])
        expect(body['events'].size).to eq(1)
        expect(body['events'][0]['attrs']).to eq({
                                                     "nested_a" => 1,
                                                     "nested_b_0" => 3,
                                                     "nested_b_1" => 4,
                                                     "nested_b_2" => 5,
                                                     'seq' => 3,
                                                     'source_file' => 'my file 3',
                                                     'source_host' => 'my host 3',
                                                     "tag_prefix_t1" => "true",
                                                     "tag_prefix_t2" => "true",
                                                     "tag_prefix_t3" => "true",
                                                     "parser" => "logstashParser",
                                                 })
      end

      it "estimate_each_event_size is true implicit (default) batch split into 3 scalyr requests" do
        config = {
            'api_write_token' => '1234',
            'perform_connectivity_check' => false,
            'flatten_tags' => true,
            'flat_tag_value' => 'true',
            'flat_tag_prefix' => 'tag_prefix_',
            'flatten_nested_values' => true,  # this converts into string 'true'
            'max_request_buffer' => 10,
        }
        plugin = LogStash::Outputs::Scalyr.new(config)

        allow(plugin).to receive(:send_status).and_return(nil)
        plugin.register
        result = plugin.build_multi_event_request_array(sample_events)
        expect(result.size).to eq(3)

        body = JSON.parse(result[0][:body])
        expect(body['events'].size).to eq(1)

        body = JSON.parse(result[1][:body])
        expect(body['events'].size).to eq(1)

        body = JSON.parse(result[2][:body])
        expect(body['events'].size).to eq(1)
        expect(body['events'][0]['attrs']).to eq({
                                                     "nested_a" => 1,
                                                     "nested_b_0" => 3,
                                                     "nested_b_1" => 4,
                                                     "nested_b_2" => 5,
                                                     'seq' => 3,
                                                     'source_file' => 'my file 3',
                                                     'source_host' => 'my host 3',
                                                     "tag_prefix_t1" => "true",
                                                     "tag_prefix_t2" => "true",
                                                     "tag_prefix_t3" => "true",
                                                     "parser" => "logstashParser",
                                                 })
      end

      it "estimate_each_event_size is false batch not split into multiple scalyr requests" do
        config = {
            'api_write_token' => '1234',
            'perform_connectivity_check' => false,
            'flatten_tags' => true,
            'flat_tag_value' => 'true',
            'flat_tag_prefix' => 'tag_prefix_',
            'flatten_nested_values' => true,  # this converts into string 'true'
            'max_request_buffer' => 10,
            'estimate_each_event_size' => false
        }
        plugin = LogStash::Outputs::Scalyr.new(config)

        allow(plugin).to receive(:send_status).and_return(nil)
        plugin.register
        result = plugin.build_multi_event_request_array(sample_events)
        expect(result.size).to eq(1)

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
          'perform_connectivity_check' => false,
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
                                                     "tags" => ["t1", "t2", "t3"],
                                                     "parser" => "logstashParser",
                                                 })
      end
    end

    context "when configured to flatten with max keys configured to 3" do
      config = {
          'api_write_token' => '1234',
          'perform_connectivity_check' => false,
          'flatten_nested_values' => true,  # this converts into string 'true'
          'flattening_max_key_count' => 3,
      }
      plugin = LogStash::Outputs::Scalyr.new(config)
      it "does not flatten" do
        allow(plugin).to receive(:send_status).and_return(nil)
        plugin.register
        allow(plugin.instance_variable_get(:@logger)).to receive(:warn)
        result = plugin.build_multi_event_request_array(sample_events)
        body = JSON.parse(result[0][:body])
        expect(body['events'].size).to eq(3)
        expect(body['events'][2]['attrs']).to eq({
                                                     "nested" => {'a'=>1, 'b'=>[3,4,5]},
                                                     'seq' => 3,
                                                     'source_file' => 'my file 3',
                                                     'source_host' => 'my host 3',
                                                     "tags" => ["t1", "t2", "t3"],
                                                     "parser" => "logstashParser",
                                                 })
        expect(plugin.instance_variable_get(:@logger)).to have_received(:warn).with("Error while flattening record",
          {
            :error_message=>"Resulting flattened object will contain more keys than the configured flattening_max_key_count of 3",
            :sample_keys=>["parser", "tags_2", "tags_1", "tags_0"]
          }
        ).exactly(3).times
      end
    end

    context "serverHost attribute handling" do
      it "no serverHost defined in server_attributes, no serverHost defined on event level - should use node hostname as the default session level value" do
        config = {
            'api_write_token' => '1234',
            'perform_connectivity_check' => false,
        }
        plugin = LogStash::Outputs::Scalyr.new(config)

        allow(plugin).to receive(:send_status).and_return(nil)
        plugin.register
        e = LogStash::Event.new
        result = plugin.build_multi_event_request_array([e])
        body = JSON.parse(result[0][:body])
        expect(body['sessionInfo']['serverHost']).to eq(NODE_HOSTNAME)

        expect(body['logs']).to eq([])
        expect(body['events'].size).to eq(1)
        expect(body['events'][0]['attrs']["serverHost"]).to eq(nil)
      end

      it "serverHost defined in server_attributes, nothing defined on event level - server_attributes value should be used" do
        config = {
            'api_write_token' => '1234',
            'perform_connectivity_check' => false,
            'server_attributes' => {'serverHost' => 'fooHost'}
        }
        plugin = LogStash::Outputs::Scalyr.new(config)

        allow(plugin).to receive(:send_status).and_return(nil)
        plugin.register
        e = LogStash::Event.new
        result = plugin.build_multi_event_request_array([e])
        body = JSON.parse(result[0][:body])
        expect(body['sessionInfo']['serverHost']).to eq('fooHost')
        expect(body['events'].size).to eq(1)
        expect(body['events'][0]['attrs']["serverHost"]).to eq(nil)
      end

      # sessionInfo serverHost always has precedence this means it's important that we don't include it if event level attribute is set, otherwise
      # session level one would simply always overwrite event level one which would be ignored
      it "serverHost defined in server_attributes (explicitly defined), event level serverHost defined - event level value should be used" do
        config = {
            'api_write_token' => '1234',
            'perform_connectivity_check' => false,
            'server_attributes' => {'serverHost' => 'fooHost', 'attr1' => 'val1'}
        }
        plugin = LogStash::Outputs::Scalyr.new(config)

        allow(plugin).to receive(:send_status).and_return(nil)
        plugin.register
        expect(plugin.server_attributes['serverHost']).to eq('fooHost')

        e1 = LogStash::Event.new
        e1.set('a1', 'v1')
        e1.set('serverHost', 'event-host-1')

        e2 = LogStash::Event.new
        e2.set('a2', 'v2')
        e2.set('serverHost', 'event-host-2')

        e3 = LogStash::Event.new
        e3.set('a3', 'v3')
        e3.set('serverHost', 'event-host-2')

        e4 = LogStash::Event.new
        e4.set('a4', 'v4')
        e4.set('serverHost', 'event-host-1')

        result = plugin.build_multi_event_request_array([e1, e2, e3, e4])
        body = JSON.parse(result[0][:body])
        expect(body['sessionInfo']['serverHost']).to eq(nil)
        expect(body['sessionInfo']['attr1']).to eq('val1')

        expect(body['logs'].size).to eq(2)
        expect(body['logs'][0]['id']).to eq(1)
        expect(body['logs'][0]['attrs'][EVENT_LEVEL_SERVER_HOST_ATTRIBUTE_NAME]).to eq('event-host-1')
        expect(body['logs'][1]['id']).to eq(2)
        expect(body['logs'][1]['attrs'][EVENT_LEVEL_SERVER_HOST_ATTRIBUTE_NAME]).to eq('event-host-2')

        expect(body['events'].size).to eq(4)
        expect(body['events'][0]['log']).to eq(1)
        expect(body['events'][0]['attrs']["serverHost"]).to eq(nil)
        expect(body['events'][0]['attrs'][EVENT_LEVEL_SERVER_HOST_ATTRIBUTE_NAME]).to eq(nil)

        expect(body['events'][1]['log']).to eq(2)
        expect(body['events'][1]['attrs']["serverHost"]).to eq(nil)
        expect(body['events'][1]['attrs'][EVENT_LEVEL_SERVER_HOST_ATTRIBUTE_NAME]).to eq(nil)

        expect(body['events'][2]['log']).to eq(2)
        expect(body['events'][2]['attrs']["serverHost"]).to eq(nil)
        expect(body['events'][2]['attrs'][EVENT_LEVEL_SERVER_HOST_ATTRIBUTE_NAME]).to eq(nil)

        expect(body['events'][3]['log']).to eq(1)
        expect(body['events'][3]['attrs']["serverHost"]).to eq(nil)
        expect(body['events'][3]['attrs'][EVENT_LEVEL_SERVER_HOST_ATTRIBUTE_NAME]).to eq(nil)
      end

      it "serverHost defined in server_attributes (defined via node hostname), event level serverHost defined - event level value should be used" do
        config = {
            'api_write_token' => '1234',
            'perform_connectivity_check' => false,
            'server_attributes' => {'attr1' => 'val1'}
        }
        plugin = LogStash::Outputs::Scalyr.new(config)

        allow(plugin).to receive(:send_status).and_return(nil)
        plugin.register

        expect(plugin.server_attributes['serverHost']).to eq(NODE_HOSTNAME)

        e1 = LogStash::Event.new
        e1.set('a1', 'v1')
        e1.set('serverHost', 'event-host-1')

        e2 = LogStash::Event.new
        e2.set('a2', 'v2')
        e2.set('serverHost', 'event-host-2')

        e3 = LogStash::Event.new
        e3.set('a3', 'v3')
        e3.set('serverHost', 'event-host-2')

        e4 = LogStash::Event.new
        e4.set('a4', 'v4')
        e4.set('serverHost', 'event-host-1')

        result = plugin.build_multi_event_request_array([e1, e2, e3, e4])
        body = JSON.parse(result[0][:body])
        expect(body['sessionInfo']['serverHost']).to eq(nil)
        expect(body['sessionInfo']['attr1']).to eq('val1')

        expect(body['logs'].size).to eq(2)
        expect(body['logs'][0]['id']).to eq(1)
        expect(body['logs'][0]['attrs'][EVENT_LEVEL_SERVER_HOST_ATTRIBUTE_NAME]).to eq('event-host-1')
        expect(body['logs'][1]['id']).to eq(2)
        expect(body['logs'][1]['attrs'][EVENT_LEVEL_SERVER_HOST_ATTRIBUTE_NAME]).to eq('event-host-2')

        expect(body['events'].size).to eq(4)
        expect(body['events'][0]['log']).to eq(1)
        expect(body['events'][0]['attrs']["serverHost"]).to eq(nil)
        expect(body['events'][0]['attrs'][EVENT_LEVEL_SERVER_HOST_ATTRIBUTE_NAME]).to eq(nil)

        expect(body['events'][1]['log']).to eq(2)
        expect(body['events'][1]['attrs']["serverHost"]).to eq(nil)
        expect(body['events'][1]['attrs'][EVENT_LEVEL_SERVER_HOST_ATTRIBUTE_NAME]).to eq(nil)

        expect(body['events'][2]['log']).to eq(2)
        expect(body['events'][2]['attrs']["serverHost"]).to eq(nil)
        expect(body['events'][2]['attrs'][EVENT_LEVEL_SERVER_HOST_ATTRIBUTE_NAME]).to eq(nil)

        expect(body['events'][3]['log']).to eq(1)
        expect(body['events'][3]['attrs']["serverHost"]).to eq(nil)
        expect(body['events'][3]['attrs'][EVENT_LEVEL_SERVER_HOST_ATTRIBUTE_NAME]).to eq(nil)
      end

      # If set_session_level_serverhost_on_events config option is true, we set session level serverHost on events which don't
      # explicitly define this special attribute.
      it "serverHost defined in server_attributes (explicitly defined), event level serverHost defined - event level value should be used and server level one for events without server host" do
        config = {
            'api_write_token' => '1234',
            'perform_connectivity_check' => false,
            'server_attributes' => {'serverHost' => 'top-level-session-host', 'attr1' => 'val1'}
        }
        plugin = LogStash::Outputs::Scalyr.new(config)

        allow(plugin).to receive(:send_status).and_return(nil)
        plugin.register
        expect(plugin.server_attributes['serverHost']).to eq('top-level-session-host')

        e1 = LogStash::Event.new
        e1.set('a1', 'v1')
        e1.set('serverHost', 'event-host-1')

        e2 = LogStash::Event.new
        e2.set('a2', 'v2')

        e3 = LogStash::Event.new
        e3.set('a3', 'v3')

        e4 = LogStash::Event.new
        e4.set('a4', 'v4')
        e4.set('serverHost', 'event-host-1')

        result = plugin.build_multi_event_request_array([e1, e2, e3, e4])
        body = JSON.parse(result[0][:body])
        expect(body['sessionInfo']['serverHost']).to eq(nil)
        expect(body['sessionInfo']['attr1']).to eq('val1')

        expect(body['logs'].size).to eq(1)
        expect(body['logs'][0]['id']).to eq(1)
        expect(body['logs'][0]['attrs'][EVENT_LEVEL_SERVER_HOST_ATTRIBUTE_NAME]).to eq('event-host-1')

        expect(body['events'].size).to eq(4)
        expect(body['events'][0]['log']).to eq(1)
        expect(body['events'][0]['attrs']["serverHost"]).to eq(nil)
        expect(body['events'][0]['attrs'][EVENT_LEVEL_SERVER_HOST_ATTRIBUTE_NAME]).to eq(nil)

        expect(body['events'][1]['log']).to eq(nil)
        expect(body['events'][1]['attrs']["serverHost"]).to eq(nil)
        expect(body['events'][2]['attrs'][EVENT_LEVEL_SERVER_HOST_ATTRIBUTE_NAME]).to eq("top-level-session-host")

        expect(body['events'][1]['log']).to eq(nil)
        expect(body['events'][2]['attrs']["serverHost"]).to eq(nil)
        expect(body['events'][2]['attrs'][EVENT_LEVEL_SERVER_HOST_ATTRIBUTE_NAME]).to eq("top-level-session-host")

        expect(body['events'][3]['log']).to eq(1)
        expect(body['events'][3]['attrs']["serverHost"]).to eq(nil)
        expect(body['events'][3]['attrs'][EVENT_LEVEL_SERVER_HOST_ATTRIBUTE_NAME]).to eq(nil)
      end

      it "no serverHost defined, event level serverHost defined via non-default serverhost_field - event level value should be used" do
        config = {
            'api_write_token' => '1234',
            'perform_connectivity_check' => false,
            'server_attributes' => {'attr1' => 'val1'},
            'use_hostname_for_serverhost' => false,
            'serverhost_field' => 'custom_server_host',
        }
        plugin = LogStash::Outputs::Scalyr.new(config)

        allow(plugin).to receive(:send_status).and_return(nil)
        plugin.register


        expect(plugin.server_attributes['serverHost']).to eq(nil)

        e1 = LogStash::Event.new
        e1.set('a1', 'v1')
        e1.set('custom_server_host', 'event-host-1')

        e2 = LogStash::Event.new
        e2.set('a2', 'v2')
        e2.set('custom_server_host', 'event-host-2')

        e3 = LogStash::Event.new
        e3.set('a3', 'v3')
        e3.set('custom_server_host', 'event-host-2')

        e4 = LogStash::Event.new
        e4.set('a4', 'v4')
        e4.set('custom_server_host', 'event-host-2')

        result = plugin.build_multi_event_request_array([e1, e2, e3, e4])
        body = JSON.parse(result[0][:body])
        expect(body['sessionInfo']['serverHost']).to eq(nil)
        expect(body['sessionInfo']['attr1']).to eq('val1')

        expect(body['logs'][0]['id']).to eq(1)
        expect(body['logs'][0]['attrs'][EVENT_LEVEL_SERVER_HOST_ATTRIBUTE_NAME]).to eq('event-host-1')
        expect(body['logs'][1]['id']).to eq(2)
        expect(body['logs'][1]['attrs'][EVENT_LEVEL_SERVER_HOST_ATTRIBUTE_NAME]).to eq('event-host-2')

        expect(body['events'].size).to eq(4)
        expect(body['events'][0]['log']).to eq(1)
        expect(body['events'][0]['attrs']["serverHost"]).to eq(nil)
        expect(body['events'][0]['attrs'][EVENT_LEVEL_SERVER_HOST_ATTRIBUTE_NAME]).to eq(nil)
        expect(body['events'][1]['log']).to eq(2)
        expect(body['events'][1]['attrs']["serverHost"]).to eq(nil)
        expect(body['events'][1]['attrs'][EVENT_LEVEL_SERVER_HOST_ATTRIBUTE_NAME]).to eq(nil)
        expect(body['events'][2]['log']).to eq(2)
        expect(body['events'][2]['attrs']["serverHost"]).to eq(nil)
        expect(body['events'][2]['attrs'][EVENT_LEVEL_SERVER_HOST_ATTRIBUTE_NAME]).to eq(nil)
        expect(body['events'][3]['log']).to eq(2)
        expect(body['events'][3]['attrs']["serverHost"]).to eq(nil)
        expect(body['events'][3]['attrs'][EVENT_LEVEL_SERVER_HOST_ATTRIBUTE_NAME]).to eq(nil)
      end

      it "no serverHost defined, event level serverHost defined - event level value should be used" do
        config = {
            'api_write_token' => '1234',
            'perform_connectivity_check' => false,
            'server_attributes' => {'attr1' => 'val1'},
            'use_hostname_for_serverhost' => false
        }
        plugin = LogStash::Outputs::Scalyr.new(config)

        allow(plugin).to receive(:send_status).and_return(nil)
        plugin.register

        expect(plugin.server_attributes['serverHost']).to eq(nil)

        e1 = LogStash::Event.new
        e1.set('a1', 'v1')
        e1.set('serverHost', 'event-host-1')

        e2 = LogStash::Event.new
        e2.set('a2', 'v2')
        e2.set('serverHost', 'event-host-2')

        e3 = LogStash::Event.new
        e3.set('a3', 'v3')
        e3.set('serverHost', 'event-host-2')

        e4 = LogStash::Event.new
        e4.set('a4', 'v4')
        e4.set('serverHost', 'event-host-2')

        result = plugin.build_multi_event_request_array([e1, e2, e3, e4])
        body = JSON.parse(result[0][:body])
        expect(body['sessionInfo']['serverHost']).to eq(nil)
        expect(body['sessionInfo']['attr1']).to eq('val1')

        expect(body['logs'][0]['id']).to eq(1)
        expect(body['logs'][0]['attrs'][EVENT_LEVEL_SERVER_HOST_ATTRIBUTE_NAME]).to eq('event-host-1')
        expect(body['logs'][1]['id']).to eq(2)
        expect(body['logs'][1]['attrs'][EVENT_LEVEL_SERVER_HOST_ATTRIBUTE_NAME]).to eq('event-host-2')

        expect(body['events'].size).to eq(4)
        expect(body['events'][0]['log']).to eq(1)
        expect(body['events'][0]['attrs']["serverHost"]).to eq(nil)
        expect(body['events'][0]['attrs'][EVENT_LEVEL_SERVER_HOST_ATTRIBUTE_NAME]).to eq(nil)
        expect(body['events'][1]['log']).to eq(2)
        expect(body['events'][1]['attrs']["serverHost"]).to eq(nil)
        expect(body['events'][1]['attrs'][EVENT_LEVEL_SERVER_HOST_ATTRIBUTE_NAME]).to eq(nil)
        expect(body['events'][2]['log']).to eq(2)
        expect(body['events'][2]['attrs']["serverHost"]).to eq(nil)
        expect(body['events'][2]['attrs'][EVENT_LEVEL_SERVER_HOST_ATTRIBUTE_NAME]).to eq(nil)
        expect(body['events'][3]['log']).to eq(2)
        expect(body['events'][3]['attrs']["serverHost"]).to eq(nil)
        expect(body['events'][3]['attrs'][EVENT_LEVEL_SERVER_HOST_ATTRIBUTE_NAME]).to eq(nil)
      end
    end

    # NOTE: BigNum issue only affected json gem < 2
    context "when receiving an event with Bignums", if: JSON_GEM_VERSION == "1.8.6 "do
      config = {
          'api_write_token' => '1234',
          'perform_connectivity_check' => false,
      }
      plugin = LogStash::Outputs::Scalyr.new(config)
      it "doesn't throw an error" do
        allow(plugin).to receive(:send_status).and_return(nil)
        plugin.register
        e = LogStash::Event.new
        e.set('bignumber', 2000023030042002050202030320240)
        allow(plugin.instance_variable_get(:@logger)).to receive(:error)
        result = plugin.build_multi_event_request_array([e])
        body = JSON.parse(result[0][:body])
        expect(body['events'].size).to eq(1)
        expect(body['events'][0]['attrs']['bignumber']).to be_a_kind_of(String)
        expect(plugin.instance_variable_get(:@logger)).to_not receive(:error)
      end
    end

    context "host attribute handling" do
      it "host attribute removed by default" do
       config = {
            'api_write_token' => '1234',
            'perform_connectivity_check' => false,
        }
        plugin = LogStash::Outputs::Scalyr.new(config)

        allow(plugin).to receive(:send_status).and_return(nil)
        plugin.register

        expect(plugin.server_attributes['serverHost']).to eq(NODE_HOSTNAME)

        e1 = LogStash::Event.new
        e1.set('a1', 'v1')
        e1.set('host', 'event-host-1')

        result = plugin.build_multi_event_request_array([e1])
        body = JSON.parse(result[0][:body])
        expect(body['sessionInfo']['serverHost']).to eq(NODE_HOSTNAME)

        expect(body['logs'].size).to eq(0)

        expect(body['events'].size).to eq(1)
        expect(body['events'][0]['attrs']["host"]).to eq(nil)
      end

      it "host attribute not removed if config option set" do
       config = {
            'api_write_token' => '1234',
            'perform_connectivity_check' => false,
            'remove_host_attribute_from_events' => false,
        }
        plugin = LogStash::Outputs::Scalyr.new(config)

        allow(plugin).to receive(:send_status).and_return(nil)
        plugin.register

        expect(plugin.server_attributes['serverHost']).to eq(NODE_HOSTNAME)

        e1 = LogStash::Event.new
        e1.set('a1', 'v1')
        e1.set('host', 'event-host-1')

        result = plugin.build_multi_event_request_array([e1])
        body = JSON.parse(result[0][:body])
        expect(body['sessionInfo']['serverHost']).to eq(NODE_HOSTNAME)

        expect(body['logs'].size).to eq(0)

        expect(body['events'].size).to eq(1)
        expect(body['events'][0]['attrs']["host"]).to eq("event-host-1")
      end
    end

    context "when using custom json library" do
      it "stdlib (implicit)" do
        config = {
            'api_write_token' => '1234',
            'perform_connectivity_check' => false,
        }
        plugin = LogStash::Outputs::Scalyr.new(config)

        allow(plugin).to receive(:send_status).and_return(nil)
        plugin.register
        e = LogStash::Event.new
        e.set('bignumber', 20)
        result = plugin.build_multi_event_request_array([e])
        body = JSON.parse(result[0][:body])
        expect(result[0][:body]).to include(sprintf('{"serverHost":"%s","monitor":"pluginLogstash"}', NODE_HOSTNAME))
        expect(body['events'].size).to eq(1)
      end

      it "stdlib (explicit)" do
        config = {
            'api_write_token' => '1234',
            'perform_connectivity_check' => false,
            'json_library' => 'stdlib'
        }
        plugin = LogStash::Outputs::Scalyr.new(config)

        allow(plugin).to receive(:send_status).and_return(nil)
        plugin.register
        e = LogStash::Event.new
        e.set('bignumber', 20)
        result = plugin.build_multi_event_request_array([e])
        body = JSON.parse(result[0][:body])
        expect(result[0][:body]).to include(sprintf('{"serverHost":"%s","monitor":"pluginLogstash"}', NODE_HOSTNAME))
        expect(body['events'].size).to eq(1)
      end

      it "jrjackson" do
        config = {
            'api_write_token' => '1234',
            'perform_connectivity_check' => false,
            'json_library' => 'jrjackson'
        }
        plugin = LogStash::Outputs::Scalyr.new(config)

        allow(plugin).to receive(:send_status).and_return(nil)
        plugin.register
        e = LogStash::Event.new
        e.set('bignumber', 20)
        result = plugin.build_multi_event_request_array([e])
        body = JSON.parse(result[0][:body])
        expect(result[0][:body]).to include(sprintf('{"serverHost":"%s","monitor":"pluginLogstash"}', NODE_HOSTNAME))
        expect(body['events'].size).to eq(1)
      end
    end

    context "when an event exceeds the max record size" do
      def setup_plugin
        config = {
            'api_write_token' => '1234',
            'perform_connectivity_check' => false,
            'estimate_each_event_size' => true,
        }
        plugin = LogStash::Outputs::Scalyr.new(config)

        allow(plugin).to receive(:send_status).and_return(nil)
        plugin.register
        return plugin
      end

      it "truncates the message field if it exceeds the max field size" do
        plugin = setup_plugin()
        e = LogStash::Event.new
        e.set('message', 'a' * (205 * 1024))

        result = plugin.build_multi_event_request_array([e])
        body = JSON.parse(result[0][:body])
        events = body['events']
        scalyr_event = events[0]
        attrs = scalyr_event['attrs']
        expect(attrs['message'].bytesize).to eq(50 * 1024)
      end
      it "doesn't copy fields that exceed the max field size" do
        plugin = setup_plugin()
        e = LogStash::Event.new
        e.set('message', 'a' * (205 * 1024))
        e.set('honk', 'b' * (65 * 1024))
        e.set('blarg', 'honk')
        e.set('rawr', 'blah')

        result = plugin.build_multi_event_request_array([e])
        body = JSON.parse(result[0][:body])
        events = body['events']
        scalyr_event = events[0]
        attrs = scalyr_event['attrs']
        expect(attrs.has_key? 'honk').to be false
      end
      it "takes field key size into account" do
        plugin = setup_plugin()
        e = LogStash::Event.new
        e.set('b' * (20 * 1024), 'blarg')
        e.set('c' * (20 * 1024), 'blarg')
        e.set('d' * (20 * 1024), 'blarg')
        e.set('e' * (20 * 1024), 'blarg')
        e.set('q' * (20 * 1024), 'blarg')
        e.set('w' * (20 * 1024), 'blarg')
        e.set('r' * (20 * 1024), 'blarg')
        e.set('z' * (20 * 1024), 'blarg')
        e.set('x' * (20 * 1024), 'blarg')
        e.set('c' * (20 * 1024), 'blarg')
        e.set('v' * (20 * 1024), 'blarg')
        e.set('t' * (20 * 1024), 'blarg')

        result = plugin.build_multi_event_request_array([e])
        body = JSON.parse(result[0][:body])
        events = body['events']
        scalyr_event = events[0]
        attrs = scalyr_event['attrs']
        expect(attrs.size).to eq(10)
        expect(attrs.to_json.bytesize).to be <= 200*1024
      end
      it "stops copying fields when the record would exceed the max record size" do
        plugin = setup_plugin()
        e = LogStash::Event.new
        e.set('b', 'a' * (20 * 1024))
        e.set('c', 'a' * (20 * 1024))
        e.set('d', 'a' * (20 * 1024))
        e.set('e', 'a' * (20 * 1024))
        e.set('q', 'a' * (20 * 1024))
        e.set('w', 'a' * (20 * 1024))
        e.set('r', 'a' * (20 * 1024))
        e.set('z', 'a' * (20 * 1024))
        e.set('x', 'a' * (20 * 1024))
        e.set('c', 'a' * (20 * 1024))
        e.set('v', 'a' * (20 * 1024))
        e.set('t', 'a' * (20 * 1024))

        result = plugin.build_multi_event_request_array([e])
        body = JSON.parse(result[0][:body])
        events = body['events']
        scalyr_event = events[0]
        attrs = scalyr_event['attrs']
        expect(attrs.size).to eq(10)
      end
      it "can estimate the size of complex nested objects, and throw them away" do
        plugin = setup_plugin()
        e = LogStash::Event.new
        e.set('message', 'a' * (205 * 1024))
        e.set('honk', [['b' * (65 * 1024)]])
        e.set('blarg', 'honk')
        e.set('rawr', 'blah')

        result = plugin.build_multi_event_request_array([e])
        body = JSON.parse(result[0][:body])
        events = body['events']
        scalyr_event = events[0]
        attrs = scalyr_event['attrs']
        expect(attrs.has_key? 'honk').to be false
      end
    end

    context "scalyr_server config option handling and connectivity check" do
      it "doesn't throw an error on valid url" do
        config = {
            'api_write_token' => '1234',
            'perform_connectivity_check' => false,
            'scalyr_server' => 'https://agent.scalyr.com'
        }
        plugin = LogStash::Outputs::Scalyr.new(config)
        plugin.register

        config = {
            'api_write_token' => '1234',
            'perform_connectivity_check' => false,
            'scalyr_server' => 'https://eu.scalyr.com'
        }
        plugin = LogStash::Outputs::Scalyr.new(config)
        plugin.register
      end

      it "throws on invalid URL" do
        config = {
            'api_write_token' => '1234',
            'perform_connectivity_check' => false,
            'scalyr_server' => 'agent.scalyr.com'
        }
        plugin = LogStash::Outputs::Scalyr.new(config)
        expect { plugin.register }.to raise_error(LogStash::ConfigurationError, /is not a valid URL/)

        config = {
            'api_write_token' => '1234',
            'perform_connectivity_check' => false,
            'scalyr_server' => 'eu.scalyr.com'
        }
        plugin = LogStash::Outputs::Scalyr.new(config)
        expect { plugin.register }.to raise_error(LogStash::ConfigurationError, /is not a valid URL/)
      end

      it "throws on invalid hostname" do
        config = {
            'api_write_token' => '1234',
            'scalyr_server' => 'https://agent.invalid.foo.scalyr.com',
            'perform_connectivity_check' => true
        }
        plugin = LogStash::Outputs::Scalyr.new(config)
        expect { plugin.register }.to raise_error(LogStash::ConfigurationError, /Received error when trying to communicate/)
      end

      it "throws on invalid api key" do
        config = {
            'api_write_token' => '1234',
            'scalyr_server' => 'https://agent.scalyr.com',
            'perform_connectivity_check' => true
        }
        plugin = LogStash::Outputs::Scalyr.new(config)
        expect { plugin.register }.to raise_error(LogStash::ConfigurationError, /Received 401 from Scalyr API during/)
      end
    end


    context "RetryStateTracker" do
      mock_config = {
        'max_retries' => 2,
        'retry_max_interval' => 2,
        'retry_initial_interval' => 0.11,
        'retry_backoff_factor' => 2.0,

        'max_retries_deploy_errors' => 4,
        'retry_max_interval_deploy_errors' => 2,
        'retry_initial_interval_deploy_errors' => 0.12,
        'retry_backoff_factor_deploy_errors' => 1.2,

        'max_retries_throttling_errors' => 3,
        'retry_max_interval_throttling_errors' => 2,
        'retry_initial_interval_throttling_errors' => 0.13,
        'retry_backoff_factor_throttling_errors' => 1.1,
      }

      mock_other_error = Manticore::UnknownException.new
      mock_deploy_error_1 = Scalyr::Common::Client::DeployWindowError.new(nil, 530)
      mock_deploy_error_2 = Scalyr::Common::Client::DeployWindowError.new(nil, 500)
      mock_client_throttled_error = Scalyr::Common::Client::ClientThrottledError.new(nil, 429)

      it "correctly tracks state across different error types" do
        mock_is_plugin_running = lambda { true }
        state_tracker = RetryStateTracker.new(mock_config, mock_is_plugin_running)

        # Verify initial state
        state = state_tracker.get_state

        expect(state[:other_errors]).to eq({
          :retries => 0,
          :sleep => 0,
          :sleep_interval => 0.11,
          :options => {
            :retry_initial_interval => 0.11,
            :max_retries => 2,
            :retry_max_interval => 2,
            :retry_backoff_factor => 2.0
          }
        })

        expect(state[:deploy_errors]).to eq({
          :retries => 0,
          :sleep => 0,
          :sleep_interval => 0.12,
          :options => {
            :retry_initial_interval => 0.12,
            :max_retries => 4,
            :retry_max_interval => 2,
            :retry_backoff_factor => 1.2
          }
        })

        expect(state[:throttling_errors]).to eq({
          :retries => 0,
          :sleep => 0,
          :sleep_interval => 0.13,
          :options => {
            :retry_initial_interval => 0.13,
            :max_retries => 3,
            :retry_max_interval => 2,
            :retry_backoff_factor => 1.1
          }
        })

        # Update internal state and verify it's updated correctly
        state_tracker.sleep_for_error_and_update_state(mock_other_error)
        state_tracker.sleep_for_error_and_update_state(mock_deploy_error_1)
        state_tracker.sleep_for_error_and_update_state(mock_deploy_error_2)
        state_tracker.sleep_for_error_and_update_state(mock_other_error)
        state_tracker.sleep_for_error_and_update_state(mock_client_throttled_error)
        state_tracker.sleep_for_error_and_update_state(mock_other_error)
        state_tracker.sleep_for_error_and_update_state(mock_client_throttled_error)

        state = state_tracker.get_state

        expect(state[:other_errors]).to eq({
          :retries => 3,
          :sleep => 0.77,
          :sleep_interval => 0.88,
          :options => {
            :retry_initial_interval => 0.11,
            :max_retries => 2,
            :retry_max_interval => 2,
            :retry_backoff_factor => 2.0
          }
        })

        expect(state[:deploy_errors]).to eq({
          :retries => 2,
          :sleep => 0.264,
          :sleep_interval => 0.17279999999999998,
          :options => {
            :retry_initial_interval => 0.12,
            :max_retries => 4,
            :retry_max_interval => 2,
            :retry_backoff_factor => 1.2
          }
        })

        expect(state[:throttling_errors]).to eq({
          :retries => 2,
          :sleep => 0.273,
          :sleep_interval => 0.15730000000000002,
          :options => {
            :retry_initial_interval => 0.13,
            :max_retries => 3,
            :retry_max_interval => 2,
            :retry_backoff_factor => 1.1
          }
        })
      end
    end
  end
end
