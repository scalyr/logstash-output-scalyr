# encoding: utf-8
require "logstash/devutils/rspec/spec_helper"
require "logstash/outputs/scalyr"
require "logstash/codecs/plain"
require "logstash/event"
require "json"
require "quantile"


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

  def post_add_events(body, is_status, body_serialization_duration = 0)
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

  describe "#build_multi_event_request_array" do

    context "test get_stats and send_status" do
      plugin = LogStash::Outputs::Scalyr.new({
                                                     'api_write_token' => '1234',
                                                     'serverhost_field' => 'source_host',
                                                     'log_constants' => ['tags'],
                                                     'flatten_nested_values' => true,
                                                 })

      mock_client_session = MockClientSession.new

      it "returns correct stats on get_stats" do
        stats = mock_client_session.get_stats
        expect(stats[:total_requests_sent]).to eq(20)
      end

      it "it doesnt include flatten metrics if flattening is disabled" do
        plugin1 = LogStash::Outputs::Scalyr.new({
                                                     'api_write_token' => '1234',
                                                     'serverhost_field' => 'source_host',
                                                     'log_constants' => ['tags'],
                                                     'flatten_nested_values' => false,
                                                 })
        mock_client_session = MockClientSession.new
        plugin1.instance_variable_set(:@last_status_transmit_time, 100)
        plugin1.instance_variable_set(:@client_session, mock_client_session)
        plugin1.instance_variable_set(:@session_id, "some_session_id")
        plugin1.instance_variable_set(:@plugin_metrics, {
          :multi_receive_duration_secs => Quantile::Estimator.new,
          :multi_receive_event_count => Quantile::Estimator.new,
          :event_attributes_count =>  Quantile::Estimator.new,
          :flatten_values_duration_secs => Quantile::Estimator.new,
          :batches_per_multi_receive => Quantile::Estimator.new
        })
        plugin1.instance_variable_get(:@plugin_metrics)[:multi_receive_duration_secs].observe(1)
        plugin1.instance_variable_set(:@multi_receive_statistics, {:total_multi_receive_secs => 0})

        status_event = plugin1.send_status
        expect(status_event[:attrs]["message"]).to eq("plugin_status: total_requests_sent=20 total_requests_failed=10 total_request_bytes_sent=100 total_compressed_request_bytes_sent=50 total_response_bytes_received=100 total_request_latency_secs=100 total_serialization_duration_secs=100.5000 total_compression_duration_secs=10.2000 compression_type=deflate compression_level=9 total_multi_receive_secs=0 multi_receive_duration_p50=1 multi_receive_duration_p90=1 multi_receive_duration_p99=1 multi_receive_event_count_p50=0 multi_receive_event_count_p90=0 multi_receive_event_count_p99=0 event_attributes_count_p50=0 event_attributes_count_p90=0 event_attributes_count_p99=0 batches_per_multi_receive_p50=0 batches_per_multi_receive_p90=0 batches_per_multi_receive_p99=0")
      end

      it "returns and sends correct status event on send_stats on initial and subsequent send" do
        # 1. Initial send
        plugin.instance_variable_set(:@last_status_transmit_time, nil)
        plugin.instance_variable_set(:@client_session, mock_client_session)
        plugin.instance_variable_set(:@session_id, "some_session_id")
        status_event = plugin.send_status
        expect(status_event[:attrs]["message"]).to eq("Started Scalyr LogStash output plugin (%s)." % [PLUGIN_VERSION])

        # 2. Second send
        plugin.instance_variable_set(:@last_status_transmit_time, 100)
        plugin.instance_variable_set(:@client_session, mock_client_session)
        # Setup one quantile calculation to make sure at least one of them calculates as expected
        plugin.instance_variable_set(:@plugin_metrics, {
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
        expect(status_event[:attrs]["message"]).to eq("plugin_status: total_requests_sent=20 total_requests_failed=10 total_request_bytes_sent=100 total_compressed_request_bytes_sent=50 total_response_bytes_received=100 total_request_latency_secs=100 total_serialization_duration_secs=100.5000 total_compression_duration_secs=10.2000 compression_type=deflate compression_level=9 total_multi_receive_secs=0 multi_receive_duration_p50=10 multi_receive_duration_p90=18 multi_receive_duration_p99=19 multi_receive_event_count_p50=0 multi_receive_event_count_p90=0 multi_receive_event_count_p99=0 event_attributes_count_p50=0 event_attributes_count_p90=0 event_attributes_count_p99=0 batches_per_multi_receive_p50=0 batches_per_multi_receive_p90=0 batches_per_multi_receive_p99=0 flatten_values_duration_secs_p50=0 flatten_values_duration_secs_p90=0 flatten_values_duration_secs_p99=0")
      end

      it "send_stats is called when events list is empty, but otherwise is noop" do
        quantile_estimator = Quantile::Estimator.new
        plugin.instance_variable_set(:@plugin_metrics, {
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
                                                     'serverhost_field' => 'source_host',
                                                     'log_constants' => ['tags'],
                                                     'flatten_nested_values' => false,
                                                     'report_status_for_empty_batches' => false,
                                                 })

        mock_client_session = MockClientSession.new
        quantile_estimator = Quantile::Estimator.new
        plugin2.instance_variable_set(:@plugin_metrics, {
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

    context "when configured to flatten values with custom delimiter, no array flattening" do
      config = {
          'api_write_token' => '1234',
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

    context "when receiving an event with Bignums" do
      config = {
          'api_write_token' => '1234',
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
        expect(plugin.instance_variable_get(:@logger)).to_not receive(:error)
      end
    end
  end
end
