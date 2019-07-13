# encoding: utf-8
require "logstash/devutils/rspec/spec_helper"
require "logstash/outputs/scalyr"
require "logstash/codecs/plain"
require "logstash/event"
require "json"



describe LogStash::Outputs::Scalyr do
  let(:sample_events) {
    events = []
    for i in 1..3 do
      e = LogStash::Event.new
      e.set('source_host', "my host #{i}")
      e.set('source_file', "my file #{i}")
      e.set('seq', i)
      e.set('origin', i)
      e.set('nested', {'a'=>1, 'b'=>[3,4,5]})
      e.set('tags', ['t1', 't2', 't3'])
      events.push(e)
    end
    events
  }

  describe "#build_multi_event_request_array" do

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
                                                     'logfile' => '/logstash/3',
                                                     "nested_a" => 1,
                                                     "nested_b_0" => 3,
                                                     "nested_b_1" => 4,
                                                     "nested_b_2" => 5,
                                                     "origin" => 3,
                                                     'seq' => 3,
                                                     'source_file' => 'my file 3',
                                                     'source_host' => 'my host 3',
                                                     "tag_prefix_t1" => "true",
                                                     "tag_prefix_t2" => "true",
                                                     "tag_prefix_t3" => "true",
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
                                                     'logfile' => '/logstash/3',
                                                     "nested" => {'a'=>1, 'b'=>[3,4,5]},
                                                     "origin" => 3,
                                                     'seq' => 3,
                                                     'source_file' => 'my file 3',
                                                     'source_host' => 'my host 3',
                                                     "tags" => ["t1", "t2", "t3"],
                                                 })
      end
    end
  end
end
