# encoding: utf-8
require "logstash/devutils/rspec/spec_helper"
require "logstash/outputs/scalyr"
require "logstash/codecs/plain"
require "logstash/event"



describe LogStash::Outputs::Scalyr do
  let(:sample_events) {
    events = []
    for i in 1..3 do
      e = LogStash::Event.new
      e.set('source_host', "my host #{i}")
      e.set('source_file', "my file #{i}")
      e.set('seq', i)
      e.set('origin', i)
      events.push(e)
    end
    events
  }
  let(:output) { LogStash::Outputs::Scalyr.new }

  before do
    output.register
  end

  describe "#receive" do
    subject { output.multi_receive(sample_events) }

    it "returns a string" do
      expect(subject).to eq("Events received 1 2 3")
    end
  end
end
