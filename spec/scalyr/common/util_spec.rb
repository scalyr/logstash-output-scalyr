# encoding: utf-8
require "scalyr/common/util"

LARGE_OBJECT_IN = {
  "level": "info",
  "ts": "2020-08-11T02:26:17.078Z",
  "caller": "api/foo:480",
  "msg": "assign active task foobar",
  "accountId": 12345,
  "cycleId": 6789,
  "uuid": "a405a4b58810e3aaa078f751bd32baa8b60aaad1",
  "task": {
    "Id": 1211111181111111400,
    "TaskTypes": [
      4,
      11,
      10,
      12,
      17,
      14
    ],
    "Ips": [
      "127.0.0.1",
      "127.0.0.2",
      "127.0.0.3",
      "127.0.0.4",
      "127.0.0.5",
    ],
    "FooProps": {
      "10": {
        "TcpPorts": [
          22,
          23,
          25,
          80,
          55,
          8000,
          8080,
        ],
        "UdpPorts": []
      }
    },
    "Subnet": "127.0.0.0/24"
  },
  "relevance": 0,
  "scannerIp": "10.0.0.2",
  "gatewayIp": "10.0.0.1",
  "gatewayMac": "fa:fa:fa:fa",
  "wired": true,
  "elapsed": 74.86664
}

LARGE_OBJECT_OUT = {
  "accountId" => 12345,
  "caller" => "api/foo:480",
  "cycleId" => 6789,
  "elapsed" => 74.86664,
  "gatewayIp" => "10.0.0.1",
  "gatewayMac" => "fa:fa:fa:fa",
  "level" => "info",
  "msg" => "assign active task foobar",
  "relevance" => 0,
  "scannerIp" => "10.0.0.2",
  "task_FooProps_10_TcpPorts_0" => 22,
  "task_FooProps_10_TcpPorts_1" => 23,
  "task_FooProps_10_TcpPorts_2" => 25,
  "task_FooProps_10_TcpPorts_3" => 80,
  "task_FooProps_10_TcpPorts_4" => 55,
  "task_FooProps_10_TcpPorts_5" => 8000,
  "task_FooProps_10_TcpPorts_6" => 8080,
  "task_Id" => 1211111181111111400,
  "task_Ips_0" => "127.0.0.1",
  "task_Ips_1" => "127.0.0.2",
  "task_Ips_2" => "127.0.0.3",
  "task_Ips_3" => "127.0.0.4",
  "task_Ips_4" => "127.0.0.5",
  "task_Subnet" => "127.0.0.0/24",
  "task_TaskTypes_0" => 4,
  "task_TaskTypes_1" => 11,
  "task_TaskTypes_2" => 10,
  "task_TaskTypes_3" => 12,
  "task_TaskTypes_4" => 17,
  "task_TaskTypes_5" => 14,
  "ts" => "2020-08-11T02:26:17.078Z",
  "uuid" => "a405a4b58810e3aaa078f751bd32baa8b60aaad1",
  "wired" => true,
}

describe Scalyr::Common::Util do
  it "does not flatten an already-flat dict" do
    din = {
        'a' => 1,
        'b' => 'two',
    }
    dout = {
        'a' => 1,
        'b' => 'two'
    }
    expect(Scalyr::Common::Util.flatten(din)).to eq(dout)
  end

  it "flattens a single-level sub-dict" do
    din = {
        'a' => 1,
        'b' => {
            'c' => 100,
            'd' => 200,
        }
    }
    dout = {
        'a' => 1,
        'b_c' => 100,
        'b_d' => 200,
    }
    expect(Scalyr::Common::Util.flatten(din)).to eq(dout)
  end

  it "flattens a two-level sub-dict" do
    din = {
        'a' => 1,
        'b' => {
            'c' => {
                'e' => 1000,
                'f' => 2000,
            },
            'd' => 200,
        }
    }
    dout = {
        'a' => 1,
        'b_c_e' => 1000,
        'b_c_f' => 2000,
        'b_d' => 200,
    }
    expect(Scalyr::Common::Util.flatten(din)).to eq(dout)
  end

  it "flattens a single-level array" do
    din = [1, 2, 3]
    dout = {
        '0' => 1,
        '1' => 2,
        '2' => 3,
    }
    expect(Scalyr::Common::Util.flatten(din)).to eq(dout)
  end

  it "flattens a multi-level array" do
    din = ['a', 'b', ['c', ['d', 'e', 'f'], 'g'], 'h', 'i']
    dout = {
        '0' => 'a',
        '1' => 'b',
        '2_0' => 'c',
        '2_1_0' => 'd',
        '2_1_1' => 'e',
        '2_1_2' => 'f',
        '2_2' => 'g',
        '3' => 'h',
        '4' => 'i',
    }
    expect(Scalyr::Common::Util.flatten(din)).to eq(dout)
  end

  it "flattens a hash that contains an array" do
    din = {
        'a' => 1,
        'c' => [100, 200, 300]
    }
    dout = {
        'a' => 1,
        'c_0' => 100,
        'c_1' => 200,
        'c_2' => 300,
    }
    expect(Scalyr::Common::Util.flatten(din)).to eq(dout)
  end

  it "flattens a hash that contains an array that contains a hash" do
    din = {
        'a' => 1,
        'c' => [
            100,
            {'d' => 1000, 'e' => 2000},
            300
        ]
    }
    dout = {
        'a' => 1,
        'c_0' => 100,
        'c_1_d' => 1000,
        'c_1_e' => 2000,
        'c_2' => 300,
    }
    expect(Scalyr::Common::Util.flatten(din)).to eq(dout)
  end

  it "flattens a hash that contains an array that contains a hash that contains an array" do
    din = {
        'a' => 1,
        'c' => [
            100,
            {'d' => 1000, 'e' => 2000, 'f' => [4, 5, 6]},
            300
        ]
    }
    dout = {
        'a' => 1,
        'c_0' => 100,
        'c_1_d' => 1000,
        'c_1_e' => 2000,
        'c_1_f_0' => 4,
        'c_1_f_1' => 5,
        'c_1_f_2' => 6,
        'c_2' => 300,
    }
    expect(Scalyr::Common::Util.flatten(din)).to eq(dout)
  end

  it "flattens a single-level array, no array flattening" do
    din = [1, 2, 3]
    dout = [1, 2, 3]
    expect(Scalyr::Common::Util.flatten(din, "_", flatten_arrays=false)).to eq(dout)
  end

  it "flattens a multi-level array, no array flattening" do
    din = ['a', 'b', ['c', ['d', 'e', 'f'], 'g'], 'h', 'i']
    dout = ['a', 'b', ['c', ['d', 'e', 'f'], 'g'], 'h', 'i']
    expect(Scalyr::Common::Util.flatten(din, "_", flatten_arrays=false)).to eq(dout)
  end

  it "flattens a hash that contains an array with hashes, no array flattening" do
    din = {
        'a' => 1,
        "b" => {"a": "a"},
        'c' => { "f" => [100, 200, {"g" => 1}] }
    }
    dout = {
        'a' => 1,
        "b_a" => "a",
        'c_f' => [100, 200, {"g" => 1}]
    }
    expect(Scalyr::Common::Util.flatten(din, "_", flatten_arrays=false)).to eq(dout)
  end

  it "flattens a hash that contains an array, no array flattening" do
    din = {
        'a' => 1,
        'c' => [100, 200, 300]
    }
    dout = {
        'a' => 1,
        'c' => [100, 200, 300]
    }
    expect(Scalyr::Common::Util.flatten(din, "_", flatten_arrays=false)).to eq(dout)
  end

  it "flattens a hash that contains an array that contains a hash, no array flattening" do
    din = {
        'a' => 1,
        'c' => [
            100,
            {'d' => 1000, 'e' => 2000},
            300
        ]
    }
    dout = {
        'a' => 1,
        'c' => [
            100,
            {'d' => 1000, 'e' => 2000},
            300
        ]
    }
    expect(Scalyr::Common::Util.flatten(din, "_", flatten_arrays=false)).to eq(dout)
  end

  it "flattens a hash that contains an array that contains a hash that contains an array, no array flattening" do
    din = {
        'a' => 1,
        'c' => [
            100,
            {'d' => 1000, 'e' => 2000, 'f' => [4, 5, 6]},
            300
        ]
    }
    dout = {
        'a' => 1,
        'c' => [
            100,
            {'d' => 1000, 'e' => 2000, 'f' => [4, 5, 6]},
            300
        ]
    }
    expect(Scalyr::Common::Util.flatten(din, "_", flatten_arrays=false)).to eq(dout)
  end

  it "flattens large hash correctly" do
    expect(Scalyr::Common::Util.flatten(LARGE_OBJECT_IN, "_", flatten_arrays=true)).to eq(LARGE_OBJECT_OUT)
  end

  it "accepts custom delimiters" do
    din = {
        'a' => 1,
        'b' => {
            'c' => 100,
            'd' => 200,
        }
    }
    dout = {
        'a' => 1,
        'b:c' => 100,
        'b:d' => 200,
    }
    expect(Scalyr::Common::Util.flatten(din, ':')).to eq(dout)
  end

  it "accepts custom delimiters with greater depth" do
    din = {
        'a' => 1,
        'b' => {
            'c' => {
              'e' => 100
            },
            'd' => 200,
        }
    }
    dout = {
        'a' => 1,
        'b:c_e' => 100,
        'b:d' => 200,
    }
    expect(Scalyr::Common::Util.flatten(din, ':')).to eq(dout)
  end

  it "accepts custom delimiters with greater depth and deep delimiters fix" do
    din = {
        'a' => 1,
        'b' => {
            'c' => {
              'e' => 100
            },
            'd' => 200,
        }
    }
    dout = {
        'a' => 1,
        'b:c:e' => 100,
        'b:d' => 200,
    }
    expect(Scalyr::Common::Util.flatten(din, ':', true, true)).to eq(dout)
  end

  it "stringifies non-string keys" do
    din = {
        'a' => 1,
        1 => {
            'c' => 100,
            'd' => 200,
        }
    }
    dout = {
        'a' => 1,
        '1:c' => 100,
        '1:d' => 200,
    }
    expect(Scalyr::Common::Util.flatten(din, ':')).to eq(dout)
  end

  it "handles nil values" do
    din = {
        'a' => nil,
        1 => {
            'c' => 100,
            'd' => nil,
        }
    }
    dout = {
        'a' => nil,
        '1:c' => 100,
        '1:d' => nil,
    }
    expect(Scalyr::Common::Util.flatten(din, ':')).to eq(dout)
  end

  it "raises exception if a non-dict is provided" do
    expect {Scalyr::Common::Util.flatten(1)}.to raise_error(TypeError)
  end

  it "flattens a hash 5000 layers deep" do
    din = {
        'a' => {},
    }
    hash = din
    for i in 0...4999
      hash = hash["a"]
      hash["a"] = {}
      if i == 4998
        hash["a"] = "b"
      end
    end

    dout = {
        'a' + "_a" * 4999 => "b",
    }
    expect(Scalyr::Common::Util.flatten(din, '_')).to eq(dout)
  end
end
