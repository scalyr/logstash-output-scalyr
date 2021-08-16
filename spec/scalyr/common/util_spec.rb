# encoding: utf-8
require "scalyr/common/util"


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
