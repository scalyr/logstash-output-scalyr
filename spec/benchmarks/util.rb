def rand_str(len)
  return (0...len).map { (65 + rand(26)).chr }.join
end

def generate_hash(widths)
  result = {}
  if widths.empty?
    return rand_str(20)
  else
    widths[0].times do
      result[rand_str(9)] = generate_hash(widths[1..widths.length])
    end
    return result
  end
end

def generate_data_array_for_spec(spec)
  data = []
  ITERATIONS.times do
    data << generate_hash(spec)
  end

  data
end
