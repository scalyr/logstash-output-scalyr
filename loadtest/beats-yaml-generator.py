import os

stream = os.popen('kubectl get pods -o wide -n logstash')
output = stream.read()
output = output.split("\n")
result = ""

i = 0
for o in output:
    if i > 0 and o != "":
        s = o.split()
        if i >= 2:
            result += ", "
        result += '"%s:5044"' % s[5]
    i += 1

beats = ""
with open('k8s_yaml/beats.yaml',mode='r') as f:
    beats = f.read()

print(beats.replace("LOGSTASH_HOSTS", result, 1))
