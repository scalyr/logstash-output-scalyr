import os

# This command produces an output we parse to get the logstash node IPs, example here:
# NAME                            READY   STATUS    RESTARTS   AGE   IP              NODE                                          NOMINATED NODE   READINESS GATES
# logstash-pool-9b468dd96-x9g9c   1/1     Running   0          81s   192.168.16.90   ip-192-168-26-84.us-west-2.compute.internal   <none>           <none>
with os.popen('kubectl get pods -o wide -n logstash') as stream:
    pods_string = stream.read()
pods_list = pods_string.split("\n")

hosts_list = []
for line in pods_list[1:]:
    if line != "":
        pod_info = line.split()
        if pod_info[5] != "<none>":
            hosts_list.append('"%s:5044"' % pod_info[5])

beats_yaml = ""
with open('k8s_yaml/beats.yaml', mode='r') as f:
    beats_yaml = f.read()

print(beats_yaml.replace("LOGSTASH_HOSTS", ", ".join(hosts_list), 1))
