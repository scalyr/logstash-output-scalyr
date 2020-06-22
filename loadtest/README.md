# Logstash loadtest setup

### K8s testing setup:

These instructions use a Scalyr private docker image that already contains an API key, if you don't have access to this
 image then edit `logstash.conf` with your own API key and build a new image with the `Dockerfile` provided, edit `logstash.yaml`
 to point to this new image.

Create a `loadgen` namespace and a `logstash` namespace in your cluster.

```
kubectl create namespace loadgen
kubectl create namespace logstash
```

Edit `k8s_yaml/logstash.yaml` with a `replicas` value you wish to test with, this determines the amount of logstash nodes.
 Apply `k8s_yaml/logstash.yaml` to the cluster to create some logstash nodes.

```
kubectl apply -f k8s_yaml/logstash.yaml
```

Run the bellow command to generate and apply yaml that will bring up filebeats pointed at all your new logstash nodes.
 Make sure your logstash nodes are up and running before doing this step.

```
python beats-yaml-generator.py | kubectl apply -f -
```

Modify `k8s_yaml/flog.yaml` with your required amount of `replicas`, this will determine the amount of load generated,
 then apply the yaml to start load generation.

```
kubectl apply -f k8s_yaml/flog.yaml
```
