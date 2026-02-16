docker build -t sysbox-lab .
docker stop sysbox
docker run -d --privileged --rm --device /dev/fuse --name sysbox sysbox-lab sleep infinity

mkdir -p /run/sysbox /var/lib/sysboxfs /tmp/fake-container
rm -f /run/sysbox/sysfs.sock

docker exec -it sysbox sysbox-fs -- sysbox-fs --log /dev/stdout --log-level debug


---

START SCRATCH


docker run -d --privileged --device /dev/fuse -v $(pwd)/build:/opt/sysbox/bin -v /var/lib/containerd --name lab ubuntu-nri-lab

---  build di nri

-- creazione pod per provare con crictl

```
crictl pull alpine:latest
```

```
cat <<EOF > pod.json
{
  "metadata": { "name": "nri-sandbox", "namespace": "default", "uid": "12345" },
  "log_directory": "/tmp",
  "linux": {}
}
EOF
```

```
cat <<EOF > cont.json
{
  "metadata": { "name": "nri-container" },
  "image": { "image": "alpine:latest" },
  "command": [ "top" ],
  "log_path": "nri-container.log",
  "linux": {}
}
EOF
```

--- ooschianto

POD_ID=$(crictl runp pod.json)