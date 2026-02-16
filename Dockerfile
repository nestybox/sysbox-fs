FROM ubuntu:24.04

# Evita prompt interattivi durante apt-get
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    curl wget git make gcc g++ iptables \
    libfuse-dev fuse3 \
    protobuf-compiler \
    vim nano iproute2 psmisc \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /etc/containerd /opt/cni/bin /etc/cni/net.d /var/lib/sysboxfs /var/run/nri

RUN wget https://github.com/containerd/containerd/releases/download/v1.7.13/cri-containerd-cni-1.7.13-linux-amd64.tar.gz && \
    tar --no-overwrite-dir -C / -xzf cri-containerd-cni-1.7.13-linux-amd64.tar.gz && \
    rm cri-containerd-cni-1.7.13-linux-amd64.tar.gz

RUN crictl config --set runtime-endpoint=unix:///run/containerd/containerd.sock

# Configura la rete Bridge per crictl
RUN echo '{"cniVersion": "1.0.0","name": "containerd-net","type": "bridge","bridge": "cni0","isGateway": true,"ipMasq": true,"ipam": {"type": "host-local","subnet": "10.88.0.0/16","routes": [{"dst": "0.0.0.0/0"}]}}' > /etc/cni/net.d/10-bridge.conf

# Configura Containerd e accendi NRI
RUN containerd config default > /etc/containerd/config.toml && \
    sed -i '/\[plugins."io.containerd.nri.v1.nri"\]/{n;s/disable = true/disable = false/}' /etc/containerd/config.toml

# Script di avvio semplice (evitiamo la complessità di systemd dentro docker)
RUN echo '#!/bin/bash\n\
    containerd &\n\
    echo "Containerd avviato..."\n\
    sleep infinity' > /entrypoint.sh && chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]

# RUN wget https://go.dev/dl/go1.21.6.linux-amd64.tar.gz && \
#     tar -C /usr/local -xzf go1.21.6.linux-amd64.tar.gz && \
#     rm go1.21.6.linux-amd64.tar.gz

# ENV PATH=$PATH:/usr/local/go/bin
# ENV GOPATH=/root/go

# RUN go install github.com/golang/protobuf/protoc-gen-go@v1.5.4



# # 3. Setup Workspace per Sysbox
# WORKDIR /root/go/src/github.com/nestybox
# RUN git clone https://github.com/nestybox/sysbox-fs.git

# # 4. Compilazione Iniziale (per verificare che tutto funzioni)
# WORKDIR /root/go/src/github.com/nestybox/sysbox-fs
# RUN make sysbox-fs

# 5. Creazione directory necessarie per il runtime
# RUN mkdir -p /run/sysbox /var/lib/sysboxfs /tmp/fake-container-root

# 6. Copia dello script "Shim" (lo creiamo nel passo successivo)
# COPY trigger.go .
# COPY build/sysbox-fs /usr/bin/sysbox-fs
# COPY trigger /usr/bin/trigger


# Entrypoint: shell per lavorare
# CMD ["/bin/bash"]