FROM ubuntu:24.04

# Install dependencies
RUN apt-get update && \
    apt-get install -y wget curl ca-certificates build-essential git

# Install Bash 5.3.3
RUN wget https://ftp.gnu.org/gnu/bash/bash-5.3.tar.gz && \
    tar xzf bash-5.3.tar.gz && \
    cd bash-5.3 && \
    ./configure --prefix=/usr/local && make && make install && \
    cd .. && rm -rf bash-5.3*

# Install jq 1.8.0
RUN wget -O /usr/local/bin/jq https://github.com/jqlang/jq/releases/download/jq-1.8.0/jq-linux-amd64 && \
    chmod +x /usr/local/bin/jq

# Install yq v4.45.4
RUN wget -O /usr/local/bin/yq https://github.com/mikefarah/yq/releases/download/v4.45.4/yq_linux_amd64 && \
    chmod +x /usr/local/bin/yq

# Set default shell to the installed bash
SHELL ["/usr/local/bin/bash", "-c"]

# Show versions for verification
RUN /usr/local/bin/bash --version && jq --version && yq --version

WORKDIR /workspace