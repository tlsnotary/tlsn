# tlsnotary gramine layer 

FROM --platform=linux/amd64 ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

ADD intel-sgx-deb.asc /etc/apt/keyrings/intel-sgx-keyring.asc

RUN echo deb [trusted=yes arch=amd64 signed-by=/etc/apt/keyrings/intel-sgx-keyring.asc] https://download.01.org/intel-sgx/sgx_repo/ubuntu noble  main > /etc/apt/sources.list.d/intel-sgx.list

RUN apt-get update && apt-get satisfy -y \
	'libcurl4 (>= 7.58)' \
	'libprotobuf-c1' \
	'python3' \
	'python3 (>= 3.10) | python3-pkg-resources' \
	'python3-click (>= 6.7)' \
	'python3-cryptography' \
	'python3-jinja2' \
	'python3-pyelftools' \
	'autoconf' \
	'bison'  \
	'cmake'  \
	'jq'  \
	'gawk'  \
	'libcurl4-openssl-dev (>= 7.58)'  \
	'libprotobuf-c-dev'  \
	'linux-libc-dev (>= 5.11) | linux-headers-amd64 (>= 5.11)'  \
	'nasm'  \
	'ninja-build (>= 1.8)'  \
	'perl'  \
	'pkg-config'  \
	'protobuf-c-compiler'  \
	'python3-breathe (>= 4.26)'  \
	'python3-sphinx (>= 3.4)'  \
	'python3-sphinx-rtd-theme'  \
	'python3-tomli (>= 1.1.0)'  \
	'python3-tomli-w (>= 0.4.0)'  \
	'python3-voluptuous'

RUN apt-get update && apt-get install -y \
    cmake git curl wget nasm g++-13  make libprotobuf-c-dev protobuf-c-compiler     protobuf-compiler python3-cryptography python3-pip python3-protobuf  pkg-config
RUN  python3 -m pip install --break-system-packages 'meson==0.64.1'
RUN git clone -b master https://github.com/gramineproject/gramine && cd gramine && meson setup build/ \
        --buildtype=release \
        -Ddirect=enabled \
        -Dsgx=enabled \
        && ninja -C build/ && ninja -C build/ install

RUN curl https://sh.rustup.rs -sSf | sh -s -- -y

RUN apt install libssl-dev

CMD ["bash"]
