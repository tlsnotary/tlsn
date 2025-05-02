FROM --platform=linux/amd64 gramineproject/gramine:latest

RUN apt update && \
    apt install -y jq openssl zip && \
    apt clean && \
    rm -rf /var/lib/apt/lists/*