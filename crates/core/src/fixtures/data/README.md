# This folder contains data to test certificate chain validation and verification of the key exchange parameters.

# The certificates are:
# ee.der - end-entity certificate
# inter.der - intermediate certificate
# ca.der - CA certificate

# The key exchange paramaters and their signature were extracted from a live session as follows:

# while running tcpdump in one console
tcpdump 'tcp port 443' -w out.pcap
# in another console connect to tlsnotary.org
openssl s_client -tls1_2 -curves prime256v1 -sigalgs "RSA+SHA256" -connect tlsnotary.org:443
# also connect to appliedzkp.org
openssl s_client -tls1_2 -curves prime256v1 -sigalgs "ECDSA+SHA256" -connect appliedzkp.org:443
# stop tcpdump and parse out the data
# get tcp stream id
NAME=tlsnotary.org # or appliedzkp.org 
STREAM_ID=$(tshark -r out.pcap -Y "tls.handshake.extensions_server_name contains $NAME" -T fields -e tcp.stream)

# client_random
tshark -r out.pcap -Y "tcp.stream==$STREAM_ID and tcp.dstport == 443" -T fields -e tls.handshake.random 
# server_random
tshark -r out.pcap -Y "tcp.stream==$STREAM_ID and tcp.srcport == 443" -T fields -e tls.handshake.random
# pubkey (ephemeral public key)
tshark -r out.pcap -Y "tcp.stream==$STREAM_ID" -T fields -e tls.handshake.server_point
# signature (over the key exchange parameters)
tshark -r out.pcap -Y "tcp.stream==$STREAM_ID" -T fields -e tls.handshake.sig