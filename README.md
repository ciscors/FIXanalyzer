# FIXanalyzer
It's a small python script parses PCAP files from tcpdump and provide information for delay between FIX HeartBeat and Response packets.
Data  into pcap files is populated  by following tcpdump args:

tcpdump -i p2p1 'host 10.10.10.1 && ((tcp[20:4]=0x383D4649 and tcp[24:1]=0x58 and tcp[38]=0x30) || 
              (tcp[tcpflags]=tcp-ack))'  -w 10.10.10.1.cap


IP 10.10.10.1 is a address of FIX server
