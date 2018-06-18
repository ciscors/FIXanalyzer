import dpkt
import datetime
import sys
import socket
import os



CAPSDIR="E:\\DASH-CAPS\\DUMP110618"
SRVIP = "192.168.9.142"






class FIX_PACKET:
    srcip = None
    dstip = None
    srcport = None
    dstport = None
    seqnum = None
    acknum = None
    timestamp = None
    type = None
    strts = None


def inet_to_str(inet):

    try:
        return socket.inet_ntop(socket.AF_INET, inet)
    except ValueError:
        return socket.inet_ntop(socket.AF_INET)

files = []
for i in os.listdir(CAPSDIR):
    if i.endswith('.cap') and i.startswith(SRVIP):
        files.append(i)

csvfile = CAPSDIR+"\\"+SRVIP+"-output.csv"
outfile = open(csvfile,"w")

for file in files:


    PACKETS = []
    APACKETS = []


    pcapfile = "E:\\DASH-CAPS\\DUMP110618\\"+file
    f = open(pcapfile,'rb')
    pcap = dpkt.pcap.Reader(f)


#Populate FIX packets

    for ts, buf in pcap:
        myfix = FIX_PACKET()
        eth = dpkt.ethernet.Ethernet(buf)
        ip = eth.data
        tcp = ip.data

        myfix.srcip = ip.src
        myfix.dstip = ip.dst
        myfix.srcport = tcp.sport
        myfix.dstport = tcp.dport
        myfix.acknum = tcp.ack
        myfix.seqnum = tcp.seq
        myfix.timestamp = ts
        myfix.strts = str(datetime.datetime.utcfromtimestamp(ts))

        if "8=FIX.4.2" in str(tcp.data):
            PACKETS.append(myfix)
        else:
            APACKETS.append(myfix)

#Analyze FIX packets

    for packet in PACKETS:

        for apacket in APACKETS:
            if packet.acknum == apacket.seqnum:

                diff_time = apacket.timestamp - packet.timestamp
                if diff_time > 0 and diff_time < 1:
                    print("%s %s" % (packet.strts,apacket.strts),end='')
                    print(" %s %d %s %d " % (inet_to_str(packet.srcip), packet.srcport, inet_to_str(apacket.srcip), apacket.srcport),end='')
                    print(' %3.6f'  % diff_time )
                    outstr = "{},{},{},{},{},{},{:3.6f}\n".format(packet.strts,apacket.strts,inet_to_str(packet.srcip),
                                                                  packet.srcport, inet_to_str(apacket.srcip), apacket.srcport,diff_time)
                    outfile.write(outstr)
    f.close()

outfile.close()



