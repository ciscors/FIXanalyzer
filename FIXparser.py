import dpkt
import datetime
import time
import sys
import socket
import os
from pytz import timezone
import numpy as np
import matplotlib.mlab as mlab
import matplotlib.pyplot as plt


DATA="1806"
CAPSDIR="E:\\DASH-CAPS\\DUMPS-"+DATA
SRVIP = "192.168.9.142"
debug = 0


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


DIFFS=[]

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
rawfile = CAPSDIR+"\\"+SRVIP+"-raw.csv"
small_rawfile = CAPSDIR+"\\"+SRVIP+"-smallraw.csv"

try:
    csv_outfile = open(csvfile, "w")
except IOError:
    print("Cant't open file $s " % csvfile)
try:
    raw_outfile = open(rawfile, "w")
except IOError:
    print("Cant't open file $s " % rawfile)

try:
    small_outfile = open(small_rawfile, "w")
except IOError:
    print("Cant't open file $s " % small_rawfile)

for file in files:

    PACKETS = []    #Packets with FIX Heartbeat
    APACKETS = []   #All other packets



    pcapfile = CAPSDIR+"\\"+file
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
        tstamp = datetime.datetime.fromtimestamp(ts)
        myfix.strts = str(tstamp.astimezone(timezone('US/Central')))
        dstIP = inet_to_str(myfix.dstip)

        if "8=FIX.4.2" in str(tcp.data) and dstIP == SRVIP:
            PACKETS.append(myfix)
        else:
            APACKETS.append(myfix)

#Analyze FIX packets
#Find pair FIX packets by ACKNUM and SEQNUM

    for packet in PACKETS:
        for apacket in APACKETS:
            if packet.acknum == apacket.seqnum:

                diff_time = apacket.timestamp - packet.timestamp
                #Exclude packets with negative and more then 1s time replay
                if diff_time > 0 and diff_time < 1:
                    if debug == 1:
                        print("%s %s" % (packet.strts,apacket.strts),end='')
                        print(" %s %d %s %d " % (inet_to_str(packet.srcip), packet.srcport, inet_to_str(apacket.srcip), apacket.srcport),end='')
                        print(' %3.6f'  % diff_time )

                    csv_outstr = "{},{},{},{},{},{},{:3.6f}\n".format(packet.strts, apacket.strts, inet_to_str(packet.srcip),
                                                                      packet.srcport, inet_to_str(apacket.srcip), apacket.srcport, diff_time)
                    csv_outfile.write(csv_outstr)

                    raw_outstr = "{:.0f},{:.0f},{},{},{},{},{:3.6f}\n".format(packet.timestamp, apacket.timestamp,
                                                                      inet_to_str(packet.srcip),
                                                                      packet.srcport, inet_to_str(apacket.srcip),
                                                                      apacket.srcport, diff_time)
                    raw_outfile.write(raw_outstr)

                    small_outstr = "{:.0f},{:3.6f}\n".format(packet.timestamp, diff_time)
                    small_outfile.write(small_outstr)
                    DIFFS.append(diff_time)

    f.close()



csv_outfile.close()
raw_outfile.close()
small_outfile.close()


PICFILE="E:\\picture\\"+SRVIP+"-"+DATA+".pdf"

num_bins = 100
range = (0.000001,0.0001)

n, bins, patches = plt.hist(DIFFS, num_bins, range, facecolor='blue', alpha=0.5)
plt.xlabel('microsec')
plt.ylabel('')
TITLE = SRVIP+"\n"+DATA+"18"
plt.title(TITLE)
plt.savefig(PICFILE)


