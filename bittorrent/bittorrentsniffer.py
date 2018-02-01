#!/usr/bin/env python
# -*- coding: utf-8 -*-

from scapy.all import *
from scapy.utils import rdpcap

liveSniffingMode = False # choose between pcap analysis mode or live sniffing mode

## pcap analysis
if not liveSniffingMode:

    ORIG_DIR = '/Users/benjaminleeds/Documents/Code/info341/bittorrent/pcap/'
    pkts = rdpcap(ORIG_DIR + "BitTorrent_single.pcap")

    for pkt in pkts: #loop through each packet in pcap
        # look for handshake w/ BitTorrent protocol
        # print(el)
        #inspect it
        # see if there's any pattern you can find
        pkt_payload = pkt[0].payload # retrieve payload from packet to look for "BitTorrent protocol"
    
        # loop over characters in payload to look for "BitTorrent protocol"
        for char in pkt_payload:
            print(type(char))

## live sniffing analysis
if liveSniffingMode:

    # print( isinstance(scapy.packet.NoPayload, scapy.packet.NoPayload))

    def bittorrentdetect(pkt):

        # all packets accessed in array with single packet at pkt[0] because each time sniff() is called it sniffs one packet
        # pkt[0]: 1st packet in pkt array
        # pkt[0][1]: 1st layer of 1st pkt in pkt array, can also specify by protocol: pkt[0][ICMP]

        print( pkt.summary())

        # print( type(pkt[0][1][1].payload))

        # print("the payload is: ")
        # print( type(pkt[0][1][1].payload))

        # if not isinstance( type(pkt[0][1][1].payload), type(scapy.packet.NoPayload) ): # check for no payload
    
        # if type(pkt[0][1][1].payload is scapy.packet.NoPayload ) : 
            # print("###")
        
    sniff(filter="ip", prn=bittorrentdetect) # use filter to sniff only packets of a specific protocol
