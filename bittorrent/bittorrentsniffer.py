#!/usr/bin/env python
# -*- coding: utf-8 -*-

from scapy.all import *
from scapy.utils import rdpcap

# helper methods
# ------------------------------------------------------

def detect_raw(pakt):
    """examines a packet to determine if it has a raw layer"""

    layer_list = list(detect_layers(pakt)) # place returned layers into a list
    if "Raw" in layer_list:
        return True
    else: return False

def detect_layers(x):
    """returns the next layer"""

    yield x.name
    while x.payload:
        x = x.payload
        yield x.name

def detect_torrent(packt):
    """given a packet, packt, detects the presence of BitTorrent protocol
    and prints a message if found
    """

    # retrieve payload from packet to look for "BitTorrent protocol"
    pkt_payload_string = str(packt.load)

    # detect if payload contains "BitTorrent protocol"
    if "BitTorrent protocol" in pkt_payload_string[1:25]:
        print(packt.summary())
        print("BitTorrent Protocol Found")

LIVE_SNIFFING_MODE = False # choose between pcap analysis mode or live sniffing mode

## static pcap analysis
if not LIVE_SNIFFING_MODE:

    ORIG_DIR = '/Users/benjaminleeds/Documents/Code/info341/bittorrent/pcap/'
    # PKTS = rdpcap(ORIG_DIR + "BitTorrent_single.pcap")
    PKTS = rdpcap(ORIG_DIR + "BitTorrent_multiple.pcap")
    # PKTS = rdpcap(ORIG_DIR + "BitTorrent_Mixed.pcap")

    for pkt in PKTS: #loop through each packet in pcap
        if detect_raw(pkt): # scan the layers of the packet to detect if it has a raw layer
            detect_torrent(pkt) # look for BitTorrent protocol in the packet's Raw-layer-payload

## live sniffing analysis
if LIVE_SNIFFING_MODE:

    # function inspects a packet and detects if it is a BitTorrent packet
    def bittorrentdetect(pakt):
        """BitTorrent detect method for input to sniff()"""

        if detect_raw(pakt):
            detect_torrent(pakt)
    # use filter to sniff only packets of a specific protocol
    print("Listening for BitTorrent traffic...")
    sniff(filter="ip", prn=bittorrentdetect)

# notes
# all packets accessed in array with single packet at pkt[0]
# because each time sniff() is called it sniffs one packet
    # pkt[0]: 1st packet in pkt array
    # pkt[0][1]: 1st layer of 1st pkt in pkt array, can also specify by protocol: pkt[0][ICMP]
    # pkt[0][1][1]: 1st layer of 1st pkt in pkt array, and so on...
