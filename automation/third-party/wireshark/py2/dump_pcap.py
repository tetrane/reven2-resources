#!/usr/bin/env python2

import argparse
import itertools
import os

import network_packet_tools as nw_tools

import reven2

from scapy.all import Ether, TCP, wrpcap

"""
Purpose:
    Generate a PCAP file containing all network packets that were sent/received in a trace.
    The timestamp of packets is replaced by the transition id where the packet was sent/received.

Dependencies:
    The script requires that the REVEN2 server have:
    * the Fast search enabled.
    * the OSSI enabled.
    * an access to the binary 'e1g6032e.sys' and its PDB file.
"""


def parse_args():
    parser = argparse.ArgumentParser(description='Dump a pcap from a trace. To get the time as transition ID in '
                                     'wireshark, select:\tView->Time display format->Seconds since '
                                     '1970-01-01\n')
    parser.add_argument('--host', metavar='host', dest='host', help='Reven host, as a string (default: "localhost")',
                        default='localhost', type=str)
    parser.add_argument('--port', metavar='port', dest='port', help='Reven port, as an int (default: 13370)',
                        type=int, default=13370)
    parser.add_argument('--filename', metavar='file_name', dest='file_name', help='the output '
                        'file name (default: "output.pcap"). Will be created if it doesn\'t exist',
                        default="output.pcap")
    parser.add_argument('--fix-checksum', dest='fix_checksum', action='store_true',
                        help='If not specified, the packet checksum won\'t be fixed and you will have the buffer that \
                        has been dumped from memory, and a lot of ugly packets in Wireshark, that you can also ignore \
                        if needed.')

    args = parser.parse_args()
    return args


def get_network_buffer_recv_RxPacketAssemble(ctx):
    packet_address = nw_tools.get_memory_address_and_size_of_received_network_packet(ctx)
    Buffer = None
    u32Size = None
    if packet_address[0] is not None and packet_address[1] is not None:
        u32Size = packet_address[1]
        # Get the buffer
        Buffer = ctx.read(packet_address[0], u32Size, raw=True)

    return Buffer, u32Size


def get_network_buffer_send_NdisSendNetBufferLists(ctx):
    packet_addresses = nw_tools.get_memory_addresses_and_sizes_of_sent_network_packet(ctx)
    Buffer = None
    u32Size = None
    # read buffer and join them
    for address in packet_addresses:
        if Buffer is None:
            Buffer = ctx.read(address[0], address[1])
            u32Size = address[1]
        else:
            Buffer += ctx.read(address[0], address[1])
            u32Size += address[1]

    return Buffer, u32Size


def get_all_send_recv(reven_server):
    print("[+] Get all sent/received packets...")

    send_queries, recv_queries = nw_tools.get_all_send_recv_packet_context(reven_server)

    # `reven2.util.collate` enables to iterate over multiple generators in a sorted way
    send_results = zip(reven2.util.collate(send_queries), itertools.repeat("send"))
    recv_results = zip(reven2.util.collate(recv_queries), itertools.repeat("recv"))

    # Return a sorted generator of both results regarding their context
    return reven2.util.collate([send_results, recv_results], lambda ctx_type: ctx_type[0])


def dump_pcap(reven_server, output_file="output.pcap", fix_checksum=False):
    if os.path.isfile(output_file):
        raise RuntimeError('\"{}\" already exists. Choose an other output file or remove it before running the script.'
                           .format(output_file))

    print("[+] Creating pcap from trace...")

    # Get all send and recv from the trace
    results = list(get_all_send_recv(reven_server))
    if len(results) == 0:
        print("[+] Finished: no network packets were sent/received in the trace")
        return

    # Get packets buffers and create the pcap file.
    print("[+] Convert packets to pcap format and write to file...")
    for ctx, ty in results:
        # Just detect if send or recv context
        if ty == "send":
            buf, size = get_network_buffer_send_NdisSendNetBufferLists(ctx)
        else:
            buf, size = get_network_buffer_recv_RxPacketAssemble(ctx)

        if buf is not None:
            packet = Ether(str(buf))

            # Here we check wether or not we have to fix checksum.
            if fix_checksum:
                if TCP in packet:
                    del packet[TCP].chksum

            # Replace the time in the packet by the transition ID, so that we get
            # it in Wireshark in a nice way.
            packet.time = ctx.transition_before().id

            # Write packet to pcap file
            wrpcap(output_file, packet, append=True)

    print("[+] Finished: PCAP file is \'{}\'.".format(output_file))


if __name__ == '__main__':
    args = parse_args()

    # Get a server instance
    reven_server = reven2.RevenServer(args.host, args.port)

    # Generate the PCAP file
    dump_pcap(reven_server, output_file=args.file_name, fix_checksum=args.fix_checksum)
