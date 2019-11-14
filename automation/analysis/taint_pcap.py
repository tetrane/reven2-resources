import argparse
import itertools

import reven2

import network_packet_tools as nw_tools

from reven2.preview.taint import TaintedMemories
from reven2.preview.taint import Tainter

"""
Purpose:
    Display the list of function that handles every network packets that were sent/received in a trace.

Dependencies:
    The script requires that the REVEN2 server have:
    * the Fast search enabled.
    * the OSSI enabled.
    * an access to the binary 'e1g6032e.sys' and its PDB file.
"""


def parse_args():
    parser = argparse.ArgumentParser(description='Taint every pcap from a trace.')
    parser.add_argument('--host', metavar='host', dest='host', help='Reven host, as a string (default: "localhost")',
                        default='localhost', type=str)
    parser.add_argument('--port', metavar='port', dest='port', help='Reven port, as an int (default: 13370)',
                        type=int, default=13370)
    parser.add_argument('--symbol', metavar='symbols', action='append', dest='symbols',
                        help='Symbol name that maybe the packet '
                        'goes through, as a string (default ""). This argument can be repeated.', type=str, default=[])

    parser.add_argument('--recv-only', dest='recv_only', action='store_true', help='If specified, handle received'
                        'packets only ')

    args = parser.parse_args()
    return args


def get_memory_range_of_received_network_packet(ctx):
    info = nw_tools.get_memory_address_and_size_of_received_network_packet(ctx)
    if info[0] is None or info[1] is None:
        return None
    return TaintedMemories(info[0], info[1])


def get_memory_range_of_sent_network_packet(ctx):
    infos = nw_tools.get_memory_addresses_and_sizes_of_sent_network_packet(ctx)
    tainted_mems = []
    for info in infos:
        tainted_mems.append(TaintedMemories(info[0], info[1]))
    return tainted_mems


def get_all_send_recv(rvn, recv_only=False):
    print("[+] Get all sent/received packets...")

    send_queries, recv_queries = nw_tools.get_all_send_recv_packet_context(rvn)

    # `reven2.util.collate` enables to iterate over multiple generators in a sorted way
    if recv_only:
        return zip(reven2.util.collate(recv_queries), itertools.repeat("recv"))

    send_results = zip(reven2.util.collate(send_queries), itertools.repeat("send"))
    recv_results = zip(reven2.util.collate(recv_queries), itertools.repeat("recv"))

    # Return a sorted generator of both results regarding their context
    return reven2.util.collate([send_results, recv_results], lambda ctx_type: ctx_type[0])


def found_symbol(current_symbol, user_symbols):
    for sym in user_symbols:
        if sym.lower() in current_symbol.name.lower():
            return True
    return False


def taint_pcap(reven_server, recv_only=False, user_symbols=[]):
    # Initialize Tainter
    tainter = Tainter(reven_server.trace)
    # Get all send and recv from the trace
    results = list(get_all_send_recv(reven_server, recv_only))
    if len(results) == 0:
        print("[+] Finished: no network packets were sent/received in the trace")
        return

    # Get packets memory range
    for ctx, ty in results:
        # Just detect if send or recv context
        # Taint packet in forward when it is received and in backward when it is sent
        is_forward = False if ty == "send" else True
        mem_range = get_memory_range_of_sent_network_packet(ctx) if ty == "send" else\
            get_memory_range_of_received_network_packet(ctx)

        if mem_range is None or isinstance(mem_range, list) and len(mem_range) == 0:
            continue

        taint = tainter.simple_taint(tag0=mem_range, from_context=ctx, is_forward=is_forward)

        print("\n=====================================================================================")
        print("[+]{} - {} packet at address {}".format(
            ctx.transition_before(),
            "Received" if is_forward else "Sent",
            mem_range if is_forward else ["{}".format(mem) for mem in mem_range]))

        last_symbol = None
        for change in taint.changes().all():
            loc = change.transition.context_before().ossi.location()
            if loc is None:
                continue
            symbol = loc.symbol
            if symbol is None or last_symbol is not None and symbol == last_symbol:
                continue
            if len(user_symbols) == 0 or found_symbol(symbol, user_symbols):
                # if user_symbols is an empty list then no requested symbols, don't filter output
                print("{}: {}".format(change.transition, symbol))
                last_symbol = symbol

        print("=====================================================================================\n")

    print("[+] Finished: tainting all pcap in the trace")


if __name__ == '__main__':

    args = parse_args()

    print("[+] Start tainting pcap from trace...")

    # Get a server instance
    rvn = reven2.RevenServer(args.host, args.port)

    taint_pcap(rvn, args.recv_only, args.symbols)
