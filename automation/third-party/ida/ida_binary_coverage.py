"""
Purpose:
    This script is a proof-of-concept for simple binary coverage: each executed instruction
    in a program will be colorized depending on its execution frequency.

Usage:
    Use IDA to load the binary and execute the script (Alt+F7).
    You will be asked to provide the following information:
        host = your REVEN server name, and
        port = your REVEN's project port on this host.

Performance:
    Very slow in the current implementation (will be improved in the future releases).
    It is not recommended to use this script on binaries that are very often executed during the
    trace, like `ntdll.dll`, `ntoskrnl.exe`, ...

Limitations:
    Very poor results for packed (or self-modifying) binaries (due to the
    limitations of IDA's static analysis)
"""

import os
import builtins

import idc
import idaapi

import reven2
from utils import colors


def find_binary(ossi, binary):
    binaries = list(ossi.executed_binaries(binary))
    if len(binaries) == 0:
        print("Binary \"{}\" not executed in the trace.".format(binary))
        exit(0)

    if len(binaries) == 1:
        return binaries[0]

    print("Multiple matches for \"{}\":".format(binary))
    for (index, binary) in enumerate(binaries):
        print("{}: {}".format(index, binary.path))
    answer = idc.AskStr("0", "Please choose one binary: ")
    return binaries[int(answer)]


def compute_coverage(search, binary):
    coverage = builtins.dict()
    for ctx in search.binary(binary):
        rva = ctx.ossi.location().rva
        try:
            coverage[rva] += 1
        except KeyError:
            coverage[rva] = 1
    return coverage


def ida_apply_colors(coverage, colors):
    base_address = idaapi.get_imagebase()
    for rva, freq in coverage.items():
        idaapi.set_item_color(base_address + rva, colors[freq])


def display_coverage(coverage):
    base_address = idaapi.get_imagebase()

    fmax = max(coverage.values())
    max_addresses = [hex(base_address + rva) for rva, freq in coverage.items() if freq == fmax]
    print('\nMax frequency: {}'.format(fmax))
    print('Addresses = {}'.format(max_addresses))

    fmin = min(coverage.values())
    min_addresses = [hex(base_address + rva) for rva, freq in coverage.items() if freq == fmin]
    print('\nMin frequency: {}'.format(fmin))
    print('Addresses = {}'.format(min_addresses))


def display_colors(colors):
    print("\nFrequency's color:")
    for freq, color in colors.items():
        print("{}: {:#x}".format(freq, color))


def main(host, port):
    print('\n**** Coverage Info *****')

    rvn = reven2.RevenServer(host, port)
    print("\n* REVEN Server: {}:{}".format(host, port))

    binary = find_binary(rvn.ossi, os.path.basename(idc.GetInputFilePath()).lower())
    print('\n* binary path: {}'.format(binary))

    print('\n* Compute Trace coverage')
    coverage = compute_coverage(rvn.trace.search, binary)
    display_coverage(coverage)

    print('\n* Compute frequency colors')
    fcolors = colors.compute_frequency_colors(coverage.values())
    display_colors(fcolors)

    print('\n* Apply colors in IDA')
    ida_apply_colors(coverage, fcolors)

    print('\n* Finished')


if __name__ == '__main__':
    try:
        host = idc.AskStr('localhost', "REVEN Server host:")
        port = int(idc.AskStr('13370', "REVEN Server port:"))
        main(host, port)
    except Exception as error:
        print('Error: {}'.format(error))
