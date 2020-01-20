"""
Purpose:
    This script is a proof-of-concept for resolving binary indirect breaking control flow instructions:
    A cross reference (xref) will be added in IDA on every executed indirect breaking control flow instruction.

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
    - The added xrefs are not necessarily complete (this is an inherent problem of dynamic analysis)
    - Results may be inconsistent in case of self-modifying or packed code.
"""

import os
import builtins

import idc
import idaapi
import idautils

import reven2


ida_dynamic_jump_types = [
    idaapi.NN_jmp,
    idaapi.NN_jmpfi,
    idaapi.NN_jmpni,
    idaapi.NN_jmpshort
]


ida_dynamic_call_types = [
    idaapi.NN_call,
    idaapi.NN_callfi,
    idaapi.NN_callni
]


ida_dynamic_ret_types = [
    idaapi.NN_retn,
    idaapi.NN_retf
]


# bfc = breaking control flow
reven_bfc_mnemonics = ['jmp', 'call', 'retn', 'retf']


def find_binary(ossi, binary):
    binaries = list(ossi.executed_binaries(binary))
    if len(binaries) == 0:
        print("Binary \"{}\" not executed in the trace.".format(binary))
        exit(0)

    if len(binaries) == 1:
        return binaries[0]

    print("Multiple match for \"{}\":".format(binary))
    for (index, binary) in enumerate(binaries):
        print("{}: {}".format(index, binary.path))
    answer = idc.AskStr("0", "Please choose one binary: ")
    return binaries[int(answer)]


def search_breaking_control_flow(search, binary):
    bfcs = []
    bfc_ctx = None
    bfc_tr = None
    for ctx in search.binary(binary):
        if bfc_ctx is not None:
            b_tr = ctx.transition_before()
            if bfc_tr == b_tr:
                bfcs.append((bfc_ctx, ctx, bfc_tr.instruction))
            bfc_ctx = None
            bfc_tr = None
        a_tr = ctx.transition_after()
        a_instr = a_tr.instruction
        if a_instr is None:
            continue
        if a_instr.mnemonic not in reven_bfc_mnemonics:
            continue
        bfc_ctx = ctx
        bfc_tr = a_tr
    return bfcs


def compute_trace_xrefs(bfcs):
    xrefs = builtins.dict()
    for src_ctx, target_ctx, instr in bfcs:
        src_pc = src_ctx.read(reven2.arch.x64.rip)
        target_pc = target_ctx.read(reven2.arch.x64.rip)
        if (src_pc, target_pc) in xrefs:
            continue
        src_rva = src_ctx.ossi.location().rva
        target_rva = target_ctx.ossi.location().rva
        xrefs[(src_pc, target_pc)] = (src_rva, target_rva, instr.mnemonic)
    return set(xrefs.values())


def ida_indirect_bfcs():
    bfcs = []
    for seg in idautils.Segments():
        for head in idautils.Heads(idc.SegStart(seg), idc.SegEnd(seg)):
            if idc.isCode(idc.GetFlags(head)):
                ins = idautils.DecodeInstruction(head)
                if ins is not None:
                    if ins.get_canon_feature() & idaapi.CF_JUMP:
                        if ins.itype in ida_dynamic_jump_types or \
                           ins.itype in ida_dynamic_call_types or \
                           ins.itype in ida_dynamic_ret_types:
                            if ins.ea not in bfcs:
                                bfcs.append(ins.ea)
    return bfcs


def convert_to_ida_indirect_xrefs(xrefs):
    indirect_xrefs = []
    base_address = idaapi.get_imagebase()
    indirect_bfcs = ida_indirect_bfcs()
    print('static bfcs: {}'.format([hex(bfc) for bfc in indirect_bfcs]))
    for src_rva, target_rva, mnemonic in xrefs:
        src_addr = base_address + src_rva
        target_addr = base_address + target_rva
        if src_addr not in indirect_bfcs:
            print('Not a an indirect xref: ({}) {:#x} -> {:#x}'.format(mnemonic, src_addr, target_addr))
            continue
        indirect_xrefs.append((src_addr, target_addr, mnemonic))
    return indirect_xrefs


def ida_apply_xrefs(xrefs):
    if len(xrefs) == 0:
        print('No indirect XREFS to apply')
    else:
        for src_addr, target_addr, mnemonic in xrefs:
            if mnemonic == 'jmp':
                success = idc.add_cref(src_addr, target_addr, idc.fl_JF)
            elif mnemonic == 'call':
                success = idc.add_cref(src_addr, target_addr, idc.fl_CF)
            else:  # mnemonic == 'ret'
                success = idc.add_cref(src_addr, target_addr, idc.fl_JF)
            if success:
                print('Create {} Xref: {:#x} -> {:#x}'.format(mnemonic, src_addr, target_addr))
            else:
                print('Failed to create {} Xref: {:#x} -> {:#x}'.format(mnemonic, src_addr, target_addr))


def main(host, port):
    print('\n**** Resolve executed XREFS *****')

    rvn = reven2.RevenServer(host, port)
    print("\n* REVEN Server: {}:{}".format(host, port))

    binary = find_binary(rvn.ossi, os.path.basename(idc.GetInputFilePath()).lower())
    print('\n* Binary path: {}'.format(binary))

    print('\n* Compute Trace XREFS')
    bfcs = search_breaking_control_flow(rvn.trace.search, binary)
    xrefs = compute_trace_xrefs(bfcs)

    print('\n* Convert Trace XREFS to IDA indirect XREFS')
    xrefs = convert_to_ida_indirect_xrefs(xrefs)

    print('\n* Apply XREFS in IDA')
    ida_apply_xrefs(xrefs)

    print('\n* Finish')


if __name__ == '__main__':
    try:
        host = idc.AskStr('localhost', "REVEN Server host:")
        port = int(idc.AskStr('13370', "REVEN Server port:"))
        main(host, port)
    except Exception as error:
        print('Error: {}'.format(error))
