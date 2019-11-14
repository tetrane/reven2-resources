"""
This module introduces two functions. The first one is used to get the memory address and the size of the buffer
used to receive a network packet. While the second one is used to return a list of memory addresses and
sizes of buffers used to send a network packet.

"""

import reven2


def get_memory_address_and_size_of_received_network_packet(ctx):
    """
    This function returns a pair of memory address, size of the received packet
    'ctx' must be a context resulting from searching "RxPacketAssemble" symbol in the trace

    Information
    ===========

    @param ctx: the context used to retrieve the list of memory address and size of sent packet buffer

    @return a list of tuples of L{address.LogicalAddress} and C{int}
    """

    # To get the memory address of received packets, we need to dereference multiple times some pointers in memory.
    # The first one is rcx, as argument. It points to a huge structure.
    # at rcx+0x308 is a pointer to a structure, which contains the size at +8
    # at rcx+0x328 is a pointer index that points the right structure to get for the buffer
    # at rcx+0x328+8 * index is a pointer to the network buffer.

    # at rcx+0x308, then deref +0xc is a byte that is tested at 1 and 2. If 0, then the call to RxPacketAssemble is
    # the last one of a serie and doesn't contain any buffer to fetch.

    # Get a pointer to the huge structure
    pHugeStruct = ctx.read(reven2.arch.x64.rcx, reven2.types.Pointer(reven2.types.USize))

    # Deref to get a pointer to the structure that contains the size
    pSizeStruct = ctx.read(pHugeStruct + 0x308, reven2.types.Pointer(reven2.types.USize))

    u8Flag = ctx.read(pSizeStruct + 0xc, reven2.types.U8)

    # Is last packet part?
    if (u8Flag & 0x3) == 0:
        return None, None

    u32Size = ctx.read(pSizeStruct + 0x8, reven2.types.U32)

    # Next get the index in the structure
    pu32IndexRaw = ctx.read(pHugeStruct + 0x328, reven2.types.Pointer(reven2.types.USize))

    # The index is a dword (eax is used)
    u32IndexRaw = ctx.read(pu32IndexRaw, reven2.types.U32)

    # Now, the system perform an operation on this index.
    u32Index = (u32IndexRaw + u32IndexRaw * 2) * 2

    # Now get a pointer to the buffer
    pArray = ctx.read(pHugeStruct + 0x328, reven2.types.Pointer(reven2.types.USize)) + 8
    pBuffer = ctx.read(pArray + 8 * u32Index + 0x20, reven2.types.Pointer(reven2.types.USize))

    return pBuffer, u32Size


def get_memory_addresses_and_sizes_of_sent_network_packet(ctx):
    """
    This Function returns a list of memory address, size of a sent packet

    'ctx' must be a context resulting from searching "E1000SendNetBufferLists" symbol in the trace

    Information
    ===========

    @param ctx: the context used to retrieve the memory address and size of received packet buffer

    @return a tuple of L{address.LogicalAddress} and C{int}
    """

    # The NET_BUFFER_LIST has a pointer to the first NET_BUFFER at +8
    # The NET_BUFFER has multiple important thing.
    #     The first entry (+0) is a pointer to the next NET_BUFFER
    #     The second entry (+8) is a pointer to an MDL
    #     The third entry (+0x10) is a pointer to the offset inside the MDL, for the data.

    pNetBufferList = ctx.read(reven2.arch.x64.rdx, reven2.types.Pointer(reven2.types.USize))
    pNetBuffer = ctx.read(pNetBufferList + 0x8, reven2.types.Pointer(reven2.types.USize))

    # The first part of the buffer need an offset in the MDL. Seems like the other one don't.
    pMdl = ctx.read(pNetBuffer + 0x8, reven2.types.Pointer(reven2.types.USize))
    pMdlOffset = ctx.read(pNetBuffer + 0x10, reven2.types.U32)

    packet_memory_addresses = []
    packet_memory_addresses.append(_get_network_packet_address_from_mdl(ctx, pMdl, pMdlOffset=pMdlOffset))

    # Next, check other mdl if they exist, and get the buffer for each one of them
    pNextMdl = ctx.read(pMdl, reven2.types.Pointer(reven2.types.USize))

    while (pNextMdl.offset != 0):
        packet_memory_addresses.append(_get_network_packet_address_from_mdl(ctx, pNextMdl))

        pNextMdl = ctx.read(pNextMdl, reven2.types.Pointer(reven2.types.USize))
    return packet_memory_addresses


def get_all_send_recv_packet_context(reven_server):
    """
    This function return a list of all contexts used to send or receive network packets.

    To get these contexts, this function searches the symbol `E1000SendNetBufferLists` to get contexts of
    sent network packets. and searches the symbol `RxPacketAssemble` to get contexts of received network packets.

    This function requires that the trace has the PDB of `e1g6032e.sys` binary otherwise no context will be found.

    'reven_server' is the L{reven2.RevenServer} instance on which to perform the search

    Information
    ===========

    @param reven_server: L{reven2.RevenServer} instance on which to search packets

    @return a tuple of send packet list and received packet list
    """
    # Get generators of search results
    send_queries = [reven_server.trace.search.symbol(symbol) for symbol in reven_server.ossi.symbols(
        pattern="E1000SendNetBufferLists",
        binary_hint="e1g6032e.sys")]
    recv_queries = [reven_server.trace.search.symbol(symbol) for symbol in reven_server.ossi.symbols(
        pattern="RxPacketAssemble",
        binary_hint="e1g6032e.sys")]

    if len(send_queries) == 0 and len(recv_queries) == 0:
        print("No network packets exist in this trace, make sure that this trace is a network trace,"
              " and if it is, make sure that the PDB of `e1g6032e.sys` binary is available in the scenario")

    return send_queries, recv_queries


def _get_network_packet_address_from_mdl(ctx, pMdl, pMdlOffset=0):
    """
    Here is the structure MDL
    typedef struct _MDL {
      struct _MDL      *Next;
      CSHORT           Size;
      CSHORT           MdlFlags;
      struct _EPROCESS *Process;
      PVOID            MappedSystemVa;
      PVOID            StartVa;
      ULONG            ByteCount;
      ULONG            ByteOffset;
    } MDL, *PMDL;

    In our case, we get the StartVa, the byte count, and the offset from the NET_BUFFER
    """

    pBufferStartVa = ctx.read(pMdl + 0x18, reven2.types.Pointer(reven2.types.USize))

    u32Size = ctx.read(pMdl + 0x28, reven2.types.U32)

    return pBufferStartVa + pMdlOffset, u32Size - pMdlOffset
