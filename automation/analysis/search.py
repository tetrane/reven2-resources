import argparse

import reven2


'''
Purpose:
    Search in a whole trace one of the following points of interest:
    * an executed symbol
    * an executed binary
    * an executed virtual address

Dependencies:
    The script requires that the REVEN2 server have:
    * the Fast search enabled.
    * the OSSI enabled.
'''


def search(reven_server, symbol=None, binary=None, pc=None, case_sensitive=False):
    """
    This function is a helper to search easily one of the following points of interest:
    * executed symbols
    * executed binaries
    * an executed virtual address

    The matching contexts are returned in ascending order.

    Examples
    ========

    >>> # Search for RIP = 0x7fff57263b2f
    >>> for ctx in search(reven_server, pc=0x7fff57263b2f):
    >>>     print(ctx)
    Context before #240135
    Context before #281211
    Context before #14608067
    Context before #14690369
    Context before #15756067
    Context before #15787089
    ...

    >>> # Search for binary "kernelbase.dll"
    >>> for ctx in search(reven_server, binary='kernelbase\.dll'):
    >>>     print(ctx)
    Context before #240135
    Context before #240136
    Context before #240137
    Context before #240138
    Context before #240139
    Context before #240140
    Context before #240141
    ...

    >>> # Search for binaries that contains "\.exe"
    >>> for ctx in search(reven_server, binary='\.exe'):
    >>>     print(ctx)
    Context before #1537879110
    Context before #1537879111
    Context before #1537879112
    Context before #1537879113
    Context before #1537879372
    Context before #1537879373
    Context before #1537879374
    ...

    >>> # Search for all symbol symbols that contains "acpi"
    >>> for ctx in search(reven_server, symbol='acpi'):
    >>>     print(ctx)
    Context before #1471900961
    Context before #1471903808
    Context before #1471908093
    Context before #1471914935
    Context before #1472413834
    Context before #1472416173
    Context before #1472419063
    ...

    >>> # Search for symbol "CreateProcessW" in binary "kernelbase.dll"
    >>> for ctx in search(reven_server, symbol='^CreateProcessW$', binary='kernelbase\.dll'):
    >>>     print(ctx)
    Context before #23886919
    Context before #1370448535
    Context before #2590849986

    Information
    ===========

    @param reven_server: A C{reven2.RevenServer} instance.
    @param symbol: A symbol regex pattern.
                   Can be complete with the `binary` argument.
    @param binary: A binary regex pattern.
    @param pc: A virtual address integer.
    @param case_sensitive: Whether the symbol pattern comparison is case sensitive or not.

    @return: A generator of C{reven2.trace.Context} instances.
    """
    search = reven_server.trace.search
    if pc is not None:
        return search.pc(pc)

    if binary is not None:
        if symbol is not None:
            queries = [search.symbol(rsymbol) for rsymbol in reven_server.ossi.symbols(pattern=symbol,
                                                                                       binary_hint=binary,
                                                                                       case_sensitive=case_sensitive)]
        else:
            queries = [search.binary(rbinary) for rbinary in reven_server.ossi.executed_binaries(pattern=binary)]
        return reven2.util.collate(queries)

    if symbol is not None:
        queries = [search.symbol(rsymbol) for rsymbol in reven_server.ossi.symbols(pattern=symbol,
                                                                                   case_sensitive=case_sensitive)]
        return reven2.util.collate(queries)

    raise ValueError("You must provide something to search")


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", type=str, default="localhost",
                        help='Reven host, as a string (default: "localhost")')
    parser.add_argument("-p", "--port", type=int, default="13370",
                        help='Reven port, as an int (default: 13370)')
    parser.add_argument("-s", "--symbol", type=str, help="symbol pattern")
    parser.add_argument("-b", "--binary", type=str, help="binary pattern")
    parser.add_argument("-a", "--pc", type=lambda a: int(a, 0), help="pc address")
    parser.add_argument("--case-sensitive", action="store_true", help="case sensitive symbol search")
    args = parser.parse_args()

    reven_server = reven2.RevenServer(args.host, args.port)
    for ctx in search(reven_server, symbol=args.symbol, binary=args.binary, pc=args.pc,
                      case_sensitive=args.case_sensitive):
        try:
            tr = ctx.transition_after()
            print("#{}: {}".format(tr.id, ctx.ossi.location()))
        except IndexError:
            tr = ctx.transition_before()
            print("#{}: {}".format(tr.id + 1, ctx.ossi.location()))
