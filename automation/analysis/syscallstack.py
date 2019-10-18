import argparse

import reven2

"""
Purpose:
    Find which user-space binaries are responsible for a system call.

Dependencies:
    The script requires that the REVEN2 server have:

    - the Fast Search enabled,
    - the OSSI enabled,
    - A Windows x64 VM
"""


#  Helper functions


def get_binary(ossi, is_user_stub):
    """
    Retrieve the correct binary in which to search for the symbol depending on the heuristic to use

    - ossi: a reven2.ossi.Ossi instance
    - is_user_stub: if True, look for user-space stubs in ntdll rather than kernel space syscalls in ntoskrnl
    """
    UNAVAILABLE_OSSI = "Could not find {binary}. Please check OSSI availability and that the trace has a supported OS."
    if is_user_stub:
        try:
            return next(server.ossi.executed_binaries("^c:/windows/system32/ntdll.dll$"))
        except StopIteration:
            raise RuntimeError(UNAVAILABLE_OSSI.format(binary="ntdll.dll"))
    else:
        try:
            return next(server.ossi.executed_binaries("^c:/windows/system32/ntoskrnl.exe$"))
        except StopIteration:
            raise RuntimeError(UNAVAILABLE_OSSI.format(binary="ntoskrnl.exe"))


def get_symbol(binary, regexp):
    """
    Retrieve the system call symbol from the binary

    - binary: binary obtained from calling get_binary
    - regexp: regular expression that should match a unique symbol in the binary
    """

    #  By converting to a list, we are performing eager evaluation of the binary.symbols query.
    #  In general, this could take a longer time than necessary.
    #  Here, in worst case, all symbols of the binary match the regexp. This should result in a reasonable time.
    #  Hence, we use a list, which allow us to easily retrieve its length (the number of matches).
    symbols = list(binary.symbols(regexp))
    if len(symbols) == 0:
        raise RuntimeError("Symbol not found in {} from regexp '{}'".format(binary.name, regexp))
    if len(symbols) > 1:
        raise RuntimeError("{} matches found in {} for regexp '{regexp}'.\n\tHint: Try restricting the regexp by "
                           "enclosing ^$ around it: '^{regexp}$'".format(
                               len(symbols), binary.name, regexp=regexp))

    return symbols[0]


def get_matches(search, symbol, is_user_stub):
    """
    Retrieve pairs of (context, binary?) indicating which binary made the syscall at context

    - search: a reven2.search.Search instance
    - symbol: a symbol obtained from calling get_symbol
    - is_user_stub: if False, use the previous backtrace heuristics
    """
    for ctx in search.symbol(symbol):
        if is_user_stub:
            stack = ctx.stack
        else:
            stack = ctx.stack.prev_stack()
        yield (ctx, find_binary(stack))


def find_binary(stack):
    """
    Attempts to find the first ring3 binary in a stack.

    - stack: a reven2.stack.Stack
    """
    for frame in stack.frames():
        fr_ctx = frame.first_context
        ring = fr_ctx.read(reven2.arch.x64.cs) & 3
        if ring == 0:
            continue
        location = fr_ctx.ossi.location()
        if location is None:
            continue
        binary = location.binary
        if binary.filename.endswith(".exe"):
            return binary
    return None


# Main


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description="Find which user-space binaries are responsible for the specified system call.")
    #  These arguments are common to most REVEN scripts
    parser.add_argument("--host", type=str, default="localhost",
                        help='Reven host, as a string (default: "localhost")')
    parser.add_argument("-p", "--port", type=int, default="13370",
                        help='Reven port, as an int (default: 13370)')
    #  Arguments specific to the script
    parser.add_argument("symbol", type=str,
        help="The symbol to search, as a regular expression. If --user-stub is specified, then it is a user-space "
        "stub in ntdll.dll. Otherwise, it is a system call symbol in ntoskrnl.exe. If several symbols match the "
        "regexp, an error will be raised.")
    parser.add_argument("--user-stub", action='count', default=0,
       help="If provided, then use the user-space stub method instead of the previous stack heuristic method")
    args = parser.parse_args()

    server = reven2.RevenServer(args.host, args.port)

    is_user_stub = args.user_stub != 0

    binary = get_binary(server.ossi, is_user_stub)

    symbol = get_symbol(binary, args.symbol)

    matches = get_matches(server.trace.search, symbol, is_user_stub)

    # print all matches
    for (ctx, binary) in matches:
        if binary is not None:
            print("{}: {}".format(ctx, binary.name))
