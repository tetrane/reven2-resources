import argparse

import reven2
from reven2.preview.project_manager import ProjectManager

"""
Purpose:
    Find which user-space binaries are responsible for a system call.

Dependencies:
    The script requires that the REVEN2 server have:

    - the Fast Search enabled,
    - the OSSI enabled,
    - A Windows x64 VM

    The script requires REVEN >= 2.3.
"""


#  Helper functions


def get_binary(ossi):
    """
    Retrieve the correct binary in which to search for the symbol (ntoskrnl.exe)

    - ossi: a reven2.ossi.Ossi instance
    """
    UNAVAILABLE_OSSI = "Could not find {binary}. Please check OSSI availability and that the trace has a supported OS."
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


def get_matches(search, symbol):
    """
    Retrieve pairs of (context, process) indicating which process made the syscall at context

    - search: a reven2.search.Search instance
    - symbol: a symbol obtained from calling get_symbol
    """
    for ctx in search.symbol(symbol):
        yield (ctx, ctx.ossi.process())


# Main


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description="Find which user-space processes are responsible for the specified system call.")
    #  These arguments are common to most REVEN scripts
    parser.add_argument("--url", type=str, default="http://localhost:8880",
                        help='Reven Project Manager URL (default: "http://localhost:8880")')
    parser.add_argument("project", type=str,
                        help='Reven project to open')
    #  Arguments specific to the script
    parser.add_argument("symbol", type=str,
        help="The symbol to search, as a regular expression. It must be "
        "a system call symbol in ntoskrnl.exe. If several symbols match the "
        "regexp, an error will be raised.")
    args = parser.parse_args()

    # Connect to REVEN Project Manager
    pm = ProjectManager(args.url)
    # Connect to the REVEN server whose name corresponds to the "project" argument
    # (This will start the server if necessary)
    connection = pm.connect(args.project)

    server = connection.server

    binary = get_binary(server.ossi)

    symbol = get_symbol(binary, args.symbol)

    matches = get_matches(server.trace.search, symbol)

    # print all matches
    for (ctx, process) in matches:
        if process is not None:
            print("{}: {}".format(ctx, process.name))
