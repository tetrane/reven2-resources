import argparse

import reven2
import reven_api

"""
Purpose:
    Get the transition that performs the `opposite` operation to the given transition.

Opposite operations:
    * The transition switches between user and kernel land.
      Examples:
          * a `syscall` transition => the related `sysret` transition
          * a `sysret` transition => the related `syscall` transition
          * a exception transition => the related `iretq` transition
          * a `iretq` transition => the related exception transition

    * The transition does memory accesses:
        * case 1: a unique access.
                  The access is selected.
        * case 1: multiple write accesses.
                  The first one is selected.
        * case 2: multiple read accesses.
                  The first one is selected.
        * case 3: multiple read and write accesses.
                  The first write access is selected.
                  This enable to get the matching `ret` transition
                  on an indirect call transition e.g. `call [rax + 10]`.
      If the selected access is a write then the next read access
      on the same memory is search for.
      If the selected access is a read then the previous write access
      on the same memory search for.

      Examples, percent on:
          * a `call` transition => the related `ret` transition.
          * a `ret` transition => the related `call` transition.
          * a `push` transition => the related `pop` transition.
          * a `pop` transition => the related `push` transition.

    If no related transition is found, `None` is returned.

Dependencies:
    The script requires that the REVEN2 server have the Memory history enabled.
"""


def previous_register_change(reven, register, from_transition):
    """
    Get the previous transition where the register's value changed.
    """
    range_size = 5000000
    start = reven_api.execution_point(from_transition.id)
    stop = reven_api.execution_point(max(from_transition.id - range_size, 0))
    result = reven._rvn.run_search_next_register_use(start, forward=False, read=False, write=True,
                                                     register_name=register.name, stop=stop)
    while result == stop:
        start = stop
        stop = reven_api.execution_point(max(start.sequence_identifier - range_size, 0))
        result = reven._rvn.run_search_next_register_use(start, forward=False, read=False, write=True,
                                                         register_name=register.name, stop=stop)
    if result.valid():
        return reven.trace.transition(result.sequence_identifier)
    return None


def next_register_change(reven, register, from_transition):
    """
    Get the next transition where the register's value changed.
    """
    range_size = 5000000
    start = reven_api.execution_point(from_transition.id)
    stop = reven_api.execution_point(from_transition.id + range_size)
    result = reven._rvn.run_search_next_register_use(start, forward=True, read=False, write=True,
                                                     register_name=register.name, stop=stop)
    while result == stop:
        start = stop
        stop = reven_api.execution_point(start.sequence_identifier + range_size)
        result = reven._rvn.run_search_next_register_use(start, forward=True, read=False, write=True,
                                                         register_name=register.name, stop=stop)
    if result.valid():
        return reven.trace.transition(result.sequence_identifier)
    return None


def previous_memory_use(reven, address, size, from_transition, operation=None):
    """
    Get the previous transition where the memory range [address ; size] is used (read/write).
    """
    try:
        access = next(reven.trace.memory_accesses(address, size, from_transition,
                                                  is_forward=False, operation=operation))
        return access.transition
    except StopIteration:
        return None


def next_memory_use(reven, address, size, from_transition, operation=None):
    """
    Get the next transition where the memory range [address ; size] is used (read/write).
    """
    try:
        access = next(reven.trace.memory_accesses(address, size, from_transition,
                                                  is_forward=True, operation=operation))
        return access.transition
    except StopIteration:
        return None


def percent(reven, transition):
    """
    This function is a helper to get the transition that performs
    the `opposite` operation to the given transition.

    If no opposite transition is found, `None` is returned.

    Opposite operations
    ===================

    * The transition switches between user and kernel land.
      Examples:
          * a `syscall` transition => the related `sysret` transition
          * a `sysret` transition => the related `syscall` transition
          * a exception transition => the related `iretq` transition
          * a `iretq` transition => the related exception transition

    * The transition does memory accesses:
        * case 1: a unique access.
                  The access is selected.
        * case 1: multiple write accesses.
                  The first one is selected.
        * case 2: multiple read accesses.
                  The first one is selected.
        * case 3: multiple read and write accesses.
                  The first write access is selected.
                  This enable to get the matching `ret` transition
                  on an indirect call transition e.g. `call [rax + 10]`.
      If the selected access is a write then the next read access
      on the same memory is search for.
      If the selected access is a read then the previous write access
      on the same memory search for.

      Examples, percent on:
          * a `call` transition => the related `ret` transition.
          * a `ret` transition => the related `call` transition.
          * a `push` transition => the related `pop` transition.
          * a `pop` transition => the related `push` transition.

    Dependencies
    ============

    The script requires that the REVEN2 server have the Memory history enabled.

    Usage
    =====

    It can be combined with other features like backtrace to obtain interesting results.

    For example, to jump to the end of the current function:
        >>> import reven2
        >>> from percent import percent
        >>> reven_server = reven2.RevenServer('localhost', 13370)
        >>> current_transition = reven_server.trace.transition(10000000)
        >>> ret_transition = percent(reven_server,
                                     current_transition.context_before().stack.frames[0].creation_transition)
    """
    ctx_b = transition.context_before()
    ctx_a = transition.context_after()

    # cs basic heuristic to handle sysenter/sysexit

    cs_b = ctx_b.read(reven2.arch.x64.cs)
    cs_a = ctx_a.read(reven2.arch.x64.cs)

    if cs_b > cs_a:
        # ss is modified by transition
        return next_register_change(reven, reven2.arch.x64.cs, transition)
    if cs_b < cs_a:
        # ss is modified by transition
        return previous_register_change(reven, reven2.arch.x64.cs, transition)

    # memory heuristic

    # first: check write accesses (get the first one)
    # this is to avoid failure on indirect call (1 read access then 1 write access)
    for access in transition.memory_accesses(operation=reven2.memhist.MemoryAccessOperation.Write):
        if access.virtual_address is None:
            # ignoring physical access
            continue
        return next_memory_use(reven, access.virtual_address, access.size, transition,
                               reven2.memhist.MemoryAccessOperation.Read)

    # second: check read accesses (get the first one)
    for access in transition.memory_accesses(operation=reven2.memhist.MemoryAccessOperation.Read):
        if access.virtual_address is None:
            # ignoring physical access
            continue
        return previous_memory_use(reven, access.virtual_address, access.size, transition,
                                   reven2.memhist.MemoryAccessOperation.Write)

    return None


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", type=str, default="localhost",
                        help='Reven host, as a string (default: "localhost")')
    parser.add_argument("-p", "--port", type=int, default="13370",
                        help='Reven port, as an int (default: 13370)')
    parser.add_argument("transition", type=int, help="Transition id, as an int")
    args = parser.parse_args()

    rvn = reven2.RevenServer(args.host, args.port)
    transition = rvn.trace.transition(args.transition)

    result = percent(rvn, transition)
    if result is not None:
        if result >= transition:
            print("=> {}".format(transition))
            print("<= {}".format(result))
        else:
            print("<= {}".format(transition))
            print("=> {}".format(result))
    else:
        print("No result found for {}".format(transition))
