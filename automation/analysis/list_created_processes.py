import argparse

import reven2
import percent


'''
Purpose:
    List all processes created in the trace.

Dependencies:
    The script requires that the REVEN2 server have:
    * the Memory history enabled (use percent example).
    * the Fast search enabled.
    * the OSSI enabled.
    * an access to the binaries 'kernel32.dll' and 'kernelbase.dll' and their PDB files.
'''


class Process(object):
    def __init__(self, name, pid, tid):
        self.name = name
        self.pid = pid
        self.tid = tid


def created_processes(reven):
    """
    Get all processes that were created during the trace (Windows 64 only).

    This is based on the call to the `CreateProcessInternalW` function of kernelbase.dll` and `kernel32.dll`.

    ```
    BOOL CreateProcessInternalW(
        LPCWSTR lpApplicationName, (rdx)
        LPWSTR lpCommandLine,      (r8)
        ...,
        LPPROCESS_INFORMATION lpProcessInformation (rsp + 0x58)
    )

    typedef struct _PROCESS_INFORMATION {
        HANDLE hProcess;   (+0x0)
        HANDLE hThread;    (+0x8)
        DWORD dwProcessId; (+0x10)
        DWORD dwThreadId;  (+0x14)
    } PROCESS_INFORMATION, *PPROCESS_INFORMATION, *LPPROCESS_INFORMATION;
    ```

    Dependencies
    ============

    The script requires that the REVEN2 server have:
    * the Memory history enabled (use percent example).
    * the Fast search enabled.
    * the OSSI enabled.
    * an access to the binaries 'kernel32.dll' and 'kernelbase.dll' and their PDB files.
    """
    queries = [rvn.trace.search.symbol(symbol) for symbol in rvn.ossi.symbols(pattern="CreateProcessInternalW",
                                                                              binary_hint="kernelbase.dll")]
    queries += [rvn.trace.search.symbol(symbol) for symbol in rvn.ossi.symbols(pattern="CreateProcessInternalW",
                                                                               binary_hint="kernel32.dll")]

    for match in reven2.util.collate(queries):
        call_tr = match.transition_before()
        instruction = call_tr.instruction
        if instruction is None:
            # This case should not happen since the RIP register of the context after an exception transition
            # is generally pointing to exception handling code, not `kernel32!CreateProcessInternalW` or
            # `kernelbase!CreateProcessInternalW` code.
            continue
        if instruction.mnemonic != 'call':
            # Certainly comes from a code page fault on the call instruction.
            # Never seen but possible.
            continue

        # Get process name from arguments lpApplicationName or lpCommandLine
        try:
            name = match.deref(reven2.arch.x64.rdx,
                               reven2.types.Pointer(reven2.types.CString(encoding=reven2.types.Encoding.Utf16,
                                                                         max_size=256)))
        except RuntimeError:
            name = match.deref(reven2.arch.x64.r8,
                               reven2.types.Pointer(reven2.types.CString(encoding=reven2.types.Encoding.Utf16,
                                                                         max_size=256)))

        # Get pointer to PROCESS_INFORMATION struct
        stack_pointer = match.read(reven2.arch.x64.rsp, reven2.types.Pointer(reven2.types.USize))
        process_info_pointer = match.read(stack_pointer + 0x58, reven2.types.Pointer(reven2.types.USize))

        # Go to the end of the function
        return_tr = percent.percent(rvn, call_tr)
        if return_tr is None:
            # Create process does not finish before the end of the trace
            continue

        return_value = return_tr.context_after().read(reven2.arch.x64.rax)
        if return_value == 0:
            # Create process failed
            continue

        # Get PID and TID from PROCESS_INFORMATION structure
        pid = return_tr.context_before().read(process_info_pointer + 0x10, 4)
        tid = return_tr.context_before().read(process_info_pointer + 0x14, 4)

        yield (call_tr, Process(name, pid, tid))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", type=str, default="localhost",
                        help='Reven host, as a string (default: "localhost")')
    parser.add_argument("-p", "--port", type=int, default="13370",
                        help='Reven port, as an int (default: 13370)')
    args = parser.parse_args()

    rvn = reven2.RevenServer(args.host, args.port)
    for transition, process in created_processes(rvn):
        print("#{}: name = {}, pid = {}, tid = {}".format(transition.id, process.name, process.pid, process.tid))
