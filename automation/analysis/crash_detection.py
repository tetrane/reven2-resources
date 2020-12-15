#!/usr/bin/env python3

import argparse

import reven2

"""
Purpose:
    Detect and report crashes and exceptions that appear during the trace.

This script detects system crashes that occur inside of a trace, as well as exceptions thrown in user space.
Because user space processes can catch exceptions, a user exception reported by this script does not necessarily
means that the involved user space process crashed after causing the exception.

Supported OS version: Windows 10 x64.

Dependencies:
    The script requires that the REVEN2 server have:
    * the Fast search enabled.
    * the OSSI enabled.
    * the backtrace enabled.
"""

HIGH_LEVEL_EXCEPTION_CODES = {
    0x80000003: 'breakpoint',
    0x80000004: 'single step debug',
    0xc000001d: 'illegal instruction',
    0xc0000094: 'integer division by zero',
    0xc0000005: 'access violation',
    0xc0000409: 'stack buffer overrun',
}

# Obtained by reversing the transformations performed on high level exception codes
# Some of the crashes find the low-level exception codes rather than the high-level ones
LOW_LEVEL_EXCEPTION_CODES = {
    0x80000003: 'breakpoint',
    0x80000004: 'single step debug',
    0x10000002: 'illegal instruction',
    0x10000003: 'integer division by zero',
    0x10000004: 'access violation',
}


class SystemCrash:
    # Code values recovered here:
    # https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/bug-check-code-reference2
    PF_BUG_CHECK_CODES = [0x50, 0xCC, 0xCD, 0xD5, 0xD6]
    EXCEPTION_BUG_CHECK_CODES = [0x1E, 0x7E, 0x8E, 0x8E, 0x135, 0x1000007E, 0x1000008E]
    SYSTEM_SERVICE_EXCEPTION = 0x3B
    KERNEL_SECURITY_CHECK_FAILURE = 0x139

    def __init__(self, trace, dispatcher_ctx):
        self._trace = trace
        self._dispatch_ctx = dispatcher_ctx
        self._bug_check_code = dispatcher_ctx.read(reven2.arch.x64.ecx)
        self._error_code = None
        self._page_fault_address = None
        self._page_fault_operation = None
        self._process = dispatcher_ctx.ossi.process()
        if self._bug_check_code in SystemCrash.PF_BUG_CHECK_CODES:
            # page fault address is the 2nd parameter of KeBugCheckEx call for PAGE_FAULT bug checks.
            # operation is 3rd parameter of KeBugCheckEx. See for instance:
            # https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/bug-check-0xcc--page-fault-in-freed-special-pool
            self._page_fault_address = dispatcher_ctx.read(reven2.arch.x64.rdx)
            self._page_fault_operation = dispatcher_ctx.read(reven2.arch.x64.r8)
        elif self._bug_check_code in SystemCrash.EXCEPTION_BUG_CHECK_CODES:
            # error code is the 2nd parameter of KeBugCheckEx call for EXCEPTION bug checks. See for instance:
            # https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/bug-check-0x1e--kmode-exception-not-handled
            self._error_code = dispatcher_ctx.read(reven2.arch.x64.edx)
        elif self._bug_check_code == SystemCrash.KERNEL_SECURITY_CHECK_FAILURE:
            # error code can be found as the first member of the exception structure that is 4th parameter of
            # KeBugCheckEx call. See:
            # https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/bug-check-0x139--kernel-security-check-failure
            # https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-exception_record
            self._error_code = dispatcher_ctx.deref(reven2.arch.x64.r9, reven2.types.Pointer(reven2.types.U32))
        elif self._bug_check_code == SystemCrash.SYSTEM_SERVICE_EXCEPTION:
            self._error_code = dispatcher_ctx.read(reven2.arch.x64.edx)
        # Look for the exception transition in the backtrace, if any is found
        self._exception_transition = None
        for frame in dispatcher_ctx.transition_before().context_before().stack.frames():
            if frame.creation_transition is not None and frame.creation_transition.exception:
                self._exception_transition = frame.creation_transition
                break

    @property
    def dispatch_ctx(self):
        return self._dispatch_ctx

    @property
    def exception_transition(self):
        return self._exception_transition

    @property
    def error_code(self):
        return self._error_code

    @property
    def bug_check_code(self):
        return self._bug_check_code

    @property
    def page_fault_address(self):
        return self._page_fault_address

    @property
    def page_fault_operation(self):
        return self._page_fault_operation

    @property
    def process(self):
        return self._process


class UserCrash:
    def __init__(self, trace, dispatcher_ctx):
        self._trace = trace
        self._dispatch_ctx = dispatcher_ctx
        self._exception_transition = None
        self._process = dispatcher_ctx.ossi.process()
        try:
            frame = next(dispatcher_ctx.transition_before().context_before().stack.frames())
            self._exception_transition = frame.first_context.transition_before()
        except StopIteration:
            pass

        self._error_code = None
        # heuristic: go back some transitions to get good stack trace
        ctx_before_rsp_changed = dispatcher_ctx - 8
        frames = ctx_before_rsp_changed.stack.frames()
        try:
            ki_exception_dispatch_ctx = next(frames).first_context
            self._error_code = ki_exception_dispatch_ctx.read(reven2.arch.x64.ecx)
        except StopIteration:
            pass

    @property
    def dispatch_ctx(self):
        return self._dispatch_ctx

    @property
    def exception_transition(self):
        return self._exception_transition

    @property
    def error_code(self):
        return self._error_code

    @property
    def process(self):
        return self._process


def detect_system_crashes(server):
    try:
        ntoskrnl = next(server.ossi.executed_binaries("ntoskrnl"))
    except StopIteration:
        raise RuntimeError("Could not find the ntoskrnl binary. "
                           "Is this a Windows 10 trace with OSSI enabled?")

    try:
        ke_bug_check_ex = next(ntoskrnl.symbols("KeBugCheckEx"))
    except StopIteration:
        raise RuntimeError("Could not find the KeBugCheckEx symbol in ntoskrnl. "
                           "Is this a Windows 10 trace with OSSI enabled?")

    for call in server.trace.search.symbol(ke_bug_check_ex):
        yield SystemCrash(server.trace, call)


def detect_user_crashes(server):
    try:
        ntdll = next(server.ossi.executed_binaries("ntdll"))
    except StopIteration:
        raise RuntimeError("Could not find the ntdll binary. "
                           "Is this a Windows 10 trace with OSSI enabled?")
    try:
        ki_user_exception_dispatcher = next(ntdll.symbols("KiUserExceptionDispatch"))
    except StopIteration:
        raise RuntimeError("Could not find the KiUserExceptionDispatch symbol in ntdll. "
                           "Is this a Windows 10 trace with OSSI enabled?")

    for call in server.trace.search.symbol(ki_user_exception_dispatcher):
        yield UserCrash(server.trace, call)


def format_exception_code(error_code):
    if error_code is None:
        return None
    if error_code in HIGH_LEVEL_EXCEPTION_CODES:
        return "{} ({:#x})".format(HIGH_LEVEL_EXCEPTION_CODES[error_code], error_code)
    elif error_code in LOW_LEVEL_EXCEPTION_CODES:
        return "{} ({:#x})".format(LOW_LEVEL_EXCEPTION_CODES[error_code], error_code)
    return "unknown or incorrect exception code: {:#x}".format(error_code)


def format_page_fault(page_fault_address, page_fault_operation):
    if page_fault_address is None:
        return None
    # operations changed recently for bug check 0x50. It should work with any version though. See:
    # https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/bug-check-0x50--page-fault-in-nonpaged-area#page_fault_in_nonpaged_area-parameters
    if page_fault_operation == 0:
        operation = "reading"
    elif page_fault_operation == 1 or page_fault_operation == 2:
        operation = "writing"
    elif page_fault_operation == 10:
        operation = "executing"
    else:
        return "page fault on address {:#x}".format(page_fault_address)

    return "page fault while {} address {:#x}".format(operation, page_fault_address)


def format_cause(error_code=None, page_fault_address=None, page_fault_operation=None):
    exception_fmt = format_exception_code(error_code)
    if exception_fmt is not None:
        return "{}".format(exception_fmt)
    page_fault_fmt = format_page_fault(page_fault_address, page_fault_operation)
    if page_fault_fmt is not None:
        return "{}".format(page_fault_fmt)

    return "Unknown"


def detect_crashes(server, has_system, has_user, has_header=False):
    if has_header:
        print("Mode | Process | Context | BugCheck | Cause | Exception transition")
        print("-----|---------|---------|----------|-------|---------------------")

    if has_system:
        for system_crash in detect_system_crashes(server):
            print("System | {} | {} | {:#x} | {} | {}".format(system_crash.process,
                  system_crash.dispatch_ctx, system_crash.bug_check_code,
                  format_cause(system_crash.error_code, system_crash.page_fault_address,
                               system_crash.page_fault_operation), system_crash.exception_transition))

    if has_user:
        for user_crash in detect_user_crashes(server):
            print("User | {} | {} | N/A | {} | {}".format(user_crash.process,
                  user_crash.dispatch_ctx, format_exception_code(user_crash.error_code),
                  user_crash.exception_transition))


CRASH_MODE_DICT = {'all': (True, True), 'user': (False, True), 'system': (True, False)}


def parse_args():
    parser = argparse.ArgumentParser(description='Detect and report crashes and exceptions that appear during a '
                                     'REVEN2 trace.\n',
                                     formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument('--host', metavar='host', dest='host', help='Reven host, as a string (default: "localhost")',
                        default='localhost', type=str)
    parser.add_argument('--port', metavar='port', dest='port', help='Reven port, as an int (default: 13370)',
                        type=int, default=13370)
    parser.add_argument('--mode', metavar='mode', dest='mode',
                        help='Whether to look for "user" crash, "system" crash, or "all"', type=str, default='all')
    parser.add_argument("--header", action='store_true', dest='header',
                        help='If present, display a header with the meaning of each column')
    args = parser.parse_args()
    return args


if __name__ == '__main__':
    args = parse_args()

    if args.mode not in CRASH_MODE_DICT:
        raise ValueError('Wrong "mode" value "{}". Mode must be "all",'
                         ' "user" or "system" (defaults to "all").'.format(args.mode))

    (has_system, has_user) = CRASH_MODE_DICT[args.mode]

    # Get a server instance
    reven_server = reven2.RevenServer(args.host, args.port)

    detect_crashes(reven_server, has_system, has_user, args.header)
