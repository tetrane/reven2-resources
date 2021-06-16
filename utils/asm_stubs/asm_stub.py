"""
Purpose
=======

Execute REVEN ASM stubs as python functions.

These functions are for use in Python scripts in recorded hosts to enable automatic recording via ASM stub.

See [the documentation](http://doc.tetrane.com/professional/2.8.2/Cookbooks/Auto-record-QEMU.html#asm-stubs) for
more information about

Perimeter
=========

This script was tested on a Linux Fedora 27 VM, but all QEMU VMs running x86 in 32 or 64-bit mode
(including Windows VMs) should be supported.

Implementation Note
===================

Cf. [Executing assembler code with python](https://stackoverflow.com/questions/6040932/executing-assembler-code-with-python/57746493#57746493).
"""

import ctypes
import mmap


class _Function:
    def __init__(self, asm):
        self.buf = mmap.mmap(-1, mmap.PAGESIZE, prot=mmap.PROT_READ | mmap.PROT_WRITE | mmap.PROT_EXEC)

        ftype = ctypes.CFUNCTYPE(None)
        self.fpointer = ctypes.c_void_p.from_buffer(self.buf)

        self.f = ftype(ctypes.addressof(self.fpointer))

        self.buf.write(asm)

    def clear(self):
        del self.fpointer
        self.buf.close()


def _asm_stub(command, arg):
    _SAVE_CLOBBERED = (
        b"\x50"  # push eax
        b"\x53"  # push ebx
        b"\x51"  # push ecx
    )

    _RESTORE_CLOBBERED = (
        b"\x59"  # pop ecx
        b"\x5b"  # pop ebx
        b"\x58"  # pop eax
    )

    set_arg = (b"\xbb" + arg) if arg is not None else b""  # mov ebx, [arg]

    return _Function(
        _SAVE_CLOBBERED
        + b"\xb8" + command + b"\x00\x00\x00"  # mov eax, [COMMAND]
        + set_arg
        + b"\xb9\xcb\xde\xcb\xde"  # mov ecx,0xdecbdecb
        + b"\xcc"  # int3
        + _RESTORE_CLOBBERED
        + b"\xc3"  # ret
    )

# Pre-create the ASM functions to minimize overhead on record
_START_RECORD = _asm_stub(b"\x00", b"\x01\x00\x00\x00")
_STOP_RECORD = _asm_stub(b"\x01", None)
_COMMIT_RECORD = _asm_stub(b"\x02", b"\x01\x00\x00\x00")
_ABORT_RECORD = _asm_stub(b"\x03", b"\x00\x00\x00\x00")  # "abort reason" unimplemented


start_record = _START_RECORD.f

stop_record = _STOP_RECORD.f

commit_record = _COMMIT_RECORD.f

abort_record = _ABORT_RECORD.f

start_record.__doc__ = """Start recording immediately.

If already recording, then the record is restarted, and the previous record is immediately discarded.
"""
stop_record.__doc__ = """Stop recording immediately. Follow by `commit_record()` to save the record.

After stopping the record, any check can be performed to determine if it is successful. If successful, `commit_record()`
can be called to end the recording session and associate the record to the current scenario.
If not, subsequent records can be taken by calling `start_record()` and `stop_record()` again.
"""
commit_record.__doc__ = """Commit the last stopped record to this scenario and end the recording session.

See `stop_record()` for more information.
"""
abort_record.__doc__ = """End the recording session without committing a record.

Use this function if no record attempts were successful, and you know no future attempt will be.
"""
