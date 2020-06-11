from IPython.core.display import display, HTML  # display HTML results
import reven2

# helper functions to output html tables
def table_line(cells):
    line = ""
    for cell in cells:
        line += "<td>{}</td>".format(cell)
    return "<tr>{}</tr>".format(line)


def display_table(title, headers, html_lines):
    header_line = ""
    for header in headers:
        header_line += "<th>{}</th>".format(header)
    header_line = "<tr>{}</tr>".format(header_line)
    display(HTML("""<h2>{}</h2><table>{} {}</table>""".format(title, header_line, html_lines)))



def try_decode_printable(buf, size):
    try:
        utf8 = buf.decode("utf8")
        if size != len(utf8):
            raise ValueError()
        if not utf8.isprintable():
            raise ValueError()
        return "utf8: " + utf8
    except UnicodeDecodeError:
        pass
    except ValueError:
        pass
    try:
        utf16 = buf.decode("utf16")
        if size / 2 != len(utf16):
            raise ValueError()
        if not utf16.isprintable():
            raise ValueError()
        return "utf16: " + utf16
    except ValueError:
        pass
    return "raw: " + str(buf)


def read_tainted_memory(change):
    state = change.state_before()
    ctx = state.context
    reads = []
    for mem, _ in state.tainted_memories():
        buffer = ctx.read(mem.address, mem.size, raw=True)
        reads.append(try_decode_printable(bytes(buffer), mem.size))
    return reads


def get_ret_ctx(trace, call_ctx):
    call_transition = call_ctx.transition_before() - 1 # `call 0x5c1dec`
    write_memory_access = next(call_transition.memory_accesses())
    read_memory_access = next(trace.memory_accesses(
        address=write_memory_access.physical_address, size=8,
        from_transition=call_transition,
        operation=reven2.memhist.MemoryAccessOperation.Read))
    return read_memory_access.transition.context_before()
