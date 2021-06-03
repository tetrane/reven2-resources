# API imports
import reven2
import reven2.arch.x64 as regs  # shortcut when reading registers
from reven2.address import LogicalAddress, LinearAddress  # shortcut when reading addresses
import reven2.types as types   # shortcut when reading a specific type
from IPython.display import HTML, display
import re
import itertools
import html
from difflib import SequenceMatcher

all_regs = {}
for reg in reven2.arch.helpers.x64_registers():
    all_regs[reg.name] = reg

def tokenize_string(string):
    return re.split(" |dword|ptr|\\[|\\]|\\+|\\*|,", string)

def tokenize_instruction(transition):
    if transition.instruction is None:
        return []
    return tokenize_string(str(transition.instruction))

def get_context_tr(tr):    
    instr_elements = tokenize_instruction(tr)
    done_already = []
    context = []
    for elem in instr_elements:
        if elem in done_already:
            continue
        done_already.append(elem)
        if elem in all_regs:
            before = tr.context_before().read(all_regs[elem])
            after = tr.context_after().read(all_regs[elem])
            if before == after or elem in ["rip"]:
                context.append("{} = {:x}".format(elem, before))
            else:
                context.append("{} = {:x} to {:x}".format(elem, before, after))

    max_items = 4
    accesses = list(itertools.islice(tr.memory_accesses(), max_items))
    for acc in accesses:
        elem = "{}[{:#x}]:{}".format("R" if acc.operation == reven2.memhist.MemoryAccessOperation.Read else "W",
                                     acc.virtual_address.offset,
                                     acc.size)
        try:
            before = tr.context_before().read(acc.virtual_address, acc.size)
            after = tr.context_after().read(acc.virtual_address, acc.size)
            if before == after:
                context.append("{} = {:x}".format(elem, before))
            else:
                context.append("{} = {:x} to {:x}".format(elem, before, after))
        except:
            context.append(elem + " = ?")

    if len(accesses) > max_items:
        context.append("...")
    return context

def get_pretty_print_tr(tr, show_context=False, show_symbol=False, show_id=True):
    output = ""
    if show_symbol:
        output += "<span>{}</span><br/>".format(html.escape(str(tr.context_before().ossi.location())))

    if show_id:
        output += tr._repr_html_()
    if tr.instruction is None or tr.instruction.mnemonic != 'call':
        output += " <code>{}</code>".format(str(tr).split(" ", 1)[1])
    else:
        output += " <code>call {}</code>".format(tr.context_after().ossi.location())
    
    output += "<br/>"

    if show_context:
        output += ", ".join(get_context_tr(tr))
        
    return '<p style="font-family:monospace" class="tex2jax_ignore">' + output + "</p>"

def pretty_print_tr(tr, show_context=False, show_symbol=False):
    display(HTML(get_pretty_print_tr(tr, show_context=show_context, show_symbol=show_symbol)))

def pretty_print_buffer(b, addr=0, col=16, highlights = []):
    style_highlight = '<span style="background-color:yellow">'
    style_highlight_off = '</span>'
    output = '<code style="background-color:white">\n'

    prev_all_zeros = 0
    for i in range(int(len(b) / col)):

        total_sum = sum(b[i*col:(i+1)*col])
        for h in highlights:
            if h in range(i*col,col):
                total_sum = 0

        total_sum_next = sum(b[(i+1)*col:(i+2)*col])
        if total_sum == 0:
            prev_all_zeros += 1
        else:
            prev_all_zeros == 0
        if prev_all_zeros > 0 and total_sum_next == 0 and len(b) >= (i+2)*col:
            if prev_all_zeros == 1:
                output += "...\n"
            continue

        output += "{:016x}:".format(i*col + addr)

        for j in range(col):
            offset = j + i*col

            if offset >= len(b):
                break
            if j % 8 == 0:
                output += " "

            total_sum += b[offset]
            if offset in highlights:
                output += style_highlight
            output += "{:02x}".format(b[offset])
            if offset in highlights:
                output += style_highlight_off
            output += " "

        output += "- "
        for j in range(col):
            offset = j + i*col
            if offset >= len(b):
                break
            c = b[offset]

            if offset in highlights:
                output += style_highlight

            if c >= 32 and c <= 126:
                output += "{}".format(chr(c))
            else:
                output += "."

            if offset in highlights:
                output += style_highlight_off
        output += "\n"
    output += "</code>"
    display(HTML(output))

def pretty_print_addr(ctx, address, size):
    if isinstance(address, reven2.arch.register.Register):
        address = ctx.read(address)
    if isinstance(address, int):
        address = LinearAddress(address)
    pretty_print_buffer(ctx.read(address, size), address.offset)
