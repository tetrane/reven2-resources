---
jupyter:
  jupytext:
    text_representation:
      extension: .md
      format_name: markdown
      format_version: '1.3'
      jupytext_version: 1.11.2
  kernelspec:
    display_name: reven-2.8.2-python3
    language: python
    name: reven_2.8.2_python3
---

<!-- #region -->
# Diffing traces

This notebook provides a basis to perform trace comparisons at the instruction level. It has been used to generate the results that can be seen in the [Diffing trace](https://blog.tetrane.com/2021/reverse-engineering-through-trace-diffing-several-approaches.html) blog article.

## Prerequisites

- This notebook should be run in a jupyter notebook server equipped with a REVEN 2 python kernel.
  REVEN comes with a jupyter notebook server accessible with the `Open Python` button in the `Analyze` page of any
  scenario.

- This notebook depends on `pandas` being installed in the REVEN 2 python kernel.
  To install capstone in the current environment, please execute the [pandas cell](#Pandas-Installation) of this
  notebook.

- This notebook requires multiple resources for your target scenario:
  - Memory history
  - Fast Search
  - OSSI

## Running the notebook

Execute the cell [Tools cell](#Tools), edit the [Servers cell](#Servers) and run it, then pick one of the [Run cell](#Run-Diff), edit its parameters and run it.

## Note

This notebook is provided as a starting point for our users to modify and adapt to their needs.

Also, this makes use of helper functions in the associated `utils.py` file located alongside this notebook.
<!-- #endregion -->

# Pandas Installation

Check for `pandas`'s presence. If missing, attempt to get it from pip

```python
try:
    import pandas
    print("pandas already installed")
except ImportError:
    print("Could not find pandas, attempting to install it from pip")
    import sys

    output = !{sys.executable} -m pip install pandas; echo $?  # noqa
    success = output[-1]

    for line in output[0:-1]:
        print(line)

    if int(success) != 0:
        raise RuntimeError("Error installing pandas")
    import pandas
    print("Successfully installed pandas")
```

# Tools

Declare all basic tool functions for comparing instruction and formating the results

```python
import reven2  # noqa: E402
import reven2.arch.x64 as regs  # noqa: E402
import reven2.preview.taint  # noqa: E402

import pandas as pd  # noqa: E402
from difflib import SequenceMatcher  # noqa: E402

from IPython.display import HTML, display  # noqa: E402
import utils  # noqa: E402

def diff_transitions(left, right, display_line, max_items_per_block=20):
    """
    Perform the diff operation and format into pandas-compatible frames
    """
    hashable_l = [str(a.instruction.raw) for a in left]
    hashable_r = [str(a.instruction.raw) for a in right]
    table = ""
    
    frame = {
        "tr_left": [],
        "ins_left": [],
        "sign": [],   
        "ins_right": [],
        "tr_right": [],
    }
    
    def fill_block(coll, start, end, is_left):
        items = []
        fill_from_bottom_starting = None
        for item in coll[start:end]:
            displayed = display_line(item, is_left)
            if displayed is None:
                continue
                
            if max_items_per_block is not None and len(items) > max_items_per_block:              
                del items[int(max_items_per_block / 2):]
                items.append("[...]")
                fill_from_bottom_starting = len(items)
                break
            items.append(displayed)
            
        if fill_from_bottom_starting is not None:
            for i in range(end-1, start-1, -1):
                displayed = display_line(coll[i], is_left)
                if displayed is None:
                    continue
                items.insert(fill_from_bottom_starting, displayed)
                if len(items) >= max_items_per_block:
                    break
        return items
                    
    for tag, i, j, k, l in SequenceMatcher(None, hashable_l, hashable_r).get_opcodes():  
        items_l = "<div style='white-space: nowrap; text-align: right;'>{}</div>".format(
            "<br/>".join(fill_block(left, i, j, is_left=True)))
        items_r = "<div style='white-space: nowrap; text-align: left;'>{}</div>".format(
            "<br/>".join(fill_block(right, k, l, is_left=False)))
            
        left_tr = ""
        right_tr = ""
        if j > i:
            if j - i > 1:
                left_tr = "{}-><br/>{}".format(left[i]._repr_html_(), left[j-1]._repr_html_())
            else:
                left_tr = "{}".format(left[i]._repr_html_())
        if l > k:
            if l - k > 1:
                right_tr = "{}-><br/>{}".format(right[k]._repr_html_(), right[l-1]._repr_html_())
            else:
                right_tr = "{}".format(right[k]._repr_html_())
        
        if tag == 'equal':
            char = "="
        if tag == 'replace':
            char = "<>"
        if tag == 'delete':
            char = "<"
        if tag == 'insert':
            char = ">"
        
        frame["tr_left"].append(left_tr)
        frame["ins_left"].append("".join(items_l))
        frame["ins_right"].append("".join(items_r))
        frame["tr_right"].append(right_tr)
        frame["sign"].append("<p style='text-align:center;'>{}</p>".format(char))
    
    return pd.DataFrame(frame)

# Basic display functions

def display_instructions(tr, is_left):
    """
    Display each instruction, and resolve call destinations
    """
    if tr.instruction is None:
        return "<code>{}</code>".format(str(tr.exception))
    elif tr.instruction.mnemonic == 'call':
        ctx = tr.context_after()
        location = ctx.ossi.location()
        symbol = str(location.symbol)
        return "<code>call {}</code>".format(symbol if len(symbol) < 40 else (symbol[0:37] + "..."))
    else:
        return "<code>{}</code><br/>".format(str(tr.instruction))

def display_instructions_context(tr, is_left):
    """
    Display each instruction, and resolve call destinations
    Also display context alongside instruction
    """
    if tr.instruction is None:
        return "<code>{}</code>".format(str(tr.exception))
    elif tr.instruction.mnemonic == 'call':
        ctx = tr.context_after()
        location = ctx.ossi.location()
        symbol = str(location.symbol)
        return "<code>call {}</code>".format(symbol if len(symbol) < 40 else (symbol[0:37] + "..."))
    else:
        output = "<code>{}</code><br/>".format(str(tr.instruction))
        output += "<span style='font-family:monospace'>{}</span>".format("<br/>".join(utils.get_context_tr(tr)))
        return output

# Fetch data

def function_data_stepover(function_start_context, max_transitions):
    """
    Will return list of all function's instruction assuming step over
    """
    context = function_start_context
    data = []

    for i in range(max_transitions):
        tr = context.transition_after()
        data.append(tr)
        mnemonic = tr.instruction.mnemonic
        if mnemonic == 'ret':
            # End of function
            break 
        elif mnemonic == 'call':
            # Force manual "step over"
            ret = tr.find_inverse()
            context = ret.context_after()
        else:
            context += 1
    return data
```

# Servers

```python
# Server connection

# Host of the REVEN server running the scenario.
# When running this notebook from the Project Manager, '127.0.0.1' should be the correct value.
reven_backend_host = '127.0.0.1'

# Port of the REVEN servers running the scenarios we want to compare.
# After starting a REVEN server on your scenario, you can get its port on the Analyze page of that scenario.
# Left trace will always be displayed on the left in the following results.
reven_backend_left_port = 13370
reven_backend_right_port = 13371

server_l = reven2.RevenServer(reven_backend_host, reven_backend_left_port)
trace_l = server_l.trace
server_r = reven2.RevenServer(reven_backend_host, reven_backend_right_port)
trace_r = server_r.trace
```

# Run Diff

The following cells demonstrate various ways to compare traces:
- Comparing the instructions of a function call, ignoring subcalls
- Comparing the instructions that manipulate a certain piece of data, leveraging the taint.

In each cell, the function `my_function_data` is responsible for retrieving the list of instruction from the trace.
You should edit it to match your use case.

Also note you can customize the output to provide additional information in the report, or hide irrelevant instructions, as seen in the second example.

## Compare function's instructions

In this cell, we will fetch all instruction from the first call to a function in both traces,
then compare them.


```python
def my_function_data(server):
    # Look for start of function
    symbol = next(server.ossi.symbols("Ipv6pHandleRouterAdvertisement", binary_hint="tcpip.sys"))
    start = next(server.trace.search.symbol(symbol))
    return function_data_stepover(start, 10000)

# Fetch data
left = my_function_data(server_l)
right = my_function_data(server_r)

# Perform & display diff
df = diff_transitions(left, right, display_instructions, max_items_per_block=5)
display(HTML(df.to_html(escape=False, index=False)))
```

## Customize diff display to focus on certain calls

In this cell, we fetch the same function as above, but we provide a custom output function:
- We only print calls and ignore other instructions
- For two particularly interesting calls, we print one argument and the returned buffer, to make the output even more explicit.

```python
def my_function_data(server):
    # Look for start of function
    symbol = next(server.ossi.symbols("Ipv6pHandleRouterAdvertisement", binary_hint="tcpip.sys"))
    start = next(server.trace.search.symbol(symbol))
    return function_data_stepover(start, 10000)


def display_calls_only(tr, is_left):
    """
    Customize how individual transitions are displayed in the report. 
    This function is passed as a callback to `diff_transitions`

    Note:
     - `is_left` indicate this is applied to the left column, and can be used
       to, for example, customize text alignment
     - The output of this function is not used when performing the comparison, 
       so it will not change the results
     - returning None will cause the transition not to be displayed (again, no 
       impact on the comparison operation itself)

    Here, we will only display calls, ignoring all other instructions, and we 
    will display more info from certain interesting calls.    
    """
    if tr.instruction is None or tr.instruction.mnemonic != 'call':
        # Ignore non-calls
        return None    

    ctx = tr.context_after()
    location = ctx.ossi.location()
    symbol = str(location.symbol)
    instr = "call {}".format(symbol if len(symbol) < 40 else (symbol[0:37] + "..."))
    
    # Print custom output on interesting calls
    if location.symbol.name == 'NdisGetDataBuffer':
        ret = tr.find_inverse().context_after()
        size = ctx.read(regs.rdx)
        instr += "({:x})".format(size)
        addr = reven2.address.LogicalAddress(ret.read(regs.rax))
        instr += "<br/>=" + ' '.join('{:02x}'.format(x) for x in ret.read(addr, size, raw=True)[0:10])
    elif location.symbol.name == 'NdisAdvanceNetBufferDataStart':
        instr += "({:x})".format(ctx.read(regs.rdx))
    return "<code>{}</code><br/>".format(instr)


# Fetch data
left = my_function_data(server_l)
right = my_function_data(server_r)

# Perform & display diff
df = diff_transitions(left, right, display_calls_only, max_items_per_block=None)
display(HTML(df.to_html(escape=False, index=False)))
```

## Compare instructions involved in tainted data

In this cell, instead of comparing the entire function, we will focus on the instructions involved with certain bytes of the input. This further reduces the output, making it easy to focus on relevant code.

Since the input is much smaller than before, we can also print the context alongside the instruction by using the callback `display_instructions_context`, making the report easier to read.

```python            
def my_function_data(server, offset, size=1):
    trace = server.trace

    # Look for start of function
    symbol = next(server.ossi.symbols("Ipv6pHandleRouterAdvertisement", binary_hint="tcpip.sys"))
    start = next(trace.search.symbol(symbol))

    # rcx points to the packet content, our first option is at +0x10
    buffer = start.read(regs.rcx) + offset

    # Do a forward taint on the requested offset
    taint_input = "[{:#x};{}]".format(buffer, size)
    tainter = reven2.preview.taint.Tainter(trace)
    taint = tainter.simple_taint(taint_input, from_context=start)
    return [acc.transition for acc in taint.accesses().all()]


# Focus of offset 0x11 of the input buffer
left = my_function_data(server_l, 0x11, 1)
right = my_function_data(server_r, 0x11, 1)

df = diff_transitions(left, right, display_instructions_context, max_items_per_block=20)
display(HTML(df.to_html(escape=False, index=False)))
```
