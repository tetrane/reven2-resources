# ---
# jupyter:
#   jupytext:
#     formats: ipynb,py:percent
#     text_representation:
#       extension: .py
#       format_name: percent
#       format_version: '1.3'
#       jupytext_version: 1.11.2
#   kernelspec:
#     display_name: reven
#     language: python
#     name: reven-python3
# ---

# %% [markdown]
# # Bookmarks to WinDbg breakpoints
#
# ## Purpose
#
# This notebook and script are designed to convert the bookmarks of a scenario to WinDbg breakpoints.
#
# The meat of the script uses the ability of the API to iterate on the bookmarks of a REVEN scenario, as well as the
# OSSI location, to generate a list of breakpoint commands for WinDbg where the addresses are independent of the REVEN
# scenario itself:
#
# ```py
# for bookmark in self._server.bookmarks.all():
#     location = bookmark.transition.context_before().ossi.location()
#     print(f"bp {location.binary.name}+{location.rva:#x}\r\n")
# ```
#
# The output of the script is a list of WinDbg breakpoint commands corresponding to the relative virtual address
# of the location of each of the bookmarks.
#
# This list of command can either be copy-pasted in WinDbg or output to a file, which can then be executed in WinDbg
# using the following syntax:
#
# ```kd
# $<breakpoints.txt
# ```
#
# ## How to use
#
# Bookmark can be converted from this notebook or from the command line.
# The script can also be imported as a module for use from your own script or notebook.
#
#
# ### From the notebook
#
# 1. Upload the `bk2bp.ipynb` file in Jupyter.
# 2. Fill out the [parameters](#Parameters) cell of this notebook according to your scenario and desired output.
# 3. Run the full notebook.
#
#
# ### From the command line
#
# 1. Make sure that you are in an
#    [environment](http://doc.tetrane.com/professional/latest/Python-API/Installation.html#on-the-reven-server)
#    that can run REVEN scripts.
# 2. Run `python bk2bp.py --help` to get a tour of available arguments.
# 3. Run `python bk2bp.py --host <your_host> --port <your_port> [<other_option>]` with your arguments of
#    choice.
#
# ### Imported in your own script or notebook
#
# 1. Make sure that you are in an
#    [environment](http://doc.tetrane.com/professional/latest/Python-API/Installation.html#on-the-reven-server)
#    that can run REVEN scripts.
# 2. Make sure that `bk2bp.py` is in the same directory as your script or notebook.
# 3. Add `import bk2bp` to your script or notebook. You can access the various functions and classes
#    exposed by the module from the `bk2bp` namespace.
# 4. Refer to the [Argument parsing](#Argument-parsing) cell for an example of use in a script, and to the
#    [Parameters](#Parameters) cell and below for an example of use in a notebook (you just need to preprend
#    `bk2bp` in front of the functions and classes from the script).
#
# ## Known limitations
#
# - For the breakpoints to be resolved by WinDbg, the debugged program/machine/REVEN scenario needs to be in a state
# where the corresponding modules have been loaded. Otherwise, WinDbg will add the breakpoints in an unresolved state,
#   and may mixup module and symbols.
#
# - When importing breakpoints generated from the bookmarks of a scenario using this script in WinDbg,
#   make sure that the debugged system is "similar enough" to the VM that was used to record the scenario.
#   In particular, if a binary changed and has symbols at different offsets in the debugged system, importing
#   the breakpoints will not lead to the correct location in the binary, and may render the debugged system unstable.
#
# ## Supported versions
#
# REVEN 2.8+
#
# ## Supported perimeter
#
# Any Windows REVEN scenario.
#
# ## Dependencies
#
# None.

# %% [markdown]
# ### Package imports

# %%
import argparse
from typing import Optional

import reven2  # type: ignore


# %% [markdown]
# ### Utility functions

# %%
# Detect if we are currently running a Jupyter notebook.
#
# This is used e.g. to display rendered results inline in Jupyter when we are executing in the context of a Jupyter
# notebook, or to display raw results on the standard output when we are executing in the context of a script.
def in_notebook():
    try:
        from IPython import get_ipython  # type: ignore
        if get_ipython() is None or ("IPKernelApp" not in get_ipython().config):
            return False
    except ImportError:
        return False
    return True


# %% [markdown]
# ### Main function

# %%
def bk2bp(server: reven2.RevenServer, output: Optional[str]):
    text = ""
    for bookmark in server.bookmarks.all():
        ossi = bookmark.transition.context_before().ossi
        if ossi is None:
            continue
        location = ossi.location()
        if location is None:
            continue
        if location.binary is None:
            continue
        if location.rva is None:
            continue
        name = location.binary.name
        # WinDbg requires the precise name of the kernel, which is difficult to get.
        # WinDbg seems to always accept "nt" as name for the kernel, so replace that.
        if name == "ntoskrnl":
            name = "nt"
        text += f"bp {name}+{location.rva:#x}\r\n"  # for windows it is safest to have the \r
    if output is None:
        print(text)
    else:
        try:
            with open(output, "w") as f:
                f.write(text)
        except OSError as ose:
            raise ValueError(f"Could not open file {output}: {ose}")


# %% [markdown]
# ### Argument parsing
#
# Argument parsing function for use in the script context.

# %%
def script_main():
    parser = argparse.ArgumentParser(
        description="Convert the bookmarks of a scenario to a WinDbg breakpoints commands."
    )
    parser.add_argument(
        "--host",
        type=str,
        default="localhost",
        required=False,
        help='REVEN host, as a string (default: "localhost")',
    )
    parser.add_argument(
        "-p",
        "--port",
        type=int,
        default="13370",
        required=False,
        help="REVEN port, as an int (default: 13370)",
    )
    parser.add_argument(
        "-o",
        "--output-file",
        type=str,
        required=False,
        help="The target file of the script. If absent, the results will be printed on the standard output.",
    )

    args = parser.parse_args()

    try:
        server = reven2.RevenServer(args.host, args.port)
    except RuntimeError:
        raise RuntimeError(f"Could not connect to the server on {args.host}:{args.port}.")

    bk2bp(server, args.output_file)


# %% [markdown]
# ### Parameters
#
# These parameters have to be filled out to use in the notebook context.

# %%
# Server connection
#
host = "localhost"
port = 13370


# Output target
#
# If set to a path, writes the breakpoint commands file there
output_file = None  # display bp commands inline in the Jupyter Notebook
# output_file = "breakpoints.txt"  # write bp commands to a file named "breakpoints.txt" in the current directory

# %% [markdown]
# ### Execution cell
#
# This cell executes according to the [parameters](#Parameters) when in notebook context, or according to the
# [parsed arguments](#Argument-parsing) when in script context.
#
# When in notebook context, if the `output` parameter is `None`, then the output will be displayed in the last cell of
# the notebook.

# %%
if __name__ == "__main__":
    if in_notebook():
        try:
            server = reven2.RevenServer(host, port)
        except RuntimeError:
            raise RuntimeError(f"Could not connect to the server on {host}:{port}.")
        bk2bp(server, output_file)
    else:
        script_main()

# %%
