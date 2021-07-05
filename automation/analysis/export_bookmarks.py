# -*- coding: utf-8 -*-
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
# # Export bookmarks
#
# ## Purpose
#
# This notebook and script are designed to export the bookmarks of a scenario, for example for inclusion in a report.
#
# The meat of the script uses the ability of the API to iterate on the bookmarks of a REVEN scenario:
#
# ```py
# for bookmark in self._server.bookmarks.all():
#     # do something with the bookmark.id, bookmark.transition and bookmark.description
# ```
#
# See the [Document](#Document) class and in particular its `add_bookmarks` function for details.
#
# ## How to use
#
# Bookmark can be exported from this notebook or from the command line.
# The script can also be imported as a package for use from your own script or notebook.
#
# ### From the notebook
#
# 1. Upload the `export_bookmarks.ipynb` file in Jupyter.
# 2. Fill out the [parameters](#Parameters) cell of this notebook according to your scenario and desired output.
# 3. Run the full notebook.
#
#
# ### From the command line
#
# 1. Make sure that you are in an
#    [environment](http://doc.tetrane.com/professional/latest/Python-API/Installation.html#on-the-reven-server)
#    that can run REVEN scripts.
# 2. Run `python export_bookmarks.py --help` to get a tour of available arguments.
# 3. Run `python export_bookmarks.py --host <your_host> --port <your_port> [<other_option>]` with your arguments of
#    choice.
#
# ### Imported in your own script or notebook
#
# 1. Make sure that you are in an
#    [environment](http://doc.tetrane.com/professional/latest/Python-API/Installation.html#on-the-reven-server)
#    that can run REVEN scripts.
# 2. Make sure that `export_bookmarks.py` is in the same directory as your script or notebook.
# 3. Add `import export_bookmarks` to your script or notebook. You can access the various functions and classes
#    exposed by `export_bookmarks.py` from the `export_bookmarks` namespace.
# 4. Refer to the [Argument parsing](#Argument-parsing) cell for an example of use in a script, and to the
#    [Parameters](#Parameters) cell and below for an example of use in a notebook (you just need to preprend
#    `export_bookmarks` in front of the functions and classes from the script).
#
# ## Customizing the notebook/script
#
# To add a new format or change the output, you may want to:
#
# - Modify the various [enumeration types](#Output-option-types) that control the output to add your new format or
#   option.
# - Modify the [Formatter](#Formatter) class to account for your new format.
# - Modify the [Document](#Document) class to account for your new output control option.
#
#
# ## Known limitations
#
# N/A.
#
# ## Supported versions
#
# REVEN 2.8+
#
# ## Supported perimeter
#
# Any REVEN scenario.
#
# ## Dependencies
#
# None.

# %% [markdown]
# ### Package imports

# %%
import argparse  # for argument parsing
import datetime  # Date generation
from enum import Enum
from html import escape as html_escape
from typing import Iterable, Optional

import reven2  # type: ignore
try:
    # Jupyter rendering
    from IPython.display import display, HTML, Markdown  # type: ignore
except ImportError:
    pass


# %% [markdown]
# ### Utility functions

# %%
# Detect if we are currently running a Jupyter notebook.
#
# This is used to display rendered results inline in Jupyter when we are executing in the context of a Jupyter
# notebook, or to display raw results on the standard output when we are executing in the context of a script.
def in_notebook():
    try:
        from IPython import get_ipython  # type: ignore
        if get_ipython() is None or ('IPKernelApp' not in get_ipython().config):
            return False
    except ImportError:
        return False
    return True


# %% [markdown]
# ### Output option types
#
# The enum types below are used to control the output of the script.
#
# Modify these enums to add more options if you want to add e.g. new output formats.

# %%
class HeaderOption(Enum):
    NoHeader = 0
    Simple = 1


class OutputFormat(Enum):
    Raw = 0
    Markdown = 1
    Html = 2


class SortOrder(Enum):
    Transition = 0
    Creation = 1


# %% [markdown]
# ### Formatter
#
# This is the rendering boilerplate.
#
# Modify this if you e.g. need to add new output formats.

# %%
class Formatter:
    def __init__(
        self,
        format: OutputFormat,
    ):
        self._format = format

    def header(self, title: str) -> str:
        if self._format == OutputFormat.Html:
            return f"<h1>{title}</h1>"
        elif self._format == OutputFormat.Markdown:
            return f"# {title}\n\n"
        elif self._format == OutputFormat.Raw:
            return f"{title}\n\n"
        raise NotImplementedError(f"'header' with {self._format}")

    def paragraph(self, paragraph: str) -> str:
        if self._format == OutputFormat.Html:
            return f"<p>{paragraph}</p>"
        elif self._format == OutputFormat.Markdown:
            return f"\n\n{paragraph}\n\n"
        elif self._format == OutputFormat.Raw:
            return f"\n{paragraph}\n"
        raise NotImplementedError(f"'paragraph' with {self._format}")

    def horizontal_ruler(self) -> str:
        if self._format == OutputFormat.Html:
            return "<hr/>"
        elif self._format == OutputFormat.Markdown:
            return "\n---\n"
        elif self._format == OutputFormat.Raw:
            return "\n---\n"
        raise NotImplementedError(f"'horizontal_ruler' with {self._format}")

    def transition(self, transition: reven2.trace.Transition) -> str:
        if transition.instruction is not None:
            tr_desc = str(transition.instruction)
        else:
            tr_desc = str(transition.exception)
        if self._format == OutputFormat.Html:
            if in_notebook():
                tr_id = f"{transition.format_as_html()}"
            else:
                tr_id = f"#{transition.id} "
            return f"{tr_id} <code>{tr_desc}</code>"
        elif self._format == OutputFormat.Markdown:
            return f"`#{transition.id}` `{tr_desc}`"
        elif self._format == OutputFormat.Raw:
            return f"#{transition.id}\t{tr_desc}"
        raise NotImplementedError(f"'transition' with {self._format}")

    def newline(self) -> str:
        if self._format == OutputFormat.Html:
            return "<br/>"
        elif self._format == OutputFormat.Markdown:
            return "  \n"  # EOL spaces to have a newline in markdown
        elif self._format == OutputFormat.Raw:
            return "\n"
        raise NotImplementedError(f"'newline' with {self._format}")

    def paragraph_begin(self) -> str:
        if self._format == OutputFormat.Html:
            return "<p>"
        elif self._format == OutputFormat.Markdown:
            return "\n\n"
        elif self._format == OutputFormat.Raw:
            return "\n"
        raise NotImplementedError(f"'paragraph_begin' with {self._format}")

    def paragraph_end(self) -> str:
        if self._format == OutputFormat.Html:
            return "</p>"
        elif self._format == OutputFormat.Markdown:
            return "\n\n"
        elif self._format == OutputFormat.Raw:
            return "\n"
        raise NotImplementedError(f"'paragraph_end' with {self._format}")

    def important(self, important: str) -> str:
        if self._format == OutputFormat.Html:
            return f"<strong>{important}</strong>"
        elif self._format == OutputFormat.Markdown:
            return f"**{important}**"
        elif self._format == OutputFormat.Raw:
            return f"{important} <- HERE"
        raise NotImplementedError(f"'important' with {self._format}")

    def code(self, code: str) -> str:
        if self._format == OutputFormat.Html:
            return f"<code>{code}</code>"
        elif self._format == OutputFormat.Markdown:
            return f"`{code}`"
        elif self._format == OutputFormat.Raw:
            return f"{code}"
        raise NotImplementedError(f"'code' with {self._format}")

    def render(self, text, output):
        if output is None:
            if in_notebook():
                if self._format == OutputFormat.Html:
                    display(HTML(text))
                elif self._format == OutputFormat.Markdown:
                    display(Markdown(text))
                elif self._format == OutputFormat.Raw:
                    display(text)
                else:
                    raise NotImplementedError(f"inline rendering with {self._format}")
            else:
                print(text)
        else:
            try:
                with open(output, "w") as f:
                    f.write(text)
            except OSError as ose:
                raise ValueError(f"Could not open file {output}: {ose}")


# %% [markdown]
# ### Document
#
# This is the main logic of the script.

# %%
class Document:
    def __init__(
        self,
        server: reven2.RevenServer,
        sort: SortOrder,
        context: Optional[int],
        header: HeaderOption,
        format: OutputFormat,
        output: Optional[str],
        escape_description: bool,
    ):
        self._text = ""
        self._server = server
        if context is None:
            self._context = 0
        else:
            self._context = context
        self._header_opt = header
        self._escape_description = escape_description
        self._output = output
        self._sort = sort
        self._formatter = Formatter(format)

    def add_bookmarks(self):
        if self._sort == SortOrder.Creation:
            for bookmark in sorted(self._server.bookmarks.all(), key=lambda bookmark: bookmark.id):
                self.add_bookmark(bookmark)
        else:
            for bookmark in sorted(self._server.bookmarks.all(), key=lambda bookmark: bookmark.transition):
                self.add_bookmark(bookmark)

    def add_bookmark(self, bookmark: reven2.bookmark.Bookmark):
        self._text += self._formatter.paragraph_begin()
        self.add_bookmark_header(bookmark)
        self.add_location(bookmark.transition)
        if bookmark.transition.id < self._context:
            first_transition = self._server.trace.first_transition
        else:
            first_transition = bookmark.transition - self._context
        self.add_transitions(
            transition
            for transition in self._server.trace.transitions(
                first_transition, bookmark.transition
            )
        )
        self.add_bookmark_transition(bookmark.transition)
        # Catch possible transitions that would out of the trace due to the value of context
        if bookmark.transition != self._server.trace.last_transition:
            if bookmark.transition.id + self._context > self._server.trace.last_transition.id:
                last_transition = self._server.trace.last_transition
            else:
                last_transition = bookmark.transition + 1 + self._context
            self.add_transitions(
                transition
                for transition in self._server.trace.transitions(
                    bookmark.transition + 1, last_transition
                )
            )
        self._text += self._formatter.paragraph_end()
        self._text += self._formatter.horizontal_ruler()

    def add_header(self):
        if self._header_opt == HeaderOption.NoHeader:
            return
        elif self._header_opt == HeaderOption.Simple:
            scenario_name = self._server.scenario_name
            self._text += self._formatter.header(f"Bookmarks for scenario {scenario_name}")
            date = datetime.datetime.now()
            self._text += self._formatter.paragraph(f"Generated on {str(date)}")
            self._text += self._formatter.horizontal_ruler()

    def add_transitions(self, transitions: Iterable[reven2.trace.Transition]):
        for transition in transitions:
            self._text += self._formatter.transition(transition)
            self._text += self._formatter.newline()

    def add_bookmark_transition(self, transition: reven2.trace.Transition):
        tr_format = self._formatter.transition(transition)
        alone = self._context == 0
        self._text += self._formatter.important(tr_format) if not alone else tr_format
        self._text += self._formatter.newline()

    def add_bookmark_header(self, bookmark: reven2.bookmark.Bookmark):
        if self._escape_description:
            bookmark_description = html_escape(bookmark.description)
        else:
            bookmark_description = bookmark.description
        self._text += f"{bookmark_description}"
        self._text += self._formatter.newline()

    def add_location(self, transition: reven2.trace.Transition):
        ossi = transition.context_before().ossi
        if ossi and ossi.location():
            location = self._formatter.code(html_escape(str(ossi.location())))
            self._text += self._formatter.paragraph(f"Location: {location}")

    def render(self):
        self._formatter.render(self._text, self._output)


# %% [markdown]
# ### Main function
#
# This function is called with parameters from the [Parameters](#Parameters) cell in the notebook context,
# or with parameters from the command line in the script context.

# %%
def export_bookmarks(
    server: reven2.RevenServer,
    sort: SortOrder,
    context: Optional[int],
    header: HeaderOption,
    format: OutputFormat,
    escape_description: bool,
    output: Optional[str],
):
    document = Document(
        server,
        sort=sort,
        context=context,
        header=header,
        format=format,
        output=output,
        escape_description=escape_description,
    )
    document.add_header()
    document.add_bookmarks()
    document.render()


# %% [markdown]
# ### Argument parsing
#
# Argument parsing function for use in the script context.

# %%
def get_sort(sort: str) -> SortOrder:
    if sort.lower() == "transition":
        return SortOrder.Transition
    if sort.lower() in ["creation", "id"]:
        return SortOrder.Creation
    raise ValueError(
        f"'order' value should be 'transition' or 'creation'. Received '{sort}'."
    )


def get_header(header: str) -> HeaderOption:
    if header.lower() == "no":
        return HeaderOption.NoHeader
    elif header.lower() == "simple":
        return HeaderOption.Simple
    raise ValueError(f"'header' value should be 'no' or 'simple'. Received '{header}'.")


def get_format(format: str) -> OutputFormat:
    if format.lower() == "html":
        return OutputFormat.Html
    elif format.lower() == "md" or format.lower() == "markdown":
        return OutputFormat.Markdown
    elif format.lower() == "raw" or format.lower() == "text":
        return OutputFormat.Raw
    raise ValueError(
        "'format' value should be one of 'html', 'md' or 'raw'. Received '{format}'."
    )


def script_main():
    parser = argparse.ArgumentParser(description="Export the bookmarks of a scenario to a report.")
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
        "-C",
        "--context",
        type=int,
        required=False,
        help="Print CONTEXT lines of surrounding context around the bookmark's instruction",
    )
    parser.add_argument(
        "--header",
        type=str,
        default="no",
        required=False,
        choices=["no", "simple"],
        help="Whether to preprend the output with a header or not (default: no)",
    )
    parser.add_argument(
        "--format",
        type=str,
        default="html",
        required=False,
        choices=["html", "md", "raw"],
        help="The output format (default: html).",
    )
    parser.add_argument(
        "--order",
        type=str,
        default="transition",
        choices=["transition", "creation"],
        required=False,
        help="The sort order of bookmarks in the report (default: transition).",
    )
    parser.add_argument(
        "--no-escape-description",
        action="store_true",
        default=False,
        required=False,
        help="If present, don't escape the HTML in the bookmark descriptions.",
    )
    parser.add_argument(
        "-o",
        "--output-file",
        type=str,
        required=False,
        help="The target file of the report. If absent, the report will be printed on the standard output.",
    )

    args = parser.parse_args()

    try:
        server = reven2.RevenServer(args.host, args.port)
    except RuntimeError:
        raise RuntimeError(f"Could not connect to the server on {args.host}:{args.port}.")

    sort = get_sort(args.order)
    header = get_header(args.header)
    format = get_format(args.format)

    export_bookmarks(
        server,
        sort,
        args.context,
        header,
        format,
        escape_description=(not args.no_escape_description),
        output=args.output_file,
    )


# %% [markdown]
# ## Parameters
#
# These parameters have to be filled out to use in the notebook context.

# %%
# Server connection
#
host = "localhost"
port = 36155


# Output target
#
# If set to a path, writes the report file there
output_file = None  # display report inline in the Jupyter Notebook
# output_file = "report.html"  # export report to a file named "report.html" in the current directory


# Output control
#
# Sort order of bookmarks
order = SortOrder.Transition  # Bookmarks will be displayed in increasing transition number.
# order = SortOrder.Creation  # Bookmarks will be displayed in their order of creation.

# Number of transitions to display around the transition of each bookmark
context = 0  # Only display the bookmark transition
# context = 3  # Displays 3 lines above and 3 lines below the bookmark transition

# Whether to prepend a header at the top of the report
header = HeaderOption.Simple  # Display a simple header with the scenario name and generation date
# header = HeaderOption.NoHeader  # Don't display any header

# The format of the report.
# When the output target is set to a file, this specifies the format of that file.
# When the output target is `None` (report rendered inline), the difference between HTML and Markdown
# mostly influences how the description of the bookmarks is interpreted.
format = OutputFormat.Html  # Bookmark description and output file rendered as HTML
# format = export_bookmarks.OutputFormat.Markdown  # Bookmark description and output file rendered as Markdown
# format = export_bookmarks.OutputFormat.Raw  # Everything rendered as raw text

# Whether to escape HTML in the description of bookmarks.
escape_description = False  # HTML will not be escaped in description
# escape_description = True   # HTML will be escaped in description


# %% [markdown]
# ### Execution cell
#
# This cell executes according to the [parameters](#Parameters) when in notebook context, or according to the
# [parsed arguments](#Argument-parsing) when in script context.
#
# When in notebook context, if the `output` parameter is `None`, then the report will be displayed in the last cell of
# the notebook.

# %%
if __name__ == "__main__":
    if in_notebook():
        try:
            server = reven2.RevenServer(host, port)
        except RuntimeError:
            raise RuntimeError(f"Could not connect to the server on {host}:{port}.")

        export_bookmarks(server, order, context, header, format, escape_description, output_file)
    else:
        script_main()

# %%

# %%
