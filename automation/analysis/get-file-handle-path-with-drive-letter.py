"""
Script capable of retrieving the full path with the drive letter of a file object pointed by a handle inside a REVEN trace.
It is using an algorithm similar to the one found here: https://docs.microsoft.com/en-us/windows/win32/memory/obtaining-a-file-name-from-a-file-handle
"""

import argparse
from typing import Iterator, Optional, Tuple

import reven2
from reven2.preview.windows import Context as WindowsContext, FileObject, Object
from reven2.preview.windows.utils import read_unicode_string


def script_main(host, port, transition, handle) -> None:
    # Connect to the REVEN server
    server = reven2.RevenServer(host, port)

    # Retrieve the context from the argument
    # Use the new API to get an enhanced context containing Windows 10 specific information
    ctx = WindowsContext(server.trace.context_before(transition))

    # Retrieve the handle from the argument at the given context
    file_object_handle = ctx.handle(handle)
    if file_object_handle is None:
        print(f"Couldn't find the handle 0x{handle:x}")
        return

    # Retrieve the object associated with the handle and check if it is an object of type 'File'
    file_object = file_object_handle.object()
    if not isinstance(file_object, FileObject):
        print(f"Object is of type '{file_object.type_name}' instead of 'File'")
        return

    print(
        f"File object found with path: {file_object.filename_with_device}, trying to find the path with the drive letter..."
    )

    # Try to retrieve the path with the drive letter instead of the device name
    path_with_drive_letter = get_path_with_drive_letter(ctx, file_object)
    if path_with_drive_letter is None:
        print("Couldn't find the path with the drive letter")
    else:
        print(f"Path with the drive letter: {path_with_drive_letter}")


def get_path_with_drive_letter(
    ctx: WindowsContext, file_object: FileObject
) -> Optional[str]:
    path = file_object.filename_with_device

    # Sort of implement the algorithm from the C++ code
    #  - Retrieve the drive letters
    #  - For each drive find the device associated with it
    #  - If the device match the one in the path, we should use this drive letter in the path
    for drive_letter in get_drive_letters(ctx):
        device = get_device_from_drive_letter(ctx, drive_letter)
        if device is None:
            continue

        if path.startswith(device):
            return f"{drive_letter}:{path[len(device):]}"

    return None


def get_drive_letters(ctx: WindowsContext) -> Iterator[str]:
    # Retrieve the kernel mapping and the types that will be used in this function
    ntoskrnl_mapping = ctx.kernel_mapping()
    EServerSiloGlobalsType = ntoskrnl_mapping.binary.exact_type("_ESERVERSILO_GLOBALS")

    # Retrieve the symbol `PspHostSiloGlobals`
    try:
        PspHostSiloGlobals = next(
            ntoskrnl_mapping.binary.data_symbols("^PspHostSiloGlobals$")
        )
    except StopIteration:
        print("Symbol 'PspHostSiloGlobals' not found in the kernel")
        return

    # Dereference `PspHostSiloGlobals` as a `_ESERVERSILO_GLOBALS`
    psp_host_silo_globals: reven2.types.StructInstance = ctx.read(
        ntoskrnl_mapping.base_address + PspHostSiloGlobals.rva,
        EServerSiloGlobalsType,
    )

    # Retrieve the drive map from `PspHostSiloGlobals.ObSiloState.SystemDeviceMap->DriveMap`
    drive_map = (
        psp_host_silo_globals.field("ObSiloState")
        .read_struct()
        .field("SystemDeviceMap")
        .deref_struct()
        .field("DriveMap")
        .read_int()
    )

    # Yield the drive letters accordingly to the bits inside the drive map
    # Each bit corresponding to a drive letter (bit 0 set = drive A present, etc)
    for i in range(26):
        if drive_map & (1 << i):
            yield chr(ord("A") + i)


def list_directory_object_entries(
    ctx: WindowsContext, directory: reven2.types.StructInstance
) -> Iterator[Tuple[reven2.address._AbstractAddress, Object]]:
    assert directory.type.name == "_OBJECT_DIRECTORY"

    # Read the hash map of entries inside the directory
    for bucket in directory.field("HashBuckets").read_array().assert_ptr():
        if bucket.address == 0:
            continue

        # Take the first _OBJECT_DIRECTORY_ENTRY and go trough the entire linked list of entries
        # Using an `Optional` here as this variable will be used to store `None` when we are at the end of the linked list
        object_directory_entry: Optional[
            reven2.types.StructInstance
        ] = bucket.assert_struct().deref()
        while object_directory_entry is not None:
            # For each entry, retrieve the object by computing its header address and giving it to the API
            obj_address = object_directory_entry.field("Object").read_ptr().address
            obj = Object.from_header(
                ctx, Object.header_address_from_object(ctx, obj_address)
            )

            yield (obj_address, obj)

            # Follow the linked list by fetching the next entry inside the field `ChainLink`
            next_object_directory_entry_ptr = object_directory_entry.field(
                "ChainLink"
            ).read_ptr()
            if next_object_directory_entry_ptr.address == 0:
                object_directory_entry = None
            else:
                object_directory_entry = (
                    next_object_directory_entry_ptr.assert_struct().deref()
                )


def get_device_from_drive_letter(
    ctx: WindowsContext, drive_letter: str
) -> Optional[str]:
    # Retrieve the kernel mapping and the types that will be used in this function
    ntoskrnl_mapping = ctx.kernel_mapping()
    ObjectSymbolicLinkType = ntoskrnl_mapping.binary.exact_type("_OBJECT_SYMBOLIC_LINK")
    DeviceMapType = ntoskrnl_mapping.binary.exact_type("_DEVICE_MAP")

    # Retrieve the global dos devices directory from `_EPROCESS.DeviceMap->GlobalDosDevicesDirectory`
    dos_devices_directory = (
        ctx.get_eprocess()
        .field("DeviceMap")
        .read_ptr()
        .cast_inner(DeviceMapType)
        .assert_struct()
        .deref()
        .field("GlobalDosDevicesDirectory")
        .deref_struct()
    )

    for obj_address, obj in list_directory_object_entries(ctx, dos_devices_directory):
        # We know that drives will be symbolic links inside the dos devices directory
        if obj.type_name != "SymbolicLink":
            continue

        # Retrieve the name of the object from the optional header (`_OBJECT_NAME_INFORMATION`) of the object
        obj_name_info_header = obj.raw_name_info_header
        if obj_name_info_header is None:
            continue

        obj_name = read_unicode_string(obj_name_info_header.field("Name").read_struct())

        # If the name is matching our drive letter we found the symbolic link of the drive pointing to the target device
        # We just need to retrieve the target of the symbolic link and it's our device
        if obj_name != f"{drive_letter}:":
            continue

        # Read manually the body of the object as a `_OBJECT_SYMBOLIC_LINK`
        body: reven2.types.StructInstance = ctx.read(
            obj_address, ObjectSymbolicLinkType
        )
        return read_unicode_string(body.field("LinkTarget").read_struct())

    return None

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

# Parameters for use within Jupyter

# Main

if __name__ == "__main__":
    if in_notebook():
        host="localhost"
        port=35877
        transition=2501360
        handle=0xa8
    else:
        # Parse the arguments given to our script
        parser = argparse.ArgumentParser()
        parser.add_argument(
            "--host",
            type=str,
            default="localhost",
            help='Reven host, as a string (default: "localhost")',
        )
        parser.add_argument(
            "-p",
            "--port",
            type=int,
            default=13770,
            help="Reven port, as an int (default: 13370)",
        )
        parser.add_argument(
            "--transition",
            type=int,
            required=True,
            help="The transition id, as an int, used to retrieve the file handle",
        )
        parser.add_argument(
            "--handle",
            type=int,
            required=True,
            help="The file handle, as an int"
        )
        args = parser.parse_args()
        host=args.host
        port=args.port
        transition=args.transition
        handle=args.handle

    script_main(host, port, transition, handle)
