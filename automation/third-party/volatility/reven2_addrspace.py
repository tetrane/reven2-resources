import reven2

import volatility.addrspace as addrspace


class Reven2AddressSpace(addrspace.BaseAddressSpace):
    """
    A physical layer address space connected to a Reven2 server
    and related to the context before a particular transition.
    """

    order = 198

    def __init__(self, base, config, **kargs):
        self.as_assert(base is None, 'Must be first Address Space')
        addrspace.BaseAddressSpace.__init__(self, base, config, **kargs)

        if not config.LOCATION:
            self.as_assert(False, "Not a Reven2 Address Space")

        location = config.LOCATION.split(':')
        self.as_assert(len(location) == 3, "Invalid Reven2 location (should be <host>:<port>:<transition id>).")

        hostname = location[0]
        try:
            port = int(location[1])
            transition_id = int(location[2])
        except (ValueError):
            self.as_assert(False, "Invalid Reven2 location (should be <host>:<port>:<transition id>).")

        try:
            self.rvn = reven2.RevenServer(hostname, port)
        except (RuntimeError):
            self.as_assert(False,
                           "Impossible to connect to the REVEN Server at {}:{}.".format(hostname, port))

        try:
            self.context = self.rvn.trace.context_before(transition_id)
        except (ValueError):
            self.as_assert(False,
                           "Impossible to jump at the REVEN transition #{}.".format(transition_id))

        self.physical_memory_regions = list(self.context.physical_memory_regions())
        self.name = "Reven Server on {}:{} at {}".format(hostname, port, transition_id)

    def read(self, offset, length):
        """ Reads a specified length in bytes from the current offset """
        paddr = reven2.address.PhysicalAddress(offset)
        return str(self.context.read(paddr, length, raw=True))

    def zread(self, offset, length):
        """ Delegate padded reads to normal read, since errors reading
        the physical address should probably be reported back to the user
        """
        data = self.read(offset, int(length))
        if len(data) != length:
            data += "\x00" * (length - len(data))
        return data

    def write(self, addr, data):
        return False

    def get_available_addresses(self):
        for (address, size) in self.physical_memory_regions:
            yield (address.offset, size)

    def is_valid_address(self, addr):
        if addr is None:
            return False
        for (address, size) in self.get_available_addresses():
            if (address <= addr and addr < address + size):
                return True
        return False

    def __eq__(self, other):
        return (self.__class__ == other.__class__ and
                self.base == other.base and
                self.name == other.name)
