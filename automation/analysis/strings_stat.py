import argparse
import builtins
import logging

import reven2


'''
Purpose:
    Display statistics about strings accesses such as:
    * binary that read/write a string.
    * number of read/write accesses a binary does on a string.

Dependencies:
    The script requires that the REVEN2 server have:
    * the Strings enabled.
    * the OSSI enabled.
'''


class BinaryStringOperations(object):
    def __init__(self, binary):
        self.binary = binary
        self.read_count = 0
        self.write_count = 0


def strings_stat(reven_server, pattern=''):
    for string in reven_server.trace.strings(args.pattern):
        binaries = builtins.dict()
        try:
            # iterates on all accesses to all binaries that access to the string (read/write).
            for memory_access in string.memory_accesses():
                ctx = memory_access.transition.context_before()
                if ctx.ossi.location() is None:
                    continue
                binary = ctx.ossi.location().binary
                try:
                    binary_operations = binaries[binary.path]
                except KeyError:
                    binaries[binary.path] = BinaryStringOperations(binary)
                    binary_operations = binaries[binary.path]
                if memory_access.operation == reven2.memhist.MemoryAccessOperation.Read:
                    binary_operations.read_count += 1
                else:
                    binary_operations.write_count += 1
        except RuntimeError:
            # Limitation of `memory_accesses` method that raise a RuntimeError when
            # the service timeout.
            pass
        yield (string, binaries)


def parse_args():
    parser = argparse.ArgumentParser(description='Display statistics about strings accesses.')
    parser.add_argument('--host', dest='host', help='Reven host, as a string (default: "localhost")',
                        default='localhost', type=str)
    parser.add_argument('--port', dest='port', help='Reven port, as an int (default: 13370)',
                        type=int, default=13370)
    parser.add_argument('-v', '--verbose', dest='log_level', help='Increase output verbosity',
                        action='store_const', const=logging.DEBUG, default=logging.INFO)
    parser.add_argument('pattern', nargs='?', help='Pattern of the string, looking for '
                        '"*pattern*", does not support Regular Expression. If no pattern provided, '
                        'all strings will be used.',
                        default='', type=str)
    return parser.parse_args()


if __name__ == '__main__':
    args = parse_args()

    logging.basicConfig(format='%(message)s', level=args.log_level)

    logging.debug('##### Getting stat for all strings containing "{0}" #####\n'.format(args.pattern))

    # Get a server instance
    reven_server = reven2.RevenServer(args.host, args.port)

    # Print strings
    for string, binaries in strings_stat(reven_server, args.pattern):
        logging.info('"{}":'.format(string.data))
        for binary_operations in binaries.values():
            logging.info('\t- {} (Read: {} - Write: {})'.format(binary_operations.binary.filename,
                                                                binary_operations.read_count,
                                                                binary_operations.write_count))
        logging.info('')
    logging.debug('##### Done #####')
