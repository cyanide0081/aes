package usage

import "core:fmt"

@(private)
USAGE ::
`usage: aes [OPERATION] [ARGUMENTS]

Operations:
    encrypt : encrypts the file
    decrypt : decrypts the file

Arguments:
    -i [FILENAME] : the input file
    -o [FILENAME] : the output file
    -m [MODE]     : the operation mode (CBC/ECB)
    -v [IV]       : the 128-bit initialization vector (CBC mode only)
    -k [KEY]      : the 128-bit key (16 comma-separated unsigned 8-bit values)

Example: aes encrypt -i input.bin -o output.bin -m CBC
    -i 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
    -k 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0`

print :: proc() {
    fmt.println(USAGE)
}
