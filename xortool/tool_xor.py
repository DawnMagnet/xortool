#!/usr/bin/env python3
from xortool import __version__

__doc__ = f"""
xortool-xor {__version__}
xor strings
options:
    -s  -  string with \\xAF escapes
    -r  -  raw string
    -h  -  hex-encoded string (non-letterdigit chars are stripped)
    -f  -  read data from file (- for stdin)

    --newline -  newline at the end (default)
    -n / --no-newline -  no newline at the end
    --cycle - do not pad (default)
    --no-cycle / --nc  -  pad smaller strings with null bytes
example: xor -s lol -h 414243 -f /etc/passwd
"""

import getopt
import sys


def main():
    cycle = True
    newline = True
    try:
        opts, _ = getopt.getopt(
            sys.argv[1:],
            "ns:r:h:f:",
            ["cycle", "no-cycle", "nc", "no-newline", "newline"],
        )
        datas = []
        for c, val in opts:
            if c == "--cycle":
                cycle = True
            elif c in ("--no-cycle", "--nc"):
                cycle = False
            elif c == "--newline":
                newline = True
            elif c in ("-n", "--no-newline"):
                newline = False
            else:
                datas.append(arg_data(c, val))
        if not datas:
            raise getopt.GetoptError("no data given")
    except getopt.GetoptError as e:
        print("error:", e, file=sys.stderr)
        print(__doc__, file=sys.stderr)
        quit()

    sys.stdout.buffer.write(xor(datas, cycle=cycle))
    if newline:
        sys.stdout.buffer.write(b"\n")


def xor(args, cycle=True):
    # Sort by len DESC
    args.sort(key=len, reverse=True)
    res = bytearray(args.pop(0))
    maxlen = len(res)

    for s in args:
        slen = len(s)
        for i in range(maxlen if cycle else slen):
            res[i] ^= s[i % slen]
    return res


def from_str(s):
    res = b""
    for char in s.encode("utf-8").decode("unicode_escape"):
        res += bytes([ord(char)])
    return res


def from_file(s):
    if s == "-":
        s = sys.stdin.fileno()
    return open(s, "rb").read()


def arg_data(opt, s):
    if opt == "-s":
        return from_str(s)
    if opt == "-r":
        return str.encode(s)
    if opt == "-h":
        return bytes.fromhex(s)
    if opt == "-f":
        return from_file(s)
    raise getopt.GetoptError("unknown option -%s" % opt)


if __name__ == "__main__":
    main()
