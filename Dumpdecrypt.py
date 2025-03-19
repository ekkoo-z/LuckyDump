#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys

def main():
    if len(sys.argv) != 3:
        print("python decrypt.py <input> <output>")
        sys.exit(1)

    source = sys.argv[1]
    dest = sys.argv[2]

    key = b"kong" + b"\x00" * (8 - len(b"kong"))
    keylen = 8
    index = 0

    try:
        with open(source, "rb") as fSource, open(dest, "wb") as fDest:
            while True:
                byte = fSource.read(1)
                if not byte:
                    break
                ckey = key[index % keylen]
                decrypted_byte = bytes([byte[0] ^ ckey])
                fDest.write(decrypted_byte)
                index += 1

        print(f"sucess: {dest}")
    except Exception as e:
        print("fail", e)

if __name__ == "__main__":
    main()
