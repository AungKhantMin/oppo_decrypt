#!/usr/bin/env python3
# (c) Aung Khant Min, MIT License
import os
import sys
import base64
from Crypto.Cipher import AES
import zipfile



unpad = lambda s: s[:-ord(s[len(s) - 1:])]

keys = [
    ["OrJ987vYU92tSF1NbeNuilkz6yBD2A3eVLrI6p1Dc/11sipvuwO2slp7q4NEKL9+MGn1CaCj6REHpdzaLeQxNQ==","12345678876543211234567887654abc"]
]

def aes_ecb(key,data):
    ctx = AES.new(bytes(key,'utf-8'),AES.MODE_ECB)
    password = ctx.decrypt(base64.b64decode(data))
    return unpad(password.decode('utf-8'))


def main():
    if len(sys.argv)<3:
        print("Usage: ./ofp_zip_extract.py [Filename.ofp] [Directory to extract files to]")
        exit(0)

    filename=sys.argv[1]
    outdir=sys.argv[2]
    if not os.path.exists(outdir):
        os.mkdir(outdir)
    
    zip_file = zipfile.ZipFile(filename)
    zip_file.debug = True
    for key in keys:
        password = bytes(aes_ecb(key[1],key[0]),'utf-8')
        try:
            zip_file.extractall(pwd=password,path=outdir)
            print("[+] Successfully Extracted")
            print("[+] Output Dir : {0}".format(outdir))
            exit(0)
        except:
           pass
    
    print("[-] Password Not Fond")
    exit(0)


if __name__ == "__main__":
    main()
