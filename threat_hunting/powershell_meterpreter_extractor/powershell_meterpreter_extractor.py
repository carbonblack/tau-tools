#!/usr/bin/env python

import base64
import zlib
import argparse
import re
import os


def get_parser():
    parser = argparse.ArgumentParser()
    parser.add_argument('-o', '--output', type=str, help='Provide a path to save final stage payload')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-i', '--input', type=str, help='Provide a base64 encoded string in the command line')
    group.add_argument('-f', '--file', type=str, help='Provide a path to a file that contains a base64 encoded string')

    return parser


def enumerate_base64string(b):
    offset = b.lower().find("frombase64string(")
    if offset > 0:
        b64_end_offset = b[offset + 18:].find('"')
        j = re.findall('[a-zA-Z0-9\.]{8,}', base64.b64decode(b[offset + 18:offset + 18 + b64_end_offset])[200:])
        for z in j:
            print "\t[*] Potential C2: " + z
    else:
        return 0


def save_file(file_path, data):
    if os.path.exists(file_path):
        while True:
            user_input = raw_input("\n[!] File '" + file_path + "' already exists. Overwrite? (y|n): ").lower()
            if user_input == "no" or user_input == "n":
                print "Qutting."
                exit(0)
            elif user_input == "yes" or user_input == "y":
                break
            else:
                print "[!] Invalid response."
                continue

    with open(file_path, 'w') as fh:
        for line in data:
            fh.write("%s\n" % line)


def get_stages(b64_string):
    data_b64_mod = len(b64_string) % 4
    if data_b64_mod != 0:
        print "[!] Invalid base64 length. The original buffer will be truncated by %s bytes" % str(data_b64_mod)
        b64_string = b64_string[:-data_b64_mod]

    # NOTE this may raise an exception, but that's okay. Caller is handling it.
    stage1 = base64.b64decode(b64_string).decode("utf-16") + "\n"
    stage2 = zlib.decompress(base64.b64decode(stage1.split('"')[1]), 31)

    return stage1, stage2


def get_b64_string(args):
    b64_string = args.input

    if args.file:
        with open(args.file, "r") as fh:
            b64_string = fh.read().strip()

    return b64_string


def main():
    parser = get_parser()
    args = parser.parse_args()
    b64_string = get_b64_string(args)

    try:
        stage1, stage2 = get_stages(b64_string)
        if not args.output:
            print ("\n[*] First Stage: \n\t" + stage1)
            print ("\n[*] Second Stage: \n\t" + stage2)
            enumerate_base64string(stage2)
        else:
            save_file(args.output + "_first_stage.txt", [stage1])
            save_file(args.output + "_shellcode.txt", [stage2])
            print "\n[*] Saved stages to filesystem as: %s" % args.output
            enumerate_base64string(stage2)
    except Exception as error:
        print error


if __name__ == "__main__":
    main()
