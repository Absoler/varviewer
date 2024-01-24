#!/usr/local/bin/python3

''' regression test:  check the correctness of extracter
    by comparing output json with previous right version

'''
import json, sys, argparse

parser = argparse.ArgumentParser()
parser.add_argument("oldPath")
parser.add_argument("newPath")
parser.add_argument("-sD","--showDetail", action='store_true', help="whether show test detail")
args = parser.parse_args()

old_file = open(args.oldPath, "r")
new_file = open(args.newPath, "r")

old_json, new_json = json.load(old_file), json.load(new_file)
old_map = { (addr["name"], addr["decl_file"], addr["decl_row"]):addr for addr in old_json }
old_ids = set(old_map.keys())
new_map = { (addr["name"], addr["decl_file"], addr["decl_row"]):addr for addr in new_json }
new_ids = set(new_map.keys())
extra = (new_ids).difference(old_ids)
lack = (old_ids).difference(new_ids)
both = (old_ids).intersection(new_ids)

# number testing
print(f"### number testing")
print(f"old / new var:  {len(old_json)} / {len(new_json)}\nlack {len(lack)} and add {len(extra)}\n")


# content testing
addr_keys = ["valid"]
addrExp_keys = ["dwarfType", "reg", "startpc", "endpc", "needCFA", "detailedDwarfType"]
exp_keys = ["regs", "offset", "valid", "empty", "hasChild", "isCFA"]

right_count = 0
both = list(both)
for addr_id in both:
    right = True
    old_addr = old_map[addr_id]
    new_addr = new_map[addr_id]
    for key in addr_keys:
        if old_addr[key] != new_addr[key]:
            right = False
            break
    
    old_addrExps = old_addr["addrExps"]
    new_addrExps = new_addr["addrExps"]
    valid_cnt = 0
    for addrExp in old_addrExps:
        if addrExp["valid"]:
            valid_cnt += 1
    for addrExp in new_addrExps:
        if addrExp["valid"]:
            valid_cnt -= 1
    if valid_cnt != 0:
        right = False
    
    if right:
        right_count += 1

print(f"### content testing")
print(f"match count {right_count} / {len(both)}")


new_file.close()
old_file.close()

