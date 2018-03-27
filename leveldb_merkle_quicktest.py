#!/usr/bin/env python2

import os

import merkle
import leveldb_merkle_tree

LEAVES = [os.urandom(2048) for i in xrange(65536)]

CMT = merkle.CompactMerkleTree()
CMT.extend(LEAVES)
print CMT.root_hash().encode('hex')

os.system("rm -rf ./merkle_db")
LMT = leveldb_merkle_tree.LeveldbMerkleTree()
for l in LEAVES:
    LMT.add_leaf(l)
# LMT.extend(LEAVES)
print LMT.get_root_hash().encode('hex')

print CMT.root_hash() == LMT.get_root_hash()
LMT.close()
