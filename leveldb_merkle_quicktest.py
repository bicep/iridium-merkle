#!/usr/bin/env python2

import os

import merkle
import in_memory_merkle_tree
import leveldb_merkle_tree

LEAVES = [os.urandom(2048) for i in xrange(65536)]

IMT = in_memory_merkle_tree.InMemoryMerkleTree(LEAVES)
print IMT.get_root_hash().encode('hex')

os.system("rm -rf ./merkle_db")
LMT = leveldb_merkle_tree.LeveldbMerkleTree()
for l in LEAVES:
    LMT.add_leaf(l)
# LMT.extend(LEAVES)
print LMT.get_root_hash().encode('hex')

# check that root hashes are identical
print IMT.get_root_hash() == LMT.get_root_hash()

# check that consistency proof is working and identical
MV = merkle.MerkleVerifier()
const_proof = LMT.get_consistency_proof(20000)
print [h.encode('hex') for h in const_proof]
print MV.verify_tree_consistency(20000, 65536, IMT.get_root_hash(20000), LMT.get_root_hash(), const_proof)

# check that inclusion proof is working and identical
leaf_hash = LMT.get_leaf(20000)
incl_proof = LMT.get_inclusion_proof(20000)
print [h.encode('hex') for h in incl_proof]
print IMT.get_inclusion_proof(20000, 65536) == incl_proof
print MV.verify_leaf_hash_inclusion(leaf_hash, 20000, incl_proof, LMT)

LMT.close()
