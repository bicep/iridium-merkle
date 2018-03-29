#!/usr/bin/env python2

import os
import random

import merkle
import in_memory_merkle_tree
import leveldb_merkle_tree

LEAF_SIZE = 2048
NUM_LEAVES = 65536
TEST_LEAF = random.randint(0, NUM_LEAVES)

def encode_byte_list(l):
    return [h.encode('hex') for h in l]

LEAVES = [os.urandom(LEAF_SIZE) for i in xrange(NUM_LEAVES)]

IMT = in_memory_merkle_tree.InMemoryMerkleTree(LEAVES)
print "Root hash in InMemoryMerkleTree: " + IMT.get_root_hash().encode('hex')

os.system("rm -rf ./merkle_db")
LMT = leveldb_merkle_tree.LeveldbMerkleTree()
for l in LEAVES:
    LMT.add_leaf(l)
# LMT.extend(LEAVES)
print "Root hash in LeveldbMerkleTree: " + LMT.get_root_hash().encode('hex')

# check that root hashes are identical
print "Are the two root hashes identical? %s: " % (IMT.get_root_hash() == LMT.get_root_hash())

# check that consistency proof is working and identical
MV = merkle.MerkleVerifier()
const_proof = LMT.get_consistency_proof(TEST_LEAF)
print "Consistency proof for subtree at leaf %s:\n%s" % (TEST_LEAF, encode_byte_list(const_proof))
print "Is consistency proof correct?: %s" % MV.verify_tree_consistency(TEST_LEAF, NUM_LEAVES, IMT.get_root_hash(TEST_LEAF), LMT.get_root_hash(), const_proof)

# check that inclusion proof is working and identical
leaf_hash = LMT.get_leaf(TEST_LEAF)
incl_proof = LMT.get_inclusion_proof(TEST_LEAF)
print "Inclusion proof for leaf %s:\n%s" % (TEST_LEAF, encode_byte_list(incl_proof))
print "Are inclusion proofs from InMemoryMerkleTree and LeveldbMerkleTree identical?: %s" % (IMT.get_inclusion_proof(TEST_LEAF, NUM_LEAVES) == incl_proof)
print "Is inclusion proof correct?: %s" % MV.verify_leaf_hash_inclusion(leaf_hash, TEST_LEAF, incl_proof, LMT)

LMT.close()
