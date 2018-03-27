"""Merkle Tree backed by LevelDB.

Operates (and owns) a LevelDB database of leaves which can be updated.
"""

import plyvel
import math

import merkle

def _down_to_power_of_two(n):
    """Returns the power-of-2 closest to n."""
    if n < 2:
        raise ValueError("N should be >= 2: %d" % n)
    log_n = math.log(n, 2)
    p = int(log_n)
    # If n is exactly power of 2 then 2**p would be n, decrease p by 1.
    if p == log_n:
        p -= 1
    return 2**p

class LeveldbMerkleTree(object):
    """LevelDB Merkle Tree representation."""

    def __init__(self, db="./merkle_db", hasher=merkle.TreeHasher()):
        """Start with the LevelDB database of leaves and hasher provided."""
        self.__hasher = hasher
        self.__db = plyvel.DB(db, create_if_missing=True)
        self.__leaves_db = self.__db.prefixed_db('leaves-')
        self.__stats_db = self.__db.prefixed_db('stats-')
        self.__index_db = self.__db.prefixed_db('index-')

    def close(self):
        self.__db.close()

    @property
    def tree_size(self):
        return int(self.__stats_db.get('tree_size', default='0'))

    def add_leaf(self, leaf):
        """Adds |leaf| to the tree, returning the index of the entry."""
        cur_tree_size = self.tree_size
        leaf_hash = self.__hasher.hash_leaf(leaf)
        with self.__db.write_batch() as wb:
            self.__db.put('leaves-' + str(cur_tree_size), leaf_hash)
            self.__db.put('index-' + leaf_hash, str(cur_tree_size))
            self.__db.put('stats-tree_size', str(cur_tree_size + 1))
        return cur_tree_size

    def get_leaf_index(self, leaf_hash):
        """Returns the index of the leaf hash, or -1 if not present."""
        return int(self.__index_db.get(leaf_hash, default='-1'))

    def __repr__(self):
        return "%s(%r)" % (self.__class__.__name__, self.__hasher)
