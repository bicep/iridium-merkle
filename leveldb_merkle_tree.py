"""Merkle Tree backed by LevelDB.

Operates (and owns) a LevelDB database of leaves which can be updated.
"""

import plyvel
import math
import struct

import merkle

class LeveldbMerkleTree(object):
    """LevelDB Merkle Tree representation."""

    def __init__(self, db="./merkle_db"):
        """Start with the LevelDB database of leaves and hasher provided."""
        self.__hasher = IncrementalTreeHasher()
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
            wb.put('leaves-' + struct.pack(">I", cur_tree_size), leaf_hash)
            wb.put('index-' + leaf_hash, struct.pack(">I", cur_tree_size))
            wb.put('stats-tree_size', str(cur_tree_size + 1))
        return cur_tree_size

    def get_leaf_index(self, leaf_hash):
        """Returns the index of the leaf hash, or -1 if not present."""
        raw_index = self.__index_db.get(leaf_hash)
        if raw_index:
            return struct.unpack(">I", self.__index_db.get(leaf_hash))[0]
        else:
            return -1

    def get_root_hash(self, tree_size=None):
        """Returns the root hash of the tree denoted by |tree_size|."""
        if tree_size is None:
            tree_size = self.tree_size
        if tree_size > self.tree_size:
            raise ValueError("Specified size beyond known tree: %d" % tree_size)
        leaves = [l for l in self.__leaves_db.iterator(start=struct.pack(">I", 0), stop=struct.pack(">I", tree_size), include_key=False)]
        return self.__hasher.hash_full_tree(leaves)

    def __repr__(self):
        return "%s(%r)" % (self.__class__.__name__, self.__hasher)

class IncrementalTreeHasher(merkle.TreeHasher):
    def _hash_full(self, leaves, l_idx, r_idx):
        """Hash the leaves between (l_idx, r_idx) as a valid entire tree.

        Note that this is only valid for certain combinations of indexes,
        depending on where the leaves are meant to be located in a parent tree.

        Returns:
            (root_hash, hashes): where root_hash is that of the entire tree,
            and hashes are that of the full (i.e. size 2^k) subtrees that form
            the entire tree, sorted in descending order of size.
        """
        width = r_idx - l_idx
        if width < 0 or l_idx < 0 or r_idx > len(leaves):
            raise IndexError("%s,%s not a valid range over [0,%s]" % (
                l_idx, r_idx, len(leaves)))
        elif width == 0:
            return self.hash_empty(), ()
        elif width == 1:
            leaf_hash = leaves[l_idx]
            return leaf_hash, (leaf_hash,)
        else:
            # next smallest power of 2
            split_width = 2**((width - 1).bit_length() - 1)
            assert split_width < width <= 2*split_width
            l_root, l_hashes = self._hash_full(leaves, l_idx, l_idx+split_width)
            assert len(l_hashes) == 1 # left tree always full
            r_root, r_hashes = self._hash_full(leaves, l_idx+split_width, r_idx)
            root_hash = self.hash_children(l_root, r_root)
            return (root_hash, (root_hash,) if split_width*2 == width else
                                l_hashes + r_hashes)
