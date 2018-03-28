"""Merkle Tree backed by LevelDB.

Operates (and owns) a LevelDB database of leaves which can be updated.
"""

import plyvel
import math
import struct

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

def encode_int(n):
    """Encode an integer into a big-endian bytestring."""
    return struct.pack(">I", n)

def decode_int(n):
    """Decode a big-endian bytestring into an integer."""
    return stuct.unpack(">I", n)[0]

class LeveldbMerkleTree(object):
    """LevelDB Merkle Tree representation."""

    def __init__(self, db="./merkle_db", leaves_db_prefix='leaves-', index_db_prefix='index-', stats_db_prefix='stats-'):
        """Start with the LevelDB database of leaves provided."""
        self.__hasher = IncrementalTreeHasher()
        self.__db = plyvel.DB(db, create_if_missing=True)
        self.__leaves_db_prefix = leaves_db_prefix
        self.__index_db_prefix = index_db_prefix
        self.__stats_db_prefix = stats_db_prefix
        self.__leaves_db = self.__db.prefixed_db(leaves_db_prefix)
        self.__index_db = self.__db.prefixed_db(index_db_prefix)
        self.__stats_db = self.__db.prefixed_db(stats_db_prefix)

    def close(self):
        self.__db.close()

    @property
    def tree_size(self):
        return int(self.__stats_db.get('tree_size', default='0'))

    @property
    def leaves_db_prefix(self):
        return self.__leaves_db_prefix

    @property
    def index_db_prefix(self):
        return self.__index_db_prefix

    @property
    def stats_db_prefix(self):
        return self.__stats_db_prefix

    def get_leaves(self, start=0, stop=None):
        if stop is None:
            stop = self.tree_size
        return [l for l in self.__leaves_db.iterator(start=encode_int(start), stop=encode_int(stop), include_key=False)]

    def add_leaf(self, leaf):
        """Adds |leaf| to the tree, returning the index of the entry."""
        cur_tree_size = self.tree_size
        leaf_hash = self.__hasher.hash_leaf(leaf)
        with self.__db.write_batch() as wb:
            wb.put(self.__leaves_db_prefix + encode_int(cur_tree_size), leaf_hash)
            wb.put(self.__index_db_prefix + leaf_hash, encode_int(cur_tree_size))
            wb.put(self.__stats_db_prefix + 'tree_size', str(cur_tree_size + 1))
        return cur_tree_size

    def extend(self, new_leaves):
        """Extend this tree with new_leaves on the end."""
        cur_tree_size = self.tree_size
        leaf_hashes = [self.__hasher.hash_leaf(l) for l in new_leaves]
        with self.__db.write_batch() as wb:
            for lf in leaf_hashes:
                wb.put(self.__leaves_db_prefix + encode_int(cur_tree_size), lf)
                wb.put(self.__index_db_prefix + lf, encode_int(cur_tree_size))
                cur_tree_size += 1
            wb.put(self.__stats_db_prefix + 'tree_size', str(cur_tree_size))

    def get_leaf_index(self, leaf_hash):
        """Returns the index of the leaf hash, or -1 if not present."""
        raw_index = self.__index_db.get(leaf_hash)
        if raw_index:
            return decode_int(raw_index)
        else:
            return -1

    def get_root_hash(self, tree_size=None):
        """Returns the root hash of the tree denoted by |tree_size|."""
        if tree_size is None:
            tree_size = self.tree_size
        if tree_size > self.tree_size:
            raise ValueError("Specified size beyond known tree: %d" % tree_size)
        return self.__hasher.hash_full_tree(self.get_leaves(stop=tree_size))

    def _calculate_subproof(self, m, leaves, complete_subtree):
        """SUBPROOF, see RFC6962 section 2.1.2."""
        n = len(leaves)
        if m == n or n == 1:
            if complete_subtree:
                return []
            else:
                return [self.__hasher.hash_full_tree(leaves)]

        k = _down_to_power_of_two(n)
        if m <= k:
            node = self.__hasher.hash_full_tree(leaves[k:n])
            res = self._calculate_subproof(m, leaves[0:k], complete_subtree)
        else:
            # m > k
            node = self.__hasher.hash_full_tree(leaves[0:k])
            res = self._calculate_subproof(m - k, leaves[k:n], False)
        res.append(node)
        return res

    def get_consistency_proof(self, tree_size_1, tree_size_2=None):
        """Returns a consistency proof between two snapshots of the tree."""
        if tree_size_2 is None:
            tree_size_2 = self.tree_size

        if tree_size_1 > self.tree_size or tree_size_2 > self.tree_size:
            raise ValueError("Requested proof for sizes beyond current tree:"
                    " current tree: %d tree_size_1 %d tree_size_2 %d" % (
                        self.tree_size, tree_size_1, tree_size_2))

        if tree_size_1 > tree_size_2:
            raise ValueError("tree_size_1 must be less than tree_size_2")
        if tree_size_1 == tree_size_2 or tree_size_1 == 0:
            return []

        return self._calculate_subproof(
                tree_size_1, self.get_leaves(stop=tree_size_2), True)

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
