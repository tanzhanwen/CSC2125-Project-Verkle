from bandersnatch import Point, Scalar
from random import randint, shuffle
from poly_utils import PrimeField
from time import time
from ipa_utils import IPAUtils, hash
from verkle_node import *
import rlp
import hashlib
import sys
import plyvel

# Bandersnatch curve modulus
MODULUS = 13108968793781547619861935127046491459309155893440570251786403306729687672801


class VerkleTrie:
    def __init__(self, storage, width_bits=8) -> None:

        # leveldb
        self._storage = storage
        self._initialize(width_bits)
        self._root = Node.Inner(Node.ROOT_PATH, {"commitment": Point().mul(0).serialize()})

    def _initialize(self, width_bits):
        
        # Verkle trie parameters
        self.KEY_LENGTH = 256 # bits

        self.WIDTH_BITS = width_bits
        self.WIDTH = 2 ** self.WIDTH_BITS
        self.primefield = PrimeField(MODULUS, self.WIDTH)

        # Number of key-value pairs to insert
        self.NUMBER_INITIAL_KEYS = 2**2

        # Number of keys to insert after computing initial tree
        self.NUMBER_ADDED_KEYS = 512

        # Number of keys to delete
        self.NUMBER_DELETED_KEYS = 512

        # Number of key/values pair in proof
        self.NUMBER_KEYS_PROOF = 5000
        

        self.BASIS = self.generate_basis()
        self.ipa_utils = IPAUtils(self.BASIS["G"], self.BASIS["Q"], self.primefield)

    def root(self):
        """ Returns a root node of the trie. Type is `bytes` if trie isn't empty and `None` othrewise. """
        return self._root

    def root_hash(self):
        """ Returns a hash of the trie's root node. For empty trie it's None. """
        return self._root["hash"]

    def generate_basis(self):
        """
        Generates a basis for Pedersen commitments
        """
        # TODO: Currently random points that differ on every run.
        # Implement reproducable basis generation once hash_to_curve is provided
        BASIS_G = [Point(generator=False) for i in range(self.WIDTH)]
        BASIS_Q = Point(generator=False)
        return {"G": BASIS_G, "Q": BASIS_Q}

    def get_verkle_indices(self, key):
        """
        Generates the list of verkle indices for key
        """
        x = int.from_bytes(key, "big")
        last_index_bits = self.KEY_LENGTH % self.WIDTH_BITS
        index = (x % (2**last_index_bits)) << (self.WIDTH_BITS - last_index_bits)
        x //= 2**last_index_bits
        indices = [index]
        for i in range((self.KEY_LENGTH - 1) // self.WIDTH_BITS):
            index = x % self.WIDTH
            x //= self.WIDTH
            indices.append(index)
        return tuple(reversed(indices))
    
    def insert_verkle_node(self, key, value):
        """
        Insert node without updating hashes/commitments (useful for building a full trie)
        """
        current_node = self._root
        indices = iter(self.get_verkle_indices(key))
        path = []
        index = None
        while current_node.type == "inner":
            previous_node = current_node
            index = str(next(indices))
            path.append(index)
            if index in current_node.data:
                current_node = self._get_node_by_path(path) # get inner node from leveldb by its path
            else:
                # leaf node does not exist
                # current_node[index] = {"node_type": "leaf", "key": key, "value": value}
                new_leaf = self.create_leaf_node(path, key, value)              # create new leaf node
                current_node.update_next_ref(index, new_leaf.get_path_hash())   # update parent node
                self._store_node(current_node)                                  # update storage
                self._store_node(new_leaf)
                return
        # leaf node exist
        if current_node.data["key"] == key:
            current_node.data["value"] = value
            self._store_node(current_node)
        else:
            # transform leaf node into inner node
            # create new two leaf nodes
            
            # previous_node[index] = {"node_type": "inner", "commitment": Point().mul(0)}
            new_inner = self.create_inner_node(path, data={"commitment": Point().mul(0).serialize()})
            self._store_node(new_inner)
            # previous_node.update_next_ref(index, new_inner)
            self.insert_verkle_node(self._root, key, value)
            self.insert_verkle_node(self._root, current_node.data["key"], current_node.data["value"])

    def _get_node_by_path(self, path):
        path_hash = hash(rlp.encode(path))
        return self._get_node_by_hash(path_hash)

    def _get_node_by_hash(self, path_hash):
        rlp_str = self._storage.get(path_hash)

        type, value = Node.decode(rlp_str)
        if type == "inner":
            return Node.Inner(path_hash, value)
        else:
            # leaf
            return Node.Leaf(path_hash, value)

    def _store_node(self, node):
        # node.test_print()
        self._storage.put(node.get_path_hash(), node.encode_value_rlp())

    def _store_nodes(self, nodes):
        wb = self._storage.write_batch()
        for node in nodes:
            wb.put(node.get_path_hash(), node.encode_value_rlp())
        wb.write()

    def create_leaf_node(self, path, key, value):
        data = {"key": key, "value": value}
        leaf = Node.Leaf(hash(rlp.encode(path)), data)
        return leaf

    def create_inner_node(self, path, data={}):
        new_inner = Node.Inner(hash(rlp.encode(path)), data)
        return new_inner

    def update_verkle_node(self, key, value):
        """
        Update or insert node and update all commitments and hashes
        """
        current_node = self._root
        indices = iter(self.get_verkle_indices(key))
        index = None
        path = []   # (index: int, parent node)
        path_index = [] # index: str
        update_node = [] # save for final update leveldb

        new_leaf_node = self.create_leaf_node([], key, value) # TODO
        self.add_node_hash(new_leaf_node)

        while True:
            index = str(next(indices))
            path.append((int(index), current_node))
            path_index.append(index)
            if index in current_node.data:
                child_node = self._get_node_by_hash(current_node.data[index])
                if child_node.type == "leaf":
                    old_node = child_node
                    child_node.test_print()
                    if child_node.data["key"] == key:
                        # leaf node exist and update
                        new_leaf_node.path = rlp.encode(path_index)
                        self._store_node(new_leaf_node)
                        value_change = (MODULUS + new_leaf_node.data["hash"] - old_node.data["hash"]) % MODULUS
                        break
                    else:
                        new_inner_node = self.create_inner_node(path_index)
                        update_node.append(new_inner_node)
                        new_index = str(next(indices))
                        old_index = str(self.get_verkle_indices(old_node.data["key"])[len(path)])
                        current_node.data[index] = new_inner_node.get_path_hash()

                        inserted_path = []
                        current_node = new_inner_node
                        while old_index == new_index:
                            index = new_index
                            path_index.append(index)
                            next_inner_node = self.create_inner_node(path_index)
                            update_node.append(next_inner_node)
                            current_node.data[index] = next_inner_node.get_path_hash()
                            inserted_path.append((index, current_node))
                            new_index = str(next(indices))
                            old_index = str(self.get_verkle_indices(old_node["key"])[len(path) + len(inserted_path)])
                            current_node = next_inner_node

                        path_index.append(new_index)
                        new_leaf_node.path = hash(rlp.encode(path_index))
                        update_node.append(new_leaf_node)
                        current_node.data[new_index] = new_leaf_node.get_path_hash()

                        path_index.pop()
                        path_index.append(old_index)
                        old_node.path = hash(rlp.encode(path_index))
                        update_node.append(old_node)
                        current_node.data[old_index] = old_node.get_path_hash()
                        self._store_nodes(update_node)
                        update_node.clear()
                        self.add_node_hash(current_node)

                        for index, node in reversed(inserted_path):
                            self.add_node_hash(node)

                        value_change = (MODULUS + new_inner_node.data["hash"] - old_node.data["hash"]) % MODULUS
                        break
                # exist inner node
                current_node = self._get_node_by_hash(current_node.data[index])
            else:
                # leaf does not exist
                new_leaf_node.path = rlp.encode(path_index)
                current_node.data[index] = new_leaf_node.get_path_hash()
                self._store_node(new_leaf_node)
                value_change = new_leaf_node.data["hash"]
                break

        # Update all the parent commitments along 'path'
        for index, node in reversed(path):
            old_point = Point().deserialize(node.data["commitment"])
            node.data["commitment"] = old_point.add(self.BASIS["G"][index].dup().mul(value_change)).serialize()
            old_hash = node.data["hash"]
            new_hash = int.from_bytes(node.data["commitment"], "little") % MODULUS
            node.data["hash"] = new_hash
            value_change = (MODULUS + new_hash - old_hash) % MODULUS
            update_node.append(node)

        # store all update into leveldb
        self._store_nodes(update_node)

    def add_node_hash(self, node):
        """
        Recursively adds all missing commitments and hashes to a verkle trie structure.
        """
        # node.test_print()
        if node.type == "leaf":
            commitment = self.ipa_utils.pedersen_commit_sparse({0: 1, 
                                                        1: int.from_bytes(node.data["key"][:31], "little"),
                                                        2: int.from_bytes(node.data["value"][:16], "little"), 
                                                        3: int.from_bytes(node.data["value"][16:], "little")})
            node.data["commitment"] = commitment.serialize()
            node.data["hash"] = int.from_bytes(commitment.serialize(), "little") % MODULUS
        if node.type == "inner":
            lagrange_polynomials = []
            values = {}
            for i in range(self.WIDTH):
                if str(i) in node.data:
                    node_i = self._get_node_by_hash(node.data[str(i)])
                    if "hash" not in node_i.data:
                        self.add_node_hash(node_i)
                    values[i] = node_i.data["hash"]
                    # print(values[i])
            commitment = self.ipa_utils.pedersen_commit_sparse(values)
            node.data["commitment"] = commitment.serialize()
            node.data["hash"] = int.from_bytes(commitment.serialize(), "little") % MODULUS
        self._store_node(node)

    def check_valid_tree(self, node, is_trie_root=True):
        """
        Checks that the tree is valid
        """
        if node.type == "inner":
            if not is_trie_root:
                only_child = self.get_only_child(node)
                if only_child is not None:
                    assert only_child["node_type"] == "inner"
        
            lagrange_polynomials = []
            values = {}
            for i in range(self.WIDTH):
                if str(i) in node.data:
                    node_i = self._get_node_by_hash(node.data[str(i)])
                    values[i] = node_i.data["hash"]
            commitment = self.ipa_utils.pedersen_commit_sparse(values)
            assert node.data["commitment"] == commitment.serialize()
            assert node.data["hash"] == int.from_bytes(commitment.serialize(), "little") % MODULUS

            for i in range(self.WIDTH):
                if str(i) in node.data:
                    node_i = self._get_node_by_hash(node.data[str(i)])
                    self.check_valid_tree(node_i, False)
        else:
            commitment = self.ipa_utils.pedersen_commit_sparse({0: 1, 
                                                        1: int.from_bytes(node.data["key"][:31], "little"),
                                                        2: int.from_bytes(node.data["value"][:16], "little"), 
                                                        3: int.from_bytes(node.data["value"][16:], "little")})
            assert node.data["commitment"] == commitment.serialize()
            assert node.data["hash"] == int.from_bytes(commitment.serialize(), "little") % MODULUS

    def get_only_child(self, node):
        """
        Returns the only child of a node which has only one child. Returns 'None' if node has 0 or >1 children
        """
        child_count = 0
        only_child = None
        for i in range(self.WIDTH):
            if str(i) in node.data:
                if child_count >= 1:
                    return None
                else:
                    only_child = self._get_node_by_hash(node.data[str(i)])
                    child_count += 1
        return only_child

if __name__ == "__main__":
    plyvel.destroy_db('/tmp/MPT/')
    db_verkle = plyvel.DB('/tmp/Verkle/', create_if_missing=True)
    verkle = VerkleTrie(storage=db_verkle)

    for i in range(verkle.NUMBER_INITIAL_KEYS):
        key = randint(0, 2**256-1).to_bytes(32, "little")
        value = randint(0, 2**256-1).to_bytes(32, "little")
        verkle.insert_verkle_node(key, value)
        # values[key] = value

    time_a = time()
    verkle.add_node_hash(verkle._root)
    time_b = time()

    print("Computed verkle root in {0:.3f} s".format(time_b - time_a), file=sys.stderr)

    print(verkle._root.data["hash"])

    time_a = time()
    verkle.check_valid_tree(verkle._root)
    time_b = time()

    print("[Checked tree valid: {0:.3f} s]".format(time_b - time_a), file=sys.stderr)
    
    time_x = time()
    for i in range(verkle.NUMBER_ADDED_KEYS):
        key = randint(0, 2**256-1).to_bytes(32, "little")
        value = randint(0, 2**256-1).to_bytes(32, "little")
        verkle.update_verkle_node(key, value)
    time_y = time()
            
    print("Additionally inserted {0} elements in {1:.3f} s".format(verkle.NUMBER_ADDED_KEYS, time_y - time_x), file=sys.stderr)

    time_a = time()
    verkle.check_valid_tree(verkle._root)
    time_b = time()

    print("[Checked tree valid: {0:.3f} s]".format(time_b - time_a), file=sys.stderr)

    del db_verkle
    plyvel.destroy_db('/tmp/MPT/')