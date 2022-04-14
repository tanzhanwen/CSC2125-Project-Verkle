from abc import ABC, abstractmethod
from glob import glob
from verkle_trie_new import *
from new_bintrie import *
from mpt import *

SMT_EMPTY_VALUE = b'\x00' * 32

class Trie(ABC):
    def __init__(self, values):
        """_summary_

        Args:
            values (Dict): A dict saving all pairs of keys and corresponding values
        """
        self._values = values
        self._root = None

    def root(self):
        """_summary_
            Returns a root node of the trie.
        Returns:
            _type_: if verkle, a dict; if mpt, bytes
        """
        return self._root

    @abstractmethod 
    def root_hash(self):
        """_summary_
            Returns a hash of the trie's root node.
        Returns:
            _type_: bytes. For empty trie it's None
        """
        pass

    @abstractmethod
    def update(self, key, value):
        """_summary_

        Args:
            key (bytes[32]): _description_
            value (bytes[32]): _description_
        """
        self._values[key] = value
    
    @abstractmethod
    def delete(self, key):

        """_summary_
            Delete node and update all commitments and hashes

        Args:
            key (bytes[32]): _description_
        """
        del self._values[key]
    
    @abstractmethod
    def get_proof(self, keys):
        """_summary_
            Creates a proof for the 'keys' in the trie
        Args:
            keys ([bytes]): keys in proof
        """
        # TODO
        pass
    
    @abstractmethod
    def verify(self, keys, values, proof):
        """_summary_
            Checks tree proof
        Args:
            keys ([bytes]): keys in proof
            values ([bytes]): values correspond to the keys
            proof (_type_): proof need to be verify
        """
        # TODO
        pass


class Verkle(Trie):
    def __init__(self, values, width_bits=8, db=None):
        self._values = values

        # initialize the root of verkle trie
        self._verkle = VerkleTrie(db, width_bits)
        self._db = db
        self._initialize()

    def _initialize(self):
        for key in self._values:
            self._verkle.insert_verkle_node(key, self._values[key]) 
        self._verkle.add_node_hash(self._verkle.root())

    def root_hash(self):
        """_summary_
            Returns a hash of the trie's root node.
        Returns:
            _type_: bytes. For empty trie it's None
        """
        return self._root["hash"]

    def update(self, key, value):
        """_summary_

        Args:
            key (bytes[32]): _description_
            value (bytes[32]): _description_
        """
        self._verkle.update_verkle_node(key, value)
        self._values[key] = value
    
    def delete(self, key):

        """_summary_
            Delete node and update all commitments and hashes

        Args:
            key (bytes[32]): _description_
        """
        self._verkle.delete_verkle_node(key)
        del self._values[key]

    def check(self):
        self._verkle.check_valid_tree(self._verkle._root)
    
    def get_proof(self, keys):
        """_summary_
            Creates a proof for the 'keys' in the trie
        Args:
            keys ([bytes]): keys in proof
        """
        return self._verkle.make_verkle_proof(keys)
    
    def verify(self, keys, values, proof):
        """_summary_
            Checks tree proof
        Args:
            keys ([bytes]): keys in proof
            values ([bytes]): values correspond to the keys
            proof (_type_): proof need to be verify
        """
        return self._verkle.check_verkle_proof(keys, values, proof)


class SMT(Trie):
    def __init__(self, values, db=None):
        super().__init__(values)
        self._values = values
        self._root = None
        self._db = EphemDB(kv=db)
        self._initialize()

    def _initialize(self):
        # self._db = EphemDB()
        self._root = new_tree(self._db)
        for key in self._values:
            self._root = update(self._db, self._root, key, self._values[key])

    def root_hash(self):
        """_summary_
            Returns a hash of the trie's root node.
        Returns:
            _type_: bytes. For empty trie it's None
        """
        return self._root

    def update(self, key, value):
        """_summary_

        Args:
            key (bytes[32]): _description_
            value (bytes[32]): _description_
        """
        self._root = update(self._db, self._root, key, value)
        self._values[key] = value

    def delete(self, key):
        """_summary_
            Delete node and update all commitments and hashes

        Args:
            key (bytes[32]): _description_
        """
        self._root = update(self._db, self._root, key, SMT_EMPTY_VALUE)
        del self._values[key]

    def get_proof(self, keys):
        """_summary_
            Creates a proof for the 'keys' in the trie
        Args:
            keys ([bytes]): keys in proof
        """
        ret_proof = []
        for key in keys:
            proof = make_merkle_proof(self._db, self._root, key)
            ret_proof.append(compress_proof(proof))
        return ret_proof

    def verify(self, keys, values, proof):
        """_summary_
            Checks tree proof
        Args:
            keys ([bytes]): keys in proof
            values ([bytes]): values correspond to the keys
            proof (_type_): proof need to be verify
        """
        ret = True
        for (key, value, single_proof)in zip(keys, values, proof):
            ret = ret and verify_proof(decompress_proof(single_proof), self._root, key, value)
        return ret

class MPT(Trie):
    def __init__(self, values, storage={}):
        super().__init__(values)
        self._root = MerklePatriciaTrie(storage, secure=True)
        self._initialize()

    def _initialize(self):
        for key in self._values:
            self._root.update(key, self._values[key])

    def root_hash(self):
        """_summary_
            Returns a hash of the trie's root node.
        Returns:
            _type_: bytes. For empty trie it's None
        """
        self._root.root_hash()

    def update(self, key, value):
        """_summary_

        Args:
            key (bytes[32]): _description_
            value (bytes[32]): _description_
        """
        self._root.update(key, value)
        self._values[key] = value
    
    def delete(self, key):

        """_summary_
            Delete node and update all commitments and hashes

        Args:
            key (bytes[32]): _description_
        """
        self._root.delete(key)
        del self._values[key]
    
    def get_proof(self, keys):
        """_summary_
            Creates a proof for the 'keys' in the trie
        Args:
            keys ([bytes]): keys in proof
        """
        pass
    
    def verify(self, keys, values, proof):
        """_summary_
            Checks tree proof
        Args:
            keys ([bytes]): keys in proof
            values ([bytes]): values correspond to the keys
            proof (_type_): proof need to be verify
        """
        pass

if __name__ == "__main__":
    # test_verkle()
    pass