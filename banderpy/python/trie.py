from abc import ABC, abstractmethod
from verkle_trie import *

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


class VerkleTrie(Trie):
    def __init__(self, values, width_bits=8):
        self._values = values

        # initialize the root of verkle trie
        self._root = None
        self._initialize(width_bits)

    def _initialize(self, width_bits):
        WIDTH_BITS = width_bits
        WIDTH = 2 ** WIDTH_BITS
        primefield = PrimeField(MODULUS, WIDTH)

        BASIS = generate_basis(WIDTH)
        ipa_utils = IPAUtils(BASIS["G"], BASIS["Q"], primefield)
        
        self._root = {"node_type": "inner", "commitment": Point().mul(0)}

        for key in self._values:
            insert_verkle_node(self._root, key, self._values[key])
    
        add_node_hash(self._root)

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
        update_verkle_node(self._root, key, value)
        self._values[key] = value
    
    def delete(self, key):

        """_summary_
            Delete node and update all commitments and hashes

        Args:
            key (bytes[32]): _description_
        """
        delete_verkle_node(self._root, key)
        del self._values[key]
    
    def get_proof(self, keys):
        """_summary_
            Creates a proof for the 'keys' in the trie
        Args:
            keys ([bytes]): keys in proof
        """
        return make_verkle_proof(self._root, keys)
    
    def verify(self, keys, values, proof):
        """_summary_
            Checks tree proof
        Args:
            keys ([bytes]): keys in proof
            values ([bytes]): values correspond to the keys
            proof (_type_): proof need to be verify
        """
        return check_verkle_proof(self._root["commitment"].serialize(), keys, values, proof)

class MPT(Trie):
    def __init__(self, values):
        super().__init__(values)
        self._initialize()

    def _initialize(self):
        # TODO
        pass

    def root_hash(self):
        """_summary_
            Returns a hash of the trie's root node.
        Returns:
            _type_: bytes. For empty trie it's None
        """
        # TODO
        pass

    def update(self, key, value):
        """_summary_

        Args:
            key (bytes[32]): _description_
            value (bytes[32]): _description_
        """
        # TODO
        pass
    
    def delete(self, key):

        """_summary_
            Delete node and update all commitments and hashes

        Args:
            key (bytes[32]): _description_
        """
        # TODO
        pass
    
    def get_proof(self, keys):
        """_summary_
            Creates a proof for the 'keys' in the trie
        Args:
            keys ([bytes]): keys in proof
        """
        # TODO
        pass
    
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

if __name__ == "__main__":
    # test_verkle()
    pass