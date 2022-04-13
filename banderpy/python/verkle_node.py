import imp
from random import randint
import rlp
from ipa_utils import hash
from bandersnatch import Point

# Bandersnatch curve modulus
MODULUS = 13108968793781547619861935127046491459309155893440570251786403306729687672801

def to_list(data: dict):
    return sorted(data.items(), key=lambda x: x[0], reverse=False)

class Node:
    ROOT_PATH = hash(rlp.encode(b''))

    class Leaf:
        def __init__(self, path, data={}):
            self.path = path
            self.data = data
            self.type = "leaf"

        def encode_value_rlp(self):
            return rlp.encode([self.type, to_list(self.data)])

        def get_path_hash(self):
            return self.path

        def get_commitment(self):
            if "commitment" in self.data:
                return Point().deserialize(self.data["commitment"])
            else:
                return None

        def test_print(self):
            print("type: " + self.type + ", path: " + str(self.path) + ", data:" + str(self.data))

        def get_node_info(self):
            return "type: " + self.type + ", path: " + str(self.path) + ", data:" + str(self.data)


    class Inner:
        def __init__(self, path, next_ref={}):
            self.path = path
            self.data = next_ref
            self.type = "inner"

        def encode_value_rlp(self):
            return rlp.encode([self.type, to_list(self.data)])

        def get_path_hash(self):
            return self.path

        def update_next_ref(self, index, path_hash):
            self.data[index] = path_hash

        def test_print(self):
            print("type: " + self.type + ", path: " + str(self.path) + ", data:" + str(self.data))

        def get_node_info(self):
            return "type: " + self.type + ", path: " + str(self.path) + ", data:" + str(self.data)

    def decode(encoded_data):
        """ Decodes node from RLP. """
        decode_str = rlp.decode(encoded_data)

        # assert len(data) == 17 or len(data) == 2   # TODO throw exception
        node_type = decode_str[0].decode()

        data = {}
        for i in range(len(decode_str[1])):
            data[decode_str[1][i][0].decode()] = decode_str[1][i][1]
        if "hash" in data:
            data["hash"] = int.from_bytes(data["hash"], "big") % MODULUS
        return node_type, data

if __name__ == "__main__":
    # key, value: byte32
    key = randint(0, 2**256-1)
    key_byte = key.to_bytes(32, "little")
    print("key: " + str(key) + ", key_byte: " + str(key_byte))

    rlp_encode_key = rlp.encode(key_byte)
    print("rlp_encode_key: " + str(rlp_encode_key))

    rlp_decode_key = rlp.decode(rlp_encode_key)
    print("rlp_decode_key: " + str(rlp_decode_key))

    assert rlp_decode_key == key_byte

    # hash
    hh = hash(rlp.encode([]))
    print(hh)
    
    rlp_encode_key = rlp.encode(hh)
    print("rlp_encode_key: " + str(rlp_encode_key))

    rlp_decode_key = rlp.decode(rlp_encode_key)
    print("rlp_decode_key: " + str(rlp_decode_key))

    print(int.from_bytes(rlp_decode_key, "big") % MODULUS)
    print(int.from_bytes(rlp_decode_key, "little") % MODULUS)
    # commitment
    
    # index: int
    
    # string: "hash", "type", "commitment"

