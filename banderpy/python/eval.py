# Evaluation of performance of Merkle and Verkle Tree
from random import randint, shuffle
from time import time
from trie import *
import sys

def test_verkle(width_bits=8, initial_keys=2**10, keys_proof=500):
    values = {}
    NUMBER_INITIAL_KEYS = keys_proof
    NUMBER_KEYS_PROOF = initial_keys

    for _ in range(NUMBER_INITIAL_KEYS):
        key = randint(0, 2**256-1).to_bytes(32, "little")
        value = randint(0, 2**256-1).to_bytes(32, "little")
        values[key] = value
        
    time_a = time()
    t = VerkleTrie(values, width_bits)
    time_b = time()

    average_depth = get_average_depth(t.root())
    print("Inserted {0} elements for an average depth of {1:.3f}".format(NUMBER_INITIAL_KEYS, average_depth), file=sys.stderr)
    print("Computed verkle root in {0:.3f} s".format(time_b - time_a), file=sys.stderr)
    
    time_a = time()
    check_valid_tree(t.root())
    time_b = time()
    
    print("[Checked tree valid: {0:.3f} s]".format(time_b - time_a), file=sys.stderr)

    time_x = time()
    for i in range(NUMBER_ADDED_KEYS):
        key = randint(0, 2**256-1).to_bytes(32, "little")
        value = randint(0, 2**256-1).to_bytes(32, "little")
        t.update(key, value)
        # values[key] = value
    time_y = time()
        
    print("Additionally inserted {0} elements in {1:.3f} s".format(NUMBER_ADDED_KEYS, time_y - time_x), file=sys.stderr)
    print("Keys in tree now: {0}, average depth: {1:.3f}".format(get_total_depth(t.root())[1], get_average_depth(t.root())), file=sys.stderr)

    time_a = time()
    check_valid_tree(t.root())
    time_b = time()
    
    print("[Checked tree valid: {0:.3f} s]".format(time_b - time_a), file=sys.stderr)

    all_keys = list(values.keys())
    shuffle(all_keys)

    keys_to_delete = all_keys[:NUMBER_DELETED_KEYS]

    time_a = time()
    for key in keys_to_delete:
        t.delete(key)
        # del values[key]
    time_b = time()
    
    print("Deleted {0} elements in {1:.3f} s".format(NUMBER_DELETED_KEYS, time_b - time_a), file=sys.stderr)
    print("Keys in tree now: {0}, average depth: {1:.3f}".format(get_total_depth(t.root())[1], get_average_depth(t.root())), file=sys.stderr)


    time_a = time()
    check_valid_tree(t.root())
    time_b = time()
    
    print("[Checked tree valid: {0:.3f} s]".format(time_b - time_a), file=sys.stderr)

    all_keys = list(values.keys())
    shuffle(all_keys)

    keys_in_proof = all_keys[:NUMBER_KEYS_PROOF]

    time_a = time()
    proof = t.get_proof(keys_in_proof)
    time_b = time()
    
    proof_size = get_proof_size(proof)
    proof_time = time_b - time_a
    
    print("Computed proof for {0} keys (size = {1} bytes) in {2:.3f} s".format(NUMBER_KEYS_PROOF, proof_size, time_b - time_a), file=sys.stderr)

    time_a = time()
    assert t.verify(keys_in_proof, [t._values[key] for key in keys_in_proof], proof)
    time_b = time()
    check_time = time_b - time_a

    print("Checked proof in {0:.3f} s".format(time_b - time_a), file=sys.stderr)

    print("{0}\t{1}\t{2}\t{3}\t{4}\t{5}\t{6}\t{7}".format(WIDTH_BITS, WIDTH, NUMBER_INITIAL_KEYS, NUMBER_KEYS_PROOF, average_depth, proof_size, proof_time, check_time))

def test_mpt():
    # TODO
    pass

if __name__ == "__main__":
    test_verkle()