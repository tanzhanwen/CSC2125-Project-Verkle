# Evaluation of performance of Merkle and Verkle Tree
from audioop import add
from random import randint, shuffle
from time import time
from trie import *
import copy
import sys

def test_verkle(values, added_values, width_bits=8):
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
    for key in added_values:
        t.update(key, added_values[key])
        # values[key] = added_values[key]
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


def test_smt(values, added_values):
    print("Start testing performance of Sparse Merkle Tree")

    time_a = time()
    t = SMT(values)
    time_b = time()

    print("Inserted {0} elements in SMT".format(NUMBER_INITIAL_KEYS), file=sys.stderr)
    print("Construct SMT in {0:.3f} s".format(time_b - time_a), file=sys.stderr)

    time_x = time()
    for key in added_values:
        t.update(key, added_values[key])
        # values[key] = added_values[key]
    time_y = time()

    print("Additionally inserted {0} elements in {1:.3f} s".format(NUMBER_ADDED_KEYS, time_y - time_x), file=sys.stderr)

    all_keys = list(values.keys())
    shuffle(all_keys)

    keys_to_delete = all_keys[:NUMBER_DELETED_KEYS]

    time_a = time()
    for key in keys_to_delete:
        t.delete(key)
        # del values[key]
    time_b = time()

    print("Deleted {0} elements in {1:.3f} s".format(NUMBER_DELETED_KEYS, time_b - time_a), file=sys.stderr)

    all_keys = list(values.keys())
    shuffle(all_keys)

    keys_in_proof = all_keys[:NUMBER_KEYS_PROOF]

    time_a = time()
    proof = t.get_proof(keys_in_proof)
    time_b = time()

    proof_size = 0
    for i in range(len(proof)):
        proof_size = proof_size + len(proof[i])
    proof_time = time_b - time_a

    print("Computed proof for {0} keys in {1:.3f} s, size: {2} bytes".format(NUMBER_KEYS_PROOF, proof_time, proof_size), file=sys.stderr)

    time_a = time()
    assert t.verify(keys_in_proof, [t._values[key] for key in keys_in_proof], proof)
    time_b = time()
    check_time = time_b - time_a

    print("Checked proof in {0:.3f} s".format(time_b - time_a), file=sys.stderr)

def test_mpt(values, added_values):
    print("Start testing performance of Sparse Merkle Tree")

    time_a = time()
    t = MPT(values)
    time_b = time()

    print("Inserted {0} elements in SMT".format(NUMBER_INITIAL_KEYS), file=sys.stderr)
    print("Construct SMT in {0:.3f} s".format(time_b - time_a), file=sys.stderr)

    time_x = time()
    for key in added_values:
        t.update(key, added_values[key])
        # values[key] = added_values[key]
    time_y = time()

    print("Additionally inserted {0} elements in {1:.3f} s".format(NUMBER_ADDED_KEYS, time_y - time_x), file=sys.stderr)

    all_keys = list(values.keys())
    shuffle(all_keys)

    keys_to_delete = all_keys[:NUMBER_DELETED_KEYS]

    time_a = time()
    for key in keys_to_delete:
        t.delete(key)
        # del values[key]
    time_b = time()

    print("Deleted {0} elements in {1:.3f} s".format(NUMBER_DELETED_KEYS, time_b - time_a), file=sys.stderr)

if __name__ == "__main__":
    NUMBER_INITIAL_KEYS = 2**10
    NUMBER_KEYS_PROOF = 500
    NUMBER_ADDED_KEYS = 512
    NUMBER_DELETED_KEYS = 512

    initial_values = {}
    for _ in range(NUMBER_INITIAL_KEYS):
        key = randint(0, 2**256-1).to_bytes(32, "little")
        value = randint(0, 2**256-1).to_bytes(32, "little")
        initial_values[key] = value

    added_values = {}
    for i in range(NUMBER_ADDED_KEYS):
        key = randint(0, 2**256-1).to_bytes(32, "little")
        value = randint(0, 2**256-1).to_bytes(32, "little")
        added_values[key] = value

    for i in [2, 4, 6, 8, 10, 12]:
        print(f'width_bits: {i}')
        test_verkle(copy.deepcopy(initial_values), copy.deepcopy(added_values), width_bits = i)
    # test_smt(copy.deepcopy(initial_values), copy.deepcopy(added_values))
    # test_mpt(copy.deepcopy(initial_values), copy.deepcopy(added_values))