# Evaluation of performance of Merkle and Verkle Tree
from audioop import add
from random import randint, shuffle
from time import time
from trie import *
import plyvel
import copy
import sys

def test_verkle(values, added_values, width_bits=8, db=None):
    time_a = time()
    t = Verkle(values, width_bits, db)
    time_b = time()

    average_depth = t._verkle.get_average_depth()
    print("Inserted {0} elements for an average depth of {1:.3f}".format(NUMBER_INITIAL_KEYS, average_depth), file=sys.stderr)
    print("Computed verkle root in {0:.3f} s".format(time_b - time_a), file=sys.stderr)
    
    time_a = time()
    t.check()
    time_b = time()
    
    print("[Checked tree valid: {0:.3f} s]".format(time_b - time_a), file=sys.stderr)

    time_x = time()
    for key in added_values:
        t.update(key, added_values[key])
        # values[key] = added_values[key]
    time_y = time()
        
    print("Additionally inserted {0} elements in {1:.3f} s".format(NUMBER_ADDED_KEYS, time_y - time_x), file=sys.stderr)
    print("Keys in tree now: {0}, average depth: {1:.3f}".format(t._verkle.get_total_depth(t._verkle.root())[1], t._verkle.get_average_depth()), file=sys.stderr)

    time_a = time()
    t.check()
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
    print("Keys in tree now: {0}, average depth: {1:.3f}".format(t._verkle.get_total_depth(t._verkle.root())[1], t._verkle.get_average_depth()), file=sys.stderr)


    time_a = time()
    t.check()
    time_b = time()
    
    print("[Checked tree valid: {0:.3f} s]".format(time_b - time_a), file=sys.stderr)

    all_keys = list(values.keys())
    shuffle(all_keys)

    keys_in_proof = all_keys[:NUMBER_KEYS_PROOF]

    time_a = time()
    proof = t.get_proof(keys_in_proof)
    time_b = time()
    
    proof_size = t._verkle.get_proof_size(proof)
    proof_time = time_b - time_a
    
    print("Computed proof for {0} keys (size = {1} bytes) in {2:.3f} s".format(NUMBER_KEYS_PROOF, proof_size, time_b - time_a), file=sys.stderr)

    time_a = time()
    assert t.verify(keys_in_proof, [t._values[key] for key in keys_in_proof], proof)
    time_b = time()
    check_time = time_b - time_a

    print("Checked proof in {0:.3f} s".format(time_b - time_a), file=sys.stderr)

    print("{0}\t{1}\t{2}\t{3}\t{4}\t{5}\t{6}\t{7}".format(t._verkle.WIDTH_BITS, t._verkle.WIDTH, NUMBER_INITIAL_KEYS, NUMBER_KEYS_PROOF, average_depth, proof_size, proof_time, check_time))


def test_smt(values, added_values, db=None):
    print("Start testing performance of Sparse Merkle Tree")

    time_a = time()
    t = SMT(values, db)
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

def test_mpt(values, added_values, db={}):
    print("Start testing performance of Sparse Merkle Tree")

    time_a = time()
    t = MPT(values, db)
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

def close_database():
    plyvel.destroy_db('/tmp/MPT/')
    plyvel.destroy_db('/tmp/SMT/')
    plyvel.destroy_db('/tmp/Verkle/')

if __name__ == "__main__":
    NUMBER_INITIAL_KEYS = 2**12
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

    # clean database
    close_database()

    # create leveldb for each trie
    db_verkle = plyvel.DB('/tmp/Verkle/', create_if_missing=True) # TODO
    db_smt = plyvel.DB('/tmp/SMT/', create_if_missing=True) 
    db_mpt = plyvel.DB('/tmp/MPT/', create_if_missing=True)

    test_verkle(copy.deepcopy(initial_values), copy.deepcopy(added_values), db=db_verkle)
    test_smt(copy.deepcopy(initial_values), copy.deepcopy(added_values), db_smt)
    test_mpt(copy.deepcopy(initial_values), copy.deepcopy(added_values), db=db_mpt)

    del db_verkle
    del db_smt
    del db_mpt

    close_database()
