# Evaluation of performance of Merkle and Verkle Tree
from random import randint, shuffle
from time import time
import sys

if __name__ == "__main__":
    if len(sys.argv) > 1:
        WIDTH_BITS = int(sys.argv[1])
        NUMBER_INITIAL_KEYS = int(sys.argv[2])
        NUMBER_KEYS_PROOF = int(sys.argv[3])
        NUMBER_ADDED_KEYS = int(sys.argv[4])
        NUMBER_DELETED_KEYS = 0

    # Randomly generate key-value pairs & Evaluate construction time
    kv_pairs = {}
    for i in range(NUMBER_INITIAL_KEYS):
        key = randint(0, 2**256-1).to_bytes(32, "little")
        value = randint(0, 2**256-1).to_bytes(32, "little")
        kv_pairs[key] = value

    time_a = time()
    verkle_root = {"node_type": "inner", "commitment": Point().mul(0)}
    construct_verkle_tree(verkle_root, kv_pairs)#TODO: Implement This
    time_b = time()
    print("Time to construct Verkle Tree: {0:.3f} s".format(time_b - time_a))

    time_a = time()
    construct_merkle_tree(kv_pairs)#TODO: Implement This
    time_b = time()
    print("Time to construct Merkle Tree: {0:.3f} s".format(time_b - time_a))

    # Randomly generate update pairs & Evaluate update time
    update_kv_pairs = {}
    for i in range(NUMBER_ADDED_KEYS):
        key = randint(0, 2 ** 256 - 1).to_bytes(32, "little")
        value = randint(0, 2 ** 256 - 1).to_bytes(32, "little")
        update_kv_pairs[key] = value
        kv_pairs[key] = value

    time_a = time()
    update_verkle_tree(verkle_root, update_kv_pairs)#TODO: Implement This
    time_b = time()
    print("Time to update Verkle Tree: {0:.3f} s".format(time_b - time_a))

    time_a = time()
    update_merkle_tree(update_kv_pairs)#TODO: Implement This
    time_b = time()
    print("Time to update Merkle Tree: {0:.3f} s".format(time_b - time_a))

    # Evaluate Proof Size
    all_keys = list(kv_pairs.keys())
    shuffle(all_keys)

    keys_in_proof = all_keys[:NUMBER_KEYS_PROOF]

    time_a = time()
    verkle_proof = make_verkle_proof(verkle_root, keys_in_proof)
    time_b = time()

    verkle_proof_size = get_proof_size(verkle_proof)

    print("Time to computed proof for Verkle Tree: {0:.3f} s, proof size: {1}".format(time_b - time_a, verkle_proof_size))

    time_a = time()
    merkle_proof = make_merkle_proof(keys_in_proof)#TODO: Implement This
    time_b = time()

    merkle_proof_size = get_merkle_proof_size(merkle_proof)#TODO: Implement This

    print("Time to computed proof for Merkle Tree: {0:.3f} s, proof size: {1}".format(time_b - time_a, merkle_proof_size))
