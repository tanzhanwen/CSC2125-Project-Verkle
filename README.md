CSC2125 Verkle Tree Project
------
![GitHub branch checks state](https://img.shields.io/github/checks-status/zhenfeizhang/bandersnatch/main)
![docs.rs](https://img.shields.io/docsrs/bandersnatch/0.1.1)
![Crates.io (version)](https://img.shields.io/crates/dv/bandersnatch/0.1.1)
![GitHub](https://img.shields.io/github/license/zhenfeizhang/bandersnatch)

This is a CSC2125 course project from UofT, which is aimed at testing the performance of Verkle Tree, comparing it with other models including Sparse Merkle Tree and Merkle Patricia Tree. The data can be stored in either memory or storage(LevelDB).


# Howto

## Required packages

Rust, Cargo, Ethereum, Cpython, LevelDB, Plyvel

```
cargo doc --open
```

## Run evaluations

Step 1: In CSC2125-Project-Verkle/banderpy/, run：

```
make all
```

Step 2: Run the evaluation python file:

```
python3 eval.py
```

## Parameters

In eval.py, the following four parameters in main function define the dataset settings:
    NUMBER_INITIAL_KEYS : Number of initial key value pairs in the tree
    NUMBER_KEYS_PROOF : Number of keys to generate the proofs for
    NUMBER_ADDED_KEYS : Number of keys to be updated
    NUMBER_DELETED_KEYS : Number of keys to be deleted
