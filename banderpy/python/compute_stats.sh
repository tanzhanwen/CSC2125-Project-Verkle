echo -e "WIDTH_BITS\tWIDTH\tNUMBER_INITIAL_KEYS\tNUMBER_KEYS_PROOF\taverage_depth\tproof_size\tproof_time\tcheck_time" > stats.txt

python3 verkle_trie.py 5 1024 500 >> stats.txt
python3 verkle_trie.py 6 1024 500 >> stats.txt
python3 verkle_trie.py 7 1024 500 >> stats.txt
python3 verkle_trie.py 8 1024 500 >> stats.txt
python3 verkle_trie.py 9 1024 500 >> stats.txt
python3 verkle_trie.py 10 1024 500 >> stats.txt
python3 verkle_trie.py 11 1024 500 >> stats.txt
python3 verkle_trie.py 12 1024 500 >> stats.txt
python3 verkle_trie.py 13 1024 500 >> stats.txt
python3 verkle_trie.py 14 1024 500 >> stats.txt
python3 verkle_trie.py 15 1024 500 >> stats.txt
python3 verkle_trie.py 16 1024 500 >> stats.txt
