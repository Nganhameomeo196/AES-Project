
"""Educational biclique-inspired demonstration.

Shows a complete bipartite graph and shared computation.
This is NOT a real biclique cryptanalysis attack on AES.
"""

from itertools import product


def build_biclique(left_nodes, right_nodes):
    """Connect every left node to every right node."""
    return list(product(left_nodes, right_nodes))


def toy_encrypt(plaintext, key):
    """Simple 8-bit toy cipher, NOT AES."""
    return ((plaintext ^ key) + ((key << 1) & 0xFF)) & 0xFF


def main():
    print("=== BICLIQUE CRYPTANALYSIS DEMO ===")

    left_nodes = ["L0", "L1", "L2", "L3"]
    right_nodes = ["R0", "R1", "R2", "R3"]

    edges = build_biclique(left_nodes, right_nodes)

    print("\n1. Complete bipartite graph:")
    for left, right in edges:
        print(f"{left} <--> {right}")

    print("Left nodes :", len(left_nodes))
    print("Right nodes:", len(right_nodes))
    print("Total edges:", len(edges))

    print("\n2. Toy key search:")
    plaintext = 0x53
    secret_key = 0xA7
    target = toy_encrypt(plaintext, secret_key)

    candidates = []

    for key in range(256):
        if toy_encrypt(plaintext, key) == target:
            candidates.append(key)

    print("Plaintext         :", hex(plaintext))
    print("Target ciphertext :", hex(target))
    print("Matching keys     :", [hex(k) for k in candidates])
    print("Secret key in matches:", secret_key in candidates)

    print("\nConclusion:")
    print("The graph illustrates the biclique structure.")
    print("The toy search illustrates key candidates.")
    print("This is NOT an AES biclique attack.")


if __name__ == "__main__":
    main()
