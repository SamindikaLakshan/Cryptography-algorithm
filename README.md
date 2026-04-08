# Cryptography-algorithm
3rd year mini project in advanced nework.

# ShiftBlock-8: A Python-Based Block Cipher Implementation

ShiftBlock-8 is a custom 8-byte block cipher designed to demonstrate the core principles of symmetric-key cryptography, specifically the Substitution-Permutation Network (SPN) architecture. This project showcases the implementation of confusion and diffusion through multiple rounds of mathematical transformation.

# 🚀 Features
Block-Based Encryption: Processes data in fixed 8-character (64-bit) blocks.

Multi-Round SPN Architecture: Utilizes 4 rounds of transformation to ensure strong data obfuscation.

Custom S-Box & P-Box: * Substitution (S-Box): Provides non-linear mapping to create confusion.

Permutation (P-Box): Reorders bits/characters to provide diffusion.

Dynamic Key Scheduling: Generates unique round keys from a single master key using cyclic left shifts.

Modular Arithmetic Mixing: Replaces standard XOR with modular addition/subtraction over a custom character set, allowing for the encryption of human-readable strings including symbols and numbers.

# 🛠️ How it Works
The algorithm follows a rigorous cryptographic pipeline for every block:

Padding: Ensures the input text is a multiple of the 8-byte block size using a ~ character.

Key Mixing: The block is mixed with the round key using modular addition.

Substitution: Each character is replaced based on a pre-generated S-Box.

Permutation: Characters are shuffled according to a fixed P-Box pattern.

Iteration: This process repeats for 4 rounds, with a final key mixing step to finalize the ciphertext.

# 💻 Tech Stack
Language: Python 3.x

Libraries: random (for S-Box generation)

# 📊 Cryptographic Strength (Educational)
While this algorithm is designed for educational purposes and personal projects, it incorporates several professional concepts:

Reversibility: Includes a matching decryption logic that perfectly reverses the P-Box and S-Box transformations.

Handling Character Sets: Supports a wide range of characters (Alphanumeric + Special Characters).

Traceability: The code includes detailed print-outs of the transformation at every round, making it an excellent tool for learning how block ciphers manipulate data.
