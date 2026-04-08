import random

# --- Algorithm Constants ---
BLOCK_SIZE = 8
NUM_ROUNDS = 4
PAD_CHAR = '~'

# --- Character Set Definition ---
# Defines all characters the algorithm can encrypt/decrypt.
CHARACTER_SET = list(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "0123456789"
    " !\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~"
)
CHAR_SET_SIZE = len(CHARACTER_SET)

# --- Character to Index Mappings ---

# These dictionaries are crucial for the new key mixing logic.
CHAR_TO_INDEX = {char: i for i, char in enumerate(CHARACTER_SET)}
INDEX_TO_CHAR = {i: char for i, char in enumerate(CHARACTER_SET)}

# --- S-Box (Substitution Box) Definition ---
def generate_s_box(char_set):
    """
    Generates a Substitution Box (S-Box) and its inverse.
    """
    shuffled_set = char_set[:]
    random.seed(42) # Use a fixed seed for consistent S-Box generation
    random.shuffle(shuffled_set)

    s_box = {char_set[i]: shuffled_set[i] for i in range(len(char_set))}
    inverse_s_box = {v: k for k, v in s_box.items()}
    return s_box, inverse_s_box

S_BOX, INVERSE_S_BOX = generate_s_box(CHARACTER_SET)

# --- P-Box (Permutation Box) Definition ---
P_BOX = [4, 7, 1, 6, 3, 0, 5, 2]

def generate_inverse_p_box(p_box):
    """Generates the inverse of a P-Box."""
    inverse_p_box = [0] * len(p_box)
    for i, j in enumerate(p_box):
        inverse_p_box[j] = i
    return inverse_p_box

INVERSE_P_BOX = generate_inverse_p_box(P_BOX)


# --- Core Cryptographic Functions ---

def generate_round_keys(master_key, num_rounds):
    """
    Generates round keys from a master key using a cyclic left shift.
    """
    if len(master_key) != BLOCK_SIZE:
        raise ValueError(f"Master key must be {BLOCK_SIZE} characters long.")

    keys = [master_key]
    current_key = master_key
    for _ in range(num_rounds):
        current_key = current_key[1:] + current_key[0] # Cyclic left shift
        keys.append(current_key)
    return keys

def mix_with_key(block, key):
    """
    Mixes a block with a key using modular addition. (Replaces XOR for encryption)
    """
    mixed_block = ""
    for i in range(len(block)):
        block_char_idx = CHAR_TO_INDEX.get(block[i])
        key_char_idx = CHAR_TO_INDEX.get(key[i])
        if block_char_idx is None or key_char_idx is None:
             raise ValueError(f"Character not in character set: {block[i]} or {key[i]}")

        new_idx = (block_char_idx + key_char_idx) % CHAR_SET_SIZE
        mixed_block += INDEX_TO_CHAR[new_idx]
    return mixed_block

def unmix_with_key(block, key):
    """
    Unmixes a block from a key using modular subtraction. (Replaces XOR for decryption)
    """
    unmixed_block = ""
    for i in range(len(block)):
        block_char_idx = CHAR_TO_INDEX.get(block[i])
        key_char_idx = CHAR_TO_INDEX.get(key[i])
        if block_char_idx is None or key_char_idx is None:
            raise ValueError(f"Character not in character set: {block[i]} or {key[i]}")

        # Add CHAR_SET_SIZE to handle negative results from subtraction
        new_idx = (block_char_idx - key_char_idx + CHAR_SET_SIZE) % CHAR_SET_SIZE
        unmixed_block += INDEX_TO_CHAR[new_idx]
    return unmixed_block

def substitute(input_block, s_box):
    """Applies the S-Box substitution to a block of text."""
    return ''.join(s_box.get(char, char) for char in input_block)

def permute(input_block, p_box):
    """Applies the P-Box permutation to a block of text."""
    output_block_list = [''] * BLOCK_SIZE
    for i in range(BLOCK_SIZE):
        output_block_list[p_box[i]] = input_block[i]
    return ''.join(output_block_list)

def pad(text):
    """Pads the text to ensure its length is a multiple of BLOCK_SIZE."""
    padding_needed = BLOCK_SIZE - (len(text) % BLOCK_SIZE)
    if padding_needed == BLOCK_SIZE:
        return text
    return text + PAD_CHAR * padding_needed

def unpad(text):
    """Removes padding from the decrypted text."""
    return text.rstrip(PAD_CHAR)

# --- Main Encryption and Decryption Logic ---

def encrypt(plaintext, master_key):
    """
    Encrypts the given plaintext using the ShiftBlock algorithm.
    """
    print("="*25 + " ENCRYPTION PROCESS " + "="*25)
    padded_plaintext = pad(plaintext)
    round_keys = generate_round_keys(master_key, NUM_ROUNDS)

    print(f"\n[1] Original Plaintext : '{plaintext}'")
    print(f"[2] Padded Plaintext   : '{padded_plaintext}' ({len(padded_plaintext)} bytes)")
    print("\n[3] Generated Round Keys:")
    for i, key in enumerate(round_keys):
        print(f"    Round Key {i}: '{key}'")

    ciphertext = ""
    blocks = [padded_plaintext[i:i+BLOCK_SIZE] for i in range(0, len(padded_plaintext), BLOCK_SIZE)]
    for i, block in enumerate(blocks):
        print(f"\n--- Processing Block {i+1}: '{block}' ---")
        current_data = block

        print("\n  [Initial Step] Key Mixing")
        current_data = mix_with_key(current_data, round_keys[0])
        print(f"    - Input  : '{block}'\n    - Mix Key: '{round_keys[0]}'\n    - Output : '{current_data}'")

        for r in range(NUM_ROUNDS):
            print(f"\n  [Round {r+1}]")
            substituted_data = substitute(current_data, S_BOX)
            print(f"    - (a) Substitution : '{current_data}' -> '{substituted_data}'")
            permuted_data = permute(substituted_data, P_BOX)
            print(f"    - (b) Permutation  : '{substituted_data}' -> '{permuted_data}'")
            current_data = mix_with_key(permuted_data, round_keys[r+1])
            print(f"    - (c) Key Mixing   : '{permuted_data}'\n      - Mix Key      : '{round_keys[r+1]}'\n      - Round Output : '{current_data}'")

        ciphertext += current_data
        print(f"--- Finished Block {i+1}, Current Ciphertext: '{ciphertext}' ---")

    print("\n" + "="*24 + " ENCRYPTION COMPLETE " + "="*25)
    return ciphertext

def decrypt(ciphertext, master_key):
    """
    Decrypts the given ciphertext using the ShiftBlock algorithm.
    """
    print("\n" + "="*25 + " DECRYPTION PROCESS " + "="*25)
    round_keys = generate_round_keys(master_key, NUM_ROUNDS)

    print("\n[1] Generated Round Keys (will be used in reverse order):")
    for i, key in enumerate(round_keys):
        print(f"    Round Key {i}: '{key}'")

    decrypted_padded_text = ""
    blocks = [ciphertext[i:i+BLOCK_SIZE] for i in range(0, len(ciphertext), BLOCK_SIZE)]
    for i, block in enumerate(blocks):
        print(f"\n--- Processing Block {i+1}: '{block}' ---")
        current_data = block

        for r in range(NUM_ROUNDS, 0, -1):
            print(f"\n  [Round {r}] (Reversed)")
            mixed_data = unmix_with_key(current_data, round_keys[r])
            print(f"    - (a) Key Un-Mixing: '{current_data}'\n      - Mix Key      : '{round_keys[r]}'\n      - Output       : '{mixed_data}'")
            unpermuted_data = permute(mixed_data, INVERSE_P_BOX)
            print(f"    - (b) Inv Permute  : '{mixed_data}' -> '{unpermuted_data}'")
            current_data = substitute(unpermuted_data, INVERSE_S_BOX)
            print(f"    - (c) Inv Substitute : '{unpermuted_data}' -> '{current_data}'")

        print("\n  [Final Step] Key Un-Mixing")
        current_data = unmix_with_key(current_data, round_keys[0])
        print(f"    - Input  : '{decrypted_padded_text[-BLOCK_SIZE:] if decrypted_padded_text else 'N/A'}'\n    - Mix Key: '{round_keys[0]}'\n    - Output : '{current_data}'")

        decrypted_padded_text += current_data
        print(f"--- Finished Block {i+1}, Current Decrypted Text: '{decrypted_padded_text}' ---")

    decrypted_text = unpad(decrypted_padded_text)
    print(f"\n[3] Decrypted (Padded) : '{decrypted_padded_text}'")
    print(f"[4] Decrypted (Unpadded) : '{decrypted_text}'")

    print("\n" + "="*24 + " DECRYPTION COMPLETE " + "="*25)
    return decrypted_text


# --- Main Execution ---
if __name__ == "__main__":
    PLAINTEXT_TO_TEST = "samiya is here!"
    MASTER_KEY = "mysecret" # Must be 8 characters

    final_ciphertext = encrypt(PLAINTEXT_TO_TEST, MASTER_KEY)
    print(f"\n\nFinal Plaintext : '{PLAINTEXT_TO_TEST}'")
    print(f"Final Ciphertext: '{final_ciphertext}'")

    recovered_plaintext = decrypt(final_ciphertext, MASTER_KEY)
    print(f"\n\nRecovered Plaintext: '{recovered_plaintext}'")

    print("\n--- VERIFICATION ---")
    if PLAINTEXT_TO_TEST == recovered_plaintext:
        print("SUCCESS: The recovered plaintext matches the original plaintext.")
    else:
        print("FAILURE: The recovered plaintext does NOT match the original.")

