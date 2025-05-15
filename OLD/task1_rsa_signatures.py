import hashlib
from parameters import KEYS

# Helper functions for RSA
def gcd(a, b):
    while b:
        a, b = b, a % b
    return a

def mod_inverse(e, phi):
    def extended_gcd(a, b):
        if a == 0:
            return b, 0, 1
        gcd, x1, y1 = extended_gcd(b % a, a)
        x = y1 - (b // a) * x1
        y = x1
        return gcd, x, y
    gcd, x, _ = extended_gcd(e, phi)
    if gcd != 1:
        raise ValueError("Modular inverse does not exist")
    return (x % phi + phi) % phi

def generate_rsa_keys(p, q, e):
    n = p * q
    phi = (p - 1) * (q - 1)
    if gcd(e, phi) != 1:
        raise ValueError("e is not coprime with phi(n)")
    d = mod_inverse(e, phi)
    return (e, n), (d, n)

# Hash the record to a number
def hash_record(record):
    md5 = hashlib.md5(record.encode()).hexdigest()
    return int(md5[:16], 16)

# Sign the record with the private key
def sign_record(record, private_key):
    d, n = private_key
    m = hash_record(record)
    return pow(m, d, n)

# Verify the signature with the public key
def verify_signature(record, signature, public_key):
    e, n = public_key
    m = hash_record(record)
    m_prime = pow(signature, e, n)
    return m == m_prime

# Main program for Task 1
def main():
    # Step 1: Generate RSA keys for each inventory
    key_pairs = {}
    for node, params in KEYS.items():
        if "Inventory" in node:  # Only process Inventory A, B, C, D
            public_key, private_key = generate_rsa_keys(params["p"], params["q"], params["e"])
            key_pairs[node] = {"public": public_key, "private": private_key}
            print(f"{node} Public Key: {public_key}")
            print(f"{node} Private Key: {private_key}")

    # Step 2: Define the records to sign
    records = {
        "Inventory A": "ID001,32,12",
        "Inventory B": "ID002,20,14",
        "Inventory C": "ID003,22,16",
        "Inventory D": "ID004,12,18"
    }

    # Step 3: Sign and verify each record
    for signer, record in records.items():
        # Sign the record
        signature = sign_record(record, key_pairs[signer]["private"])
        print(f"\n{signer} signed record '{record}' with signature: {signature}")

        # Other inventories verify the signature
        for verifier in key_pairs:
            if verifier != signer:
                is_valid = verify_signature(record, signature, key_pairs[signer]["public"])
                print(f"{verifier} verified {signer}'s signature: {'Valid' if is_valid else 'Invalid'}")

if __name__ == "__main__":
    main()