import hashlib
import json
import os
from parameters import KEYS

# Helper functions for RSA (same as Part 1)
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

def hash_record(record):
    md5 = hashlib.md5(record.encode()).hexdigest()
    return int(md5[:16], 16)

def sign_record(record, private_key):
    d, n = private_key
    m = hash_record(record)
    return pow(m, d, n)

def verify_signature(record, signature, public_key):
    e, n = public_key
    m = hash_record(record)
    m_prime = pow(signature, e, n)
    return m == m_prime

# Initialize inventory databases (JSON files)
def initialize_databases():
    initial_data = [
        {"ID": "001", "QTY": 32, "Price": 12, "Location": "D"},
        {"ID": "002", "QTY": 20, "Price": 14, "Location": "C"},
        {"ID": "003", "QTY": 22, "Price": 16, "Location": "B"},
        {"ID": "004", "QTY": 12, "Price": 18, "Location": "A"}
    ]
    for node in ["Inventory A", "Inventory B", "Inventory C", "Inventory D"]:
        filename = f"{node.replace(' ', '_').lower()}.json"
        if not os.path.exists(filename):
            with open(filename, 'w') as f:
                json.dump(initial_data, f, indent=4)

# Load inventory database
def load_inventory(node):
    filename = f"{node.replace(' ', '_').lower()}.json"
    with open(filename, 'r') as f:
        return json.load(f)

# Save record to inventory database
def save_to_inventory(node, record, proposer):
    filename = f"{node.replace(' ', '_').lower()}.json"
    data = load_inventory(node)
    item_id, qty, price = record.split(',')
    for entry in data:
        if entry["ID"] == item_id:
            entry["QTY"] = int(qty)
            entry["Price"] = int(price)
            break
    else:
        proposer_location = proposer.split()[1]  # e.g., "A" from "Inventory A"
        data.append({
            "ID": item_id,
            "QTY": int(qty),
            "Price": int(price),
            "Location": proposer_location
        })
    with open(filename, 'w') as f:
        json.dump(data, f, indent=4)

# PoA Consensus Protocol
def run_poa_consensus(proposer, record, signature, key_pairs, nodes):
    print(f"\nRunning PoA consensus for {proposer}'s record '{record}'...")
    valid_count = 0
    print(f"{proposer} (authority) proposes the record.")
    valid_count += 1  # Proposer gets 1 vote
    for verifier in [n for n in nodes if n != proposer]:
        is_valid = verify_signature(record, signature, key_pairs[proposer]["public"])
        print(f"{verifier} verified {proposer}'s signature: {'Valid' if is_valid else 'Invalid'}")
        if is_valid:
            valid_count += 1
    required_votes = 3
    if valid_count >= required_votes:
        print(f"Consensus reached with {valid_count}/{len(nodes)} votes!")
        return True
    else:
        print(f"Consensus failed with {valid_count}/{len(nodes)} votes.")
        return False

# Main program for Task 2
def main():
    # Initialize the databases (create JSON files)
    initialize_databases()

    # Generate RSA keys (same as Part 1)
    key_pairs = {}
    for node, params in KEYS.items():
        if "Inventory" in node:
            public_key, private_key = generate_rsa_keys(params["p"], params["q"], params["e"])
            key_pairs[node] = {"public": public_key, "private": private_key}
            print(f"{node} Public Key: {public_key}")
            print(f"{node} Private Key: {private_key}")

    # New records to add
def main():
    # Initialize the databases (create JSON files)
    initialize_databases()

    # Generate RSA keys (same as Part 1)
    key_pairs = {}
    for node, params in KEYS.items():
        if "Inventory" in node:
            public_key, private_key = generate_rsa_keys(params["p"], params["q"], params["e"])
            key_pairs[node] = {"public": public_key, "private": private_key}
            print(f"{node} Public Key: {public_key}")
            print(f"{node} Private Key: {private_key}")

    # New records to add (only the new record for Inventory C)
    new_records = {
        "Inventory C": "ID005,300,22",
        "Inventory D": "ID006,50,25"
    }

    # Run consensus for each new record
    for proposer, record in new_records.items():
        # Adjust proposer name in case we have multiple records from the same inventory
        actual_proposer = proposer.split(" - ")[0]  # In case we use "Inventory C - IDxxx" format
        signature = sign_record(record, key_pairs[actual_proposer]["private"])
        print(f"\n{actual_proposer} signed record '{record}' with signature: {signature}")
        if run_poa_consensus(actual_proposer, record, signature, key_pairs, ["Inventory A", "Inventory B", "Inventory C", "Inventory D"]):
            for node in ["Inventory A", "Inventory B", "Inventory C", "Inventory D"]:
                save_to_inventory(node, record, actual_proposer)
                print(f"Stored record '{record}' in {node}'s database.")

    # Show the updated databases
    print("\nUpdated Inventory Databases:")
    for node in ["Inventory A", "Inventory B", "Inventory C", "Inventory D"]:
        print(f"\n{node}:")
        data = load_inventory(node)
        for entry in data:
            print(f"ID: {entry['ID']}, QTY: {entry['QTY']}, Price: {entry['Price']}, Location: {entry['Location']}")

if __name__ == "__main__":
    main()
    input("Press Enter to exit...")