import hashlib

# --- RSA / CRYPTO UTILITIES ---
def gcd(a, b):
    while b:
        a, b = b, a % b
    return a

def mod_inverse(e, phi):
    def extended_gcd(a, b):
        if a == 0:
            return b, 0, 1
        g, x1, y1 = extended_gcd(b % a, a)
        return g, y1 - (b // a) * x1, x1
    g, x, _ = extended_gcd(e, phi)
    if g != 1:
        raise Exception("No modular inverse")
    return x % phi

def generate_rsa_keys(p, q, e):
    n = p * q
    phi = (p - 1)*(q - 1)
    d = mod_inverse(e, phi)
    return (e, n), (d, n)

def encrypt(message: str, public_key):
    e, n = public_key
    m = int.from_bytes(message.encode(), 'big')
    return pow(m, e, n)

def decrypt(ciphertext: int, private_key):
    d, n = private_key
    m = pow(ciphertext, d, n)
    return m.to_bytes((m.bit_length() + 7) // 8, 'big').decode()

# --- PARAMETERS FROM ASSIGNMENT ---

IDENTITIES = {
    "Inventory A": 126,
    "Inventory B": 127,
    "Inventory C": 128,
    "Inventory D": 129
}
RANDOM_VALUES = {
    "Inventory A": 621,
    "Inventory B": 721,
    "Inventory C": 821,
    "Inventory D": 921
}

PKG_KEYS = {
    "p": 1004162036461488639338597000466705179253226703,
    "q": 950133741151267522116252385927940618264103623,
    "e": 973028207197278907211
}
PROCUREMENT_KEYS = {
    "p": 1080954735722463992988394149602856332100628417,
    "q": 1158106283320086444890911863299879973542293243,
    "e": 106506253943651610547613
}

# --- HARN MULTISIGNATURE LOGIC ---

def hash_message(msg, identity=None):
    if identity is not None:
        msg += f"::{identity}"
    return int(hashlib.sha256(msg.encode()).hexdigest(), 16)

def generate_partial_signature(identity, r, message, n):
    m = hash_message(message, identity)
    return (m * pow(identity, r, n)) % n


def aggregate_signatures(signatures, n):
    return sum(signatures) % n

def verify_multisig(aggregated_sig, message, identities, randoms, n):
    expected = 0
    for i in range(len(identities)):
        m_i = hash_message(message, identities[i])
        partial_expected = (m_i * pow(identities[i], randoms[i], n)) % n
        expected = (expected + partial_expected) % n
    return aggregated_sig == expected


# --- DEMO FUNCTION THAT SHOWS FULL FLOW ---
def simulate_task3(item_id='002', qty=20):
    print(f"\n[1] Procurement Officer queries for Item {item_id} (QTY {qty})")

    message = f"Item: {item_id}, QTY: {qty}"
    print(f"[2] PKG forwards query to all inventories\n[3] Each inventory signs: '{message}'")

    # Fix: Use explicit modulus
    pkg_n = PKG_KEYS["p"] * PKG_KEYS["q"]

    partial_sigs = []
    for name in IDENTITIES:
        r = RANDOM_VALUES[name]
        identity = IDENTITIES[name]
        sig = generate_partial_signature(identity, r, message, pkg_n)
        print(f" - {name} generated partial sig: {sig}")
        partial_sigs.append(sig)

    aggregated_sig = aggregate_signatures(partial_sigs, pkg_n)
    print(f"[4] PKG aggregates signature: {aggregated_sig}")

    is_valid = verify_multisig(aggregated_sig, message, list(IDENTITIES.values()), list(RANDOM_VALUES.values()), pkg_n)
    print(f"[5] PKG verifies aggregated signature: {'✅ VALID' if is_valid else '❌ INVALID'}")

    print(f"[6] PKG encrypts result for Procurement Officer...")

    po_pub, po_priv = generate_rsa_keys(PROCUREMENT_KEYS["p"], PROCUREMENT_KEYS["q"], PROCUREMENT_KEYS["e"])
    encrypted = encrypt(message, po_pub)
    print(f"[7] Encrypted ciphertext: {encrypted}")

    print(f"[8] Procurement Officer decrypts...")
    decrypted = decrypt(encrypted, po_priv)
    print(f"[9] Decrypted result: {decrypted}")

    print(f"[10] Final signature validation: {'✅ VALID' if is_valid and decrypted == message else '❌ FAILED'}")

if __name__ == "__main__":
    simulate_task3()
