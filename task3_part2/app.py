import os
import json
import hashlib
from flask import Flask, render_template, request, session

app = Flask(__name__)
app.secret_key = "super_secret_and_unique_key_123"  # Just a random dev key — replace in prod

# Node configuration
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

# Key pairs for signing and encryption
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

# --- RSA / Signature Utilities ---
def mod_inverse(e, phi):
    def egcd(a, b):
        if a == 0: return b, 0, 1
        g, x1, y1 = egcd(b % a, a)
        return g, y1 - (b // a) * x1, x1
    g, x, _ = egcd(e, phi)
    return x % phi if g == 1 else None

def generate_rsa_keys(p, q, e):
    n = p * q
    phi = (p - 1) * (q - 1)
    d = mod_inverse(e, phi)
    return (e, n), (d, n)

def hash_message(msg, identity=None):
    if identity:
        msg += f"::{identity}"
    return int(hashlib.sha256(msg.encode()).hexdigest(), 16)

def generate_partial_signature(identity, r, message, n):
    m = hash_message(message, identity)
    return (m * pow(identity, r, n)) % n

def aggregate_signatures(sigs, n):
    return sum(sigs) % n

def verify_multisig(agg_sig, messages, ids, randoms, n):
    expected = 0
    for inv in ids:
        m = hash_message(messages[inv], ids[inv])
        expected = (expected + m * pow(ids[inv], randoms[inv], n)) % n
    return agg_sig == expected

def encrypt(message, pub_key):
    e, n = pub_key
    m = int.from_bytes(message.encode(), "big")
    return pow(m, e, n)

def decrypt(ciphertext, priv_key):
    d, n = priv_key
    m = pow(ciphertext, d, n)
    return m.to_bytes((m.bit_length() + 7) // 8, "big").decode()

# Load an inventory record by file and ID
def load_record(inv_key, item_id):
    filename = f"inventory_{inv_key.lower()}.json"
    if not os.path.exists(filename):
        return None
    with open(filename) as f:
        data = json.load(f)
    return next((item for item in data if item["ID"] == item_id), None)

# --- Web Route ---
@app.route("/", methods=["GET", "POST"])
def task3_ui():
    result = {}
    if request.method == "POST":
        item_id = request.form["item_id"].strip()
        session["last_item_id"] = item_id

        pkg_n = PKG_KEYS["p"] * PKG_KEYS["q"]
        partial_sigs, partial_log, messages = [], [], {}

        # Loop through each inventory node
        for key in ["A", "B", "C", "D"]:
            label = f"Inventory {key}"
            record = load_record(key, item_id)

            if not record:
                result["error"] = f"Item ID '{item_id}' not found in {label}"
                return render_template("task3.html", result=result, last_item_id=session.get("last_item_id", ""))

            msg = f"Item: {item_id}, QTY: {record['QTY']}, Location: {record['Location']}"
            messages[label] = msg

            r = RANDOM_VALUES[label]
            identity = IDENTITIES[label]
            sig = generate_partial_signature(identity, r, msg, pkg_n)

            partial_sigs.append(sig)
            partial_log.append(f"{label} ➜ {sig}")

        agg = aggregate_signatures(partial_sigs, pkg_n)
        verified = verify_multisig(agg, messages, IDENTITIES, RANDOM_VALUES, pkg_n)

        # Encrypt with Procurement Officer's public key
        po_pub, po_priv = generate_rsa_keys(**PROCUREMENT_KEYS)
        encrypted = encrypt(messages["Inventory A"], po_pub)
        decrypted = decrypt(encrypted, po_priv)

        result = {
            "item_id": item_id,
            "qty": record["QTY"],
            "price": record["Price"],
            "location": record["Location"],
            "message": messages["Inventory A"],
            "partial_log": partial_log,
            "aggregated": agg,
            "verified": verified,
            "encrypted": encrypted,
            "decrypted": decrypted
        }

    return render_template("task3.html", result=result, last_item_id=session.get("last_item_id", ""))

if __name__ == "__main__":
    app.run(debug=True)
