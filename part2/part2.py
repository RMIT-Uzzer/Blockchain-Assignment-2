import os
import json
import hashlib
from flask import Flask, render_template, request, session

app = Flask(__name__)
app.secret_key = "secrettt"

def load_parameters(filepath="parameters.txt"):
    section = None
    identities = {}
    randoms = {}
    pkg_keys = {}
    procurement_keys = {}

    with open(filepath, "r") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("[") and line.endswith("]"):
                section = line[1:-1]
                continue
            key, val = line.split(",", 1)
            val = int(val)
            if section == "Identities":
                identities[key] = val
            elif section == "RandomValues":
                randoms[key] = val
            elif section == "PKGKeys":
                pkg_keys[key] = val
            elif section == "ProcurementKeys":
                procurement_keys[key] = val
    return identities, randoms, pkg_keys, procurement_keys

IDENTITIES, RANDOM_VALUES, PKG_KEYS, PROCUREMENT_KEYS = load_parameters("parameters.txt")

# old
'''IDENTITIES = {
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
'''
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

def load_record(inv_key, item_id):
    filename = os.path.join("DATA", f"inventory_{inv_key.lower()}.json")
    if not os.path.exists(filename):
        return None
    with open(filename) as f:
        data = json.load(f)
    return next((item for item in data if item["ID"] == item_id), None)

@app.route("/", methods=["GET", "POST"])
def task3_ui():
    result = {}
    if request.method == "POST":
        item_id = request.form["item_id"].strip()
        session["last_item_id"] = item_id

        pkg_n = PKG_KEYS["p"] * PKG_KEYS["q"]
        partial_sigs, partial_log, messages = [], [], {}
        records = {}

        for key in ["A", "B", "C", "D"]:
            label = f"Inventory {key}"
            record = load_record(key, item_id)

            if not record:
                result["error"] = f"Item ID '{item_id}' not found in {label}"
                return render_template("task3.html", result=result, last_item_id=session.get("last_item_id", ""))

            records[label] = record

        # Compare fields for mismatches
        base_record = next(iter(records.values()))
        mismatches = []

        for label, rec in records.items():
            for field in ["QTY", "Price", "Location"]:
                if rec[field] != base_record[field]:
                    mismatches.append(f"{label} → {field} = {rec[field]} (expected {base_record[field]})")

        ref_vals = [f"Inventory A → {field} = {base_record[field]}" for field in ["QTY", "Price", "Location"]]
        if mismatches:
            result["error"] = ("<div><strong>Reference (Inventory A):</strong><ul>" + "".join(f"<li>{r}</li>" for r in ref_vals) + "</ul></div>" +
                "Mismatch detected in inventory data across nodes:<br><ul>" +
                "".join(f"<li>{m}</li>" for m in mismatches) +
                "</ul>Please ensure QTY, Price, and Location are consistent in all inventories."
            )
            return render_template("task3.html", result=result, last_item_id=session.get("last_item_id", ""))

        for label, record in records.items():
            msg = f"Item: {item_id}, QTY: {record['QTY']}, Location: {record['Location']}"
            messages[label] = msg

            r = RANDOM_VALUES[label]
            identity = IDENTITIES[label]
            sig = generate_partial_signature(identity, r, msg, pkg_n)

            partial_sigs.append(sig)
            partial_log.append(f"{label} ➜ {sig}")

        agg = aggregate_signatures(partial_sigs, pkg_n)
        verified = verify_multisig(agg, messages, IDENTITIES, RANDOM_VALUES, pkg_n)

        po_pub, po_priv = generate_rsa_keys(**PROCUREMENT_KEYS)
        encrypted = encrypt(messages["Inventory A"], po_pub)
        decrypted = decrypt(encrypted, po_priv)

        result = {
            "item_id": item_id,
            "qty": base_record["QTY"],
            "price": base_record["Price"],
            "location": base_record["Location"],
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
