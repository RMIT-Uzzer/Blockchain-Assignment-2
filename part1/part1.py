
from flask import Flask, render_template, request
import hashlib
import json
import os

app = Flask(__name__)

def mod_inverse(e, phi):
    def egcd(a, b):
        if a == 0:
            return b, 0, 1
        g, x1, y1 = egcd(b % a, a)
        return g, y1 - (b // a) * x1, x1
    g, x, _ = egcd(e, phi)
    return x % phi

def generate_rsa_keys(p, q, e):
    n = p * q
    phi = (p - 1)*(q - 1)
    d = mod_inverse(e, phi)
    return (e, n), (d, n), n, phi, d

def hash_message(msg):
    return int(hashlib.sha256(msg.encode()).hexdigest(), 16)

def sign_message(msg, private_key):
    d, n = private_key
    m = hash_message(msg)
    return pow(m, d, n)

def verify_signature(msg, sig, public_key):
    e, n = public_key
    m = hash_message(msg)
    return pow(sig, e, n) == m

inventory_keys = {
    "Inventory A": {
        "p": 1210613765735147311106936311866593978079938707,
        "q": 1247842850282035753615951347964437248190231863,
        "e": 815459040813953176289801
    },
    "Inventory B": {
        "p": 787435686772982288169641922308628444877260947,
        "q": 1325305233886096053310340418467385397239375379,
        "e": 692450682143089563609787
    },
    "Inventory C": {
        "p": 1014247300991039444864201518275018240361205111,
        "q": 904030450302158058469475048755214591704639633,
        "e": 1158749422015035388438057
    },
    "Inventory D": {
        "p": 1287737200891425621338551020762858710281638317,
        "q": 1330909125725073469794953234151525201084537607,
        "e": 33981230465225879849295979
    }
}

@app.route("/", methods=["GET", "POST"])
def index():
    result = {}
    if request.method == "POST":
        node = request.form["node"]
        item_id = request.form["item_id"]
        qty = int(request.form["qty"])
        price = int(request.form["price"])
        msg = f"Item: {item_id} | QTY: {qty} | Price: {price}"

        keys = inventory_keys[node]
        pub_key, priv_key, n, phi, d = generate_rsa_keys(keys["p"], keys["q"], keys["e"])
        signature = sign_message(msg, priv_key)

        verifications = {}
        consensus_count = 0
        for other_node in inventory_keys:
            is_valid = verify_signature(msg, signature, pub_key)
            verifications[other_node] = "Accepted" if is_valid else "Rejected"
            if is_valid:
                consensus_count += 1

        consensus_success = consensus_count >= 3
        result = {
            "node": node,
            "message": msg,
            "signature": signature,
            "verifications": verifications,
            "consensus": "Consensus Achieved" if consensus_success else "Consensus Failed",
            "n": n,
            "phi": phi,
            "d": d
        }

        if consensus_success:
            location = node[-1]
            new_record = {"ID": item_id, "QTY": qty, "Price": price, "Location": location}
            for inventory_file in [
                os.path.join("DATA", "inventory_a.json"),
                os.path.join("DATA", "inventory_b.json"),
                os.path.join("DATA", "inventory_c.json"),
                os.path.join("DATA", "inventory_d.json")
            ]:
                if os.path.exists(inventory_file):
                    with open(inventory_file, "r") as f:
                        try:
                            data = json.load(f)
                        except:
                            data = []
                else:
                    data = []
                data.append(new_record)
                with open(inventory_file, "w") as f:
                    json.dump(data, f, indent=2)

    return render_template("part2.html", result=result, nodes=list(inventory_keys.keys()))

if __name__ == "__main__":
    app.run(debug=True)
