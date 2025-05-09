from flask import Flask, request, render_template, jsonify
import os, json

app = Flask(__name__)

@app.context_processor
def inject_request():
    return dict(request=request)


VALID_INVENTORIES = ['A', 'B', 'C', 'D']
DATA_DIR = "data"
os.makedirs(DATA_DIR, exist_ok=True)

def get_inventory_path(inventory):
    return os.path.join(DATA_DIR, f"inventory_{inventory}.json")

# Home page for adding records
@app.route('/')
def index():
    return render_template('index.html')

# Query page
@app.route('/query')
def query():
    return render_template('query.html')

# Submit new record
@app.route('/submit', methods=['POST'])
def submit():
    inventory = request.form['inventory'].upper()
    item_id = request.form['item_id']
    qty = int(request.form['quantity'])
    price = float(request.form['price'])
    location = request.form['location']

    if inventory not in VALID_INVENTORIES:
        return f"Invalid inventory node: {inventory}", 400

    file_path = get_inventory_path(inventory)
    data = []

    if os.path.exists(file_path):
        with open(file_path, 'r') as f:
            data = json.load(f)

    data.append({
        "id": item_id,
        "qty": qty,
        "price": price,
        "location": location
    })

    with open(file_path, 'w') as f:
        json.dump(data, f, indent=4)

    return f"✅ Record added to Inventory {inventory}."

# Search existing records
@app.route('/search', methods=['POST'])
def search():
    inventory = request.form['inventory'].upper()
    item_id = request.form['item_id']

    if inventory not in VALID_INVENTORIES:
        return f"Invalid inventory node: {inventory}", 400

    file_path = get_inventory_path(inventory)

    if not os.path.exists(file_path):
        return f"Inventory {inventory} has no records yet.", 404

    with open(file_path, 'r') as f:
        data = json.load(f)

    results = [item for item in data if item["id"] == item_id]

    return render_template('query.html', results=results, searched=True)

if __name__ == '__main__':
    app.run(debug=True)