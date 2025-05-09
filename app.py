from flask import Flask, request, render_template
import os

app = Flask(__name__)

DATA_DIR = "data"
os.makedirs(DATA_DIR, exist_ok=True)

# Page to add new records
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/submit', methods=['POST'])
def submit_record():
    data = request.form
    inventory = data['inventory'].upper()
    item_id = data['item_id']
    quantity = data['quantity']
    price = data['price']

    record_line = f"{inventory},{item_id},{quantity},{price}\n"
    file_path = os.path.join(DATA_DIR, f"inventory_{inventory}.txt")

    with open(file_path, "a") as f:
        f.write(record_line)

    return f"✅ Record submitted and saved to inventory_{inventory}.txt"

# Page to query records
@app.route('/query')
def query_page():
    return render_template('query.html')

@app.route('/search', methods=['POST'])
def search_record():
    inventory = request.form['inventory'].upper()
    item_id = request.form['item_id']
    file_path = os.path.join(DATA_DIR, f"inventory_{inventory}.txt")

    results = []
    if os.path.exists(file_path):
        with open(file_path, 'r') as f:
            for line in f:
                inv, iid, qty, price = line.strip().split(',')
                if iid == item_id:
                    results.append((inv, iid, qty, price))

    return render_template('query.html', results=results, searched=True)
    
if __name__ == '__main__':
    app.run(debug=True)
