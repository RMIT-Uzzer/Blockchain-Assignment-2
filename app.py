from flask import Flask, request, render_template
import os

app = Flask(__name__)

DATA_DIR = "data"

# Ensure data directory exists
os.makedirs(DATA_DIR, exist_ok=True)

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/submit', methods=['POST'])
def submit_record():
    data = request.form
    inventory = data['inventory'].upper()  # Ensure A/B/C/D format
    item_id = data['item_id']
    quantity = data['quantity']
    price = data['price']

    record_line = f"{inventory},{item_id},{quantity},{price}\n"
    file_path = os.path.join(DATA_DIR, f"inventory_{inventory}.txt")

    with open(file_path, "a") as f:
        f.write(record_line)

    return f"Record submitted and saved to inventory_{inventory}.txt"

if __name__ == '__main__':
    app.run(debug=True)
