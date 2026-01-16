from flask import Flask, jsonify, render_template

app = Flask(__name__)
@app.route('/health', methods=['GET'])
def health():
    health_data = {"ok": True}
    return jsonify(health_data)

@app.route('/')
def index():
    return render_template('index.html')


if __name__ == '__main__':
        app.run(debug=True)