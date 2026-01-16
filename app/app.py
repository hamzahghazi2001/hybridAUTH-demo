from flask import Flask, jsonify

app = Flask(__name__)
@app.route('/health', methods=['GET'])
def health():
    health_data = {"ok": True}
    return jsonify(health_data)


if __name__ == '__main__':
        app.run(debug=True)