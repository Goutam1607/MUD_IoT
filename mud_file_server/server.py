from flask import Flask, send_from_directory, jsonify
import os

app = Flask(__name__)
MUD_FILES_DIR = os.path.join(os.path.dirname(__file__), '..', 'mud_files')


@app.route('/mud/<filename>')
def serve_mud_file(filename):
    """Serve MUD JSON files — this simulates the manufacturer's server"""
    try:
        return send_from_directory(MUD_FILES_DIR, filename,
                                   mimetype='application/mud+json')
    except FileNotFoundError:
        return jsonify({"error": "MUD file not found"}), 404


@app.route('/')
def index():
    files = os.listdir(MUD_FILES_DIR)
    return jsonify({"available_mud_files": files,
                    "server_info": "MUD File Server - RFC 8520"})


if __name__ == '__main__':
    print("[MUD FILE SERVER] Starting on http://localhost:5000")
    print("[MUD FILE SERVER] MUD files available at: http://localhost:5000/mud/<filename>")
    app.run(host='0.0.0.0', port=5000, debug=True)
