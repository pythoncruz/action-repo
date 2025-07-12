from flask import Flask, request, jsonify, render_template
from pymongo import MongoClient
from datetime import datetime
import os
from bson import ObjectId
import json
import hmac
import hashlib
from functools import wraps

app = Flask(__name__)
app.template_folder = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'templates')

# Configuration
WEBHOOK_SECRET = os.getenv('WEBHOOK_SECRET')
MONGO_URI = os.getenv('MONGO_URI', 'mongodb://localhost:27017/')

# MongoDB connection with error handling
try:
    client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000)
    client.server_info()  # Test connection
    db = client.github_events
    collection = db.actions
except Exception as e:
    print(f"❌ MongoDB connection failed: {str(e)}")
    raise

class JSONEncoder(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, ObjectId):
            return str(o)
        if isinstance(o, datetime):
            return o.isoformat()
        return super().default(o)

app.json_encoder = JSONEncoder

def verify_signature(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if WEBHOOK_SECRET:
            signature = request.headers.get('X-Hub-Signature-256')
            if not signature:
                return jsonify({"error": "Missing signature"}), 403
                
            body = request.get_data()
            expected_signature = 'sha256=' + hmac.new(
                WEBHOOK_SECRET.encode(),
                body,
                hashlib.sha256
            ).hexdigest()
            
            if not hmac.compare_digest(signature, expected_signature):
                return jsonify({"error": "Invalid signature"}), 403
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
def home():
    try:
        return render_template('index.html')
    except Exception as e:
        app.logger.error(f"Template error: {str(e)}")
        return "Error loading page", 500

@app.route('/webhook', methods=['POST'])
@verify_signature
def webhook():
    try:
        data = request.get_json(silent=True) or {}
        event_type = request.headers.get('X-GitHub-Event')
        
        if not event_type:
            return jsonify({"error": "Missing event type"}), 400
            
        handlers = {
            'push': handle_push,
            'pull_request': handle_pull_request
        }
        
        if handler := handlers.get(event_type):
            handler(data)
            return jsonify({"status": "success"}), 200
            
        return jsonify({"error": "Unsupported event type"}), 400

    except Exception as e:
        app.logger.error(f"Webhook error: {str(e)}")
        return jsonify({"error": "Processing failed"}), 500

def handle_push(data):
    if not (commit := data.get('head_commit')):
        raise ValueError("Missing head_commit in push event")
    
    record = {
        "request_id": commit['id'],
        "author": commit['author']['name'],
        "action": "PUSH",
        "from_branch": data['ref'].split('/')[-1],
        "to_branch": data['ref'].split('/')[-1],
        "timestamp": datetime.strptime(commit['timestamp'], '%Y-%m-%dT%H:%M:%SZ')
    }
    collection.insert_one(record)

def handle_pull_request(data):
    if not (pr := data.get('pull_request')):
        raise ValueError("Missing pull_request data")
    
    action = data.get('action')
    if action == 'closed' and pr.get('merged'):
        record = {
            "request_id": str(pr['number']),
            "author": pr['merged_by']['login'],
            "action": "MERGE",
            "from_branch": pr['head']['ref'],
            "to_branch": pr['base']['ref'],
            "timestamp": datetime.strptime(pr['merged_at'], '%Y-%m-%dT%H:%M:%SZ')
        }
    elif action in ['opened', 'reopened']:
        record = {
            "request_id": str(pr['number']),
            "author": pr['user']['login'],
            "action": "PULL_REQUEST",
            "from_branch": pr['head']['ref'],
            "to_branch": pr['base']['ref'],
            "timestamp": datetime.strptime(pr['created_at'], '%Y-%m-%dT%H:%M:%SZ')
        }
    else:
        return
        
    collection.insert_one(record)

@app.route('/api/events')
def get_events():
    try:
        events = list(collection.find()
                     .sort("timestamp", -1)
                     .limit(10))
        return jsonify(events)
    except Exception as e:
        app.logger.error(f"DB error: {str(e)}")
        return jsonify({"error": "Failed to fetch events"}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=os.getenv('FLASK_DEBUG', False))