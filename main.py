from flask import Flask, render_template, redirect, url_for, session, jsonify, request
from authlib.integrations.flask_client import OAuth
import os
import qrcode
import io
import base64
from datetime import datetime
import threading
import time

try:
    from urllib.parse import urlparse, urlencode, parse_qs
except ImportError:
    from urlparse import urlparse, parse_qs
    from urllib import urlencode

import re
import sys
import requests
from boto3 import Session
from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest

app = Flask(__name__)
app.secret_key = os.urandom(24)  # Use a secure random key in production
oauth = OAuth(app)

oauth.register(
  name='oidc',
  authority='https://cognito-idp.eu-central-1.amazonaws.com/eu-central-1_9fgHZ61yH',
  client_id='6uel2db6j5saqmaj25shnu034p',
  client_secret='1nddrgdd198lcvn4dtn2gctosdgdmjip729kt1vq1thr9o0lg188',
  server_metadata_url='https://cognito-idp.eu-central-1.amazonaws.com/eu-central-1_9fgHZ61yH/.well-known/openid-configuration',
  client_kwargs={'scope': 'email openid phone profile'}
)

def signing_headers(method, url_string, body):
    # Adapted from:
    #   https://github.com/jmenga/requests-aws-sign/blob/master/requests_aws_sign/requests_aws_sign.py
    region = re.search("execute-api.(.*).amazonaws.com", url_string).group(1)
    url = urlparse(url_string)
    path = url.path or '/'
    querystring = ''
    if url.query:
        querystring = '?' + urlencode(
            parse_qs(url.query, keep_blank_values=True), doseq=True)

    safe_url = url.scheme + '://' + url.netloc.split(
        ':')[0] + path + querystring
    request = AWSRequest(method=method.upper(), url=safe_url, data=body)
    SigV4Auth(Session().get_credentials(), "execute-api",
              region).add_auth(request)
    return dict(request.headers.items())



# Data models
class Message:
    def __init__(self, messageId, message, sender, receiver, timestamp=None):
        self.messageId = messageId
        self.message = message
        self.sender = sender
        self.receiver = receiver
        self.timestamp = timestamp or datetime.now()

class Team:
    def __init__(self, teamId, teamName, allowedUsers):
        self.teamId = teamId
        self.teamName = teamName
        self.allowedUsers = allowedUsers or []



# Data loading from DynamoDB
messages_cache = []
messages_cache_lock = threading.Lock()

def fetch_messages():
    global messages_cache
    try:
        url = "https://nkfm9qap59.execute-api.eu-central-1.amazonaws.com/default/RequestMessages?TableName=MeshtasticMessages"
        response = requests.get(url, headers=signing_headers("GET", url, ""))
        data = response.json()
        new_messages = [
            Message(
                messageId=item['messageId']['S'],
                message=item['message']['S'],
                sender=item['sender']['S'],
                receiver=item['receiver']['S'],
                timestamp=datetime.fromisoformat(item['timestamp']['S'])
            )
            for item in data.get('Items', [])
        ]
        new_messages.sort(key=lambda msg: msg.timestamp, reverse=False)
        with messages_cache_lock:
            messages_cache = new_messages
    except Exception as e:
        print("Error fetching messages:", e)

teams_cache = []
teams_cache_lock = threading.Lock()

def fetch_teams():
    global teams_cache
    try:
        url = "https://nkfm9qap59.execute-api.eu-central-1.amazonaws.com/default/RequestMessages?TableName=MeshtasticTeams"
        response = requests.get(url, headers=signing_headers("GET", url, ""))
        data = response.json()
        loaded_teams = [
            Team(
                teamId=item['teamId']['S'],
                teamName=item['teamName']['S'],
                allowedUsers=[
                    user['S'] for user in item.get('allowedUsers', {}).get('L', [])
                ] if 'allowedUsers' in item else []
            )
            for item in data.get('Items', [])
        ]
        loaded_teams.sort(key=lambda msg: msg.teamName)
        with teams_cache_lock:
            teams_cache = loaded_teams
    except Exception as e:
        print("Error fetching teams:", e)

def fetch_data_periodically():
    global messages_cache, teams_cache
    while True:
        fetch_teams()
        fetch_messages()
        time.sleep(10)

# Start background thread for fetching data periodically
threading.Thread(target=fetch_data_periodically, daemon=True).start()




# General endpoints
@app.route('/')
def index():
    user = session.get('user')
    return render_template('index.html', user=user)

@app.route('/login')
def login():
    return oauth.oidc.authorize_redirect('https://lora-dashboard.gabor7d2.hu/authorize')

@app.route('/authorize')
def authorize():
    token = oauth.oidc.authorize_access_token()
    user = token['userinfo']
    session['user'] = user
    return redirect(url_for('index'))

@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('index'))




# API endpoints
@app.route('/messages')
def get_messages():
    user = session.get('user')
    if not user or 'cognito:username' not in user:
        return jsonify({"error": "Unauthorized"}), 401

    username = user['cognito:username']

    # Get team IDs the user is allowed to access
    with teams_cache_lock:
        allowed_team_ids = {team.teamId for team in teams_cache if username in team.allowedUsers}
    
    print(f"Allowed team IDs for user {username}: {allowed_team_ids}")

    # Return only messages where receiver is in allowed_team_ids
    with messages_cache_lock:
        msgs = [
            {
                "messageId": msg.messageId,
                "timestamp": msg.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
                "sender": msg.sender,
                "receiver": msg.receiver,
                "message": msg.message
            }
            for msg in messages_cache
            if msg.receiver in allowed_team_ids
        ]
    return jsonify(msgs)

@app.route('/teams')
def get_teams():
    user = session.get('user')
    if not user or 'cognito:username' not in user:
        return jsonify({"error": "Unauthorized"}), 401

    username = user['cognito:username']
    with teams_cache_lock:
        teams = [
            {
                "teamId": team.teamId,
                "teamName": team.teamName
            }
            for team in teams_cache
            if username in team.allowedUsers
        ]
    return jsonify(teams)

@app.route('/sendMessage', methods=['POST'])
def send_message():
    user = session.get('user')
    if not user or 'cognito:username' not in user:
        return jsonify({"error": "Unauthorized"}), 401

    data = request.get_json()
    target_teams = data.get('targetTeams', [])
    message = data.get('message', '')
    print(f"SendMessage called by {user['cognito:username']}:")
    print("Target teams:", target_teams)
    print("Message:", message)
    return jsonify({"status": "ok"})




# Key generator
# Static URL to encode in QR code
STATIC_URL = "https://www.youtube.com/watch?v=dQw4w9WgXcQ"

def generate_qr():
    # Generate QR code
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(STATIC_URL)
    qr.make(fit=True)

    # Create QR code image
    img = qr.make_image(fill_color="black", back_color="white")

    # Convert image to base64 string for embedding in HTML
    img_buffer = io.BytesIO()
    img.save(img_buffer, format='PNG')
    img_buffer.seek(0)
    return base64.b64encode(img_buffer.getvalue()).decode()

@app.route('/keygen')
def keygen():
    user = session.get('user')
    if not user:
        return jsonify({"error": "Unauthorized"}), 401

    img_base64 = generate_qr()
    return jsonify({
        "img_data": img_base64,
        "url": STATIC_URL
    })

if __name__ == '__main__':
    app.run(port=5001, debug=True)