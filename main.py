from flask import Flask, render_template, redirect, url_for, session, jsonify
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

messages_cache = []
messages_cache_lock = threading.Lock()

def fetch_messages_periodically():
    global messages_cache
    while True:
        try:
            url = "https://nkfm9qap59.execute-api.eu-central-1.amazonaws.com/default/RequestMessages?TableName=MeshtasticMessages"
            response = requests.get(url, headers=signing_headers("GET", url, ""))
            data = response.json()
            new_messages = [
                Message(
                    text=item['message']['S'],
                    sender=item['sender']['S'],
                    timestamp=datetime.fromisoformat(item['timestamp']['S'])
                )
                for item in data.get('Items', [])
            ]
            new_messages.sort(key=lambda msg: msg.timestamp, reverse=True)
            with messages_cache_lock:
                messages_cache = new_messages
        except Exception as e:
            print("Error fetching messages:", e)
        time.sleep(10)

# Start background thread
threading.Thread(target=fetch_messages_periodically, daemon=True).start()

app = Flask(__name__)
app.secret_key = os.urandom(24)  # Use a secure random key in production
oauth = OAuth(app)

oauth.register(
  name='oidc',
  authority='https://cognito-idp.eu-central-1.amazonaws.com/eu-central-1_9fgHZ61yH',
  client_id='***REMOVED***',
  client_secret='***REMOVED***',
  server_metadata_url='https://cognito-idp.eu-central-1.amazonaws.com/eu-central-1_9fgHZ61yH/.well-known/openid-configuration',
  client_kwargs={'scope': 'email openid phone'}
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


class Message:
    def __init__(self, text, sender, timestamp=None):
        self.text = text
        self.sender = sender
        self.timestamp = timestamp or datetime.now()

@app.route('/')
def index():
    user = session.get('user')
    return render_template('index.html', user=user)

@app.route('/login')
def login():
    return oauth.oidc.authorize_redirect('https://lora-keygen.gabor7d2.hu/authorize')

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

@app.route('/messages')
def get_messages():
    user = session.get('user')
    if not user:
        return jsonify({"error": "Unauthorized"}), 401
    
    # Return cached messages
    with messages_cache_lock:
        msgs = [
            {
                "timestamp": msg.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
                "sender": msg.sender,
                "text": msg.text
            }
            for msg in messages_cache
        ]
    return jsonify(msgs)

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

@app.route('/qr')
def show_qr():
    user = session.get('user')
    if not user:
        return redirect(url_for('index'))
    
    img_base64 = generate_qr()
    return render_template('qr_code.html', img_data=img_base64, url=STATIC_URL)

if __name__ == '__main__':
    app.run(port=5002, debug=True)