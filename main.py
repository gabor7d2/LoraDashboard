from flask import Flask, render_template, redirect, url_for, session, jsonify, request
from authlib.integrations.flask_client import OAuth
import os
import qrcode
import io
import base64
from datetime import datetime
import threading
import time
import json
import uuid
import pytz

try:
    from urllib.parse import urlparse, urlencode, parse_qs
except ImportError:
    from urlparse import urlparse, parse_qs
    from urllib import urlencode

import re
import sys
import requests
import secrets
import string
from boto3 import Session
from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest

import meshtastic_channelset_stripped_reduced_pb2 as proto

from awscrt import mqtt, http
from awsiot import mqtt_connection_builder

app = Flask(__name__)
app.secret_key = os.urandom(24)  # Use a secure random key in production
oauth = OAuth(app)

oauth.register(
  name='oidc',
  authority='https://cognito-idp.eu-central-1.amazonaws.com/eu-central-1_9fgHZ61yH',
  client_id=os.environ.get('OIDC_CLIENT_ID'),
  client_secret=os.environ.get('OIDC_CLIENT_SECRET'),
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
    def __init__(self, teamId, teamName, allowedUsers, gatewayNodeId=None):
        self.teamId = teamId
        self.teamName = teamName
        self.allowedUsers = allowedUsers or []
        self.gatewayNodeId = gatewayNodeId



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
                ] if 'allowedUsers' in item else [],
                gatewayNodeId=int(item['gatewayNodeId']['N']) if 'gatewayNodeId' in item else None  # Fetch gatewayNodeId
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

    # Find team objects for each target team
    with teams_cache_lock:
        team_map = {team.teamId: team for team in teams_cache}

    for team_id in target_teams:
        team = team_map.get(team_id)
        if not team or not team.gatewayNodeId:
            print(f"Team {team_id} not found or missing gatewayNodeId, skipping.")
            continue

        topic = f"cloud/{team_id}"
        #topic = "cloud/anton"
        publish_to_aws_iot_core(
            topic=topic,
            message={
                "from": team.gatewayNodeId,
                "type": "sendtext",
                "payload": "[OPS] " + message,
                "channel": 1
            }
        )

        # Set timezone to Europe/Budapest (or your local timezone)
        local_tz = pytz.timezone('Europe/Amsterdam')
        local_time = datetime.now(local_tz)
        timestamp_str = local_time.strftime('%Y-%m-%dT%H:%M:%S')

        # Save message to DynamoDB (RequestMessages table)
        dynamo_payload = {
            "TableName": "MeshtasticMessages",
            "Item": {
                "messageId": {"S": str(uuid.uuid4())},
                "message": {"S": "[OPS] " + message},
                "sender": {"S": "[OPS] " + user['name']},
                "receiver": {"S": team_id},
                "timestamp": {"S": timestamp_str}
            }
        }
        try:
            url = "https://nkfm9qap59.execute-api.eu-central-1.amazonaws.com/default/RequestMessages"
            headers = signing_headers("POST", url, json.dumps(dynamo_payload))
            response = requests.post(url, headers=headers, json=dynamo_payload)
            if response.status_code != 200:
                print(f"Failed to save message for team {team_id}: {response.text}")
        except Exception as e:
            print(f"Exception saving message for team {team_id}: {e}")

    return jsonify({"status": "ok"})




# Key generator
MESHTASTIC_URL_BASE = "https://meshtastic.org/e/#"

def generate_psk_bytes(length=32):
    # Generate a cryptographically secure random ASCII string (printable, no whitespace)
    chars = string.ascii_letters + string.digits
    rand_str = ''.join(secrets.choice(chars) for _ in range(length))
    # Convert to list of byte values
    return [ord(c) for c in rand_str]

def add_channel_settings(cs, psk_bytes, name, uplink_enabled = True, downlink_enabled = True, position_precision = 0, is_client_muted = False):
    chan = cs.settings.add()
    chan.psk = bytes(psk_bytes)
    chan.name = name
    chan.uplink_enabled = uplink_enabled
    chan.downlink_enabled = downlink_enabled
    chan.module_settings.position_precision = position_precision
    chan.module_settings.is_client_muted = is_client_muted
    return chan

def generate_channelset_protobuf():
    cs = proto.ChannelSet()

    add_channel_settings(
        cs,
        psk_bytes=[1],
        name="Public",
        position_precision=13
    )
    add_channel_settings(
        cs,
        psk_bytes=generate_psk_bytes(),
        name="mqtt",
    )

    # LoRaConfig
    cs.lora_config.use_preset = True
    cs.lora_config.modem_preset = proto.LoRaConfig.LONG_SLOW
    cs.lora_config.region = proto.LoRaConfig.EU_868
    cs.lora_config.hop_limit = 7
    cs.lora_config.tx_enabled = True
    cs.lora_config.tx_power = 27
    cs.lora_config.sx126x_rx_boosted_gain = True
    cs.lora_config.config_ok_to_mqtt = True

    bytestream = cs.SerializeToString()
    b64 = base64.urlsafe_b64encode(bytestream).decode().rstrip("=")
    print("Generated ChannelSet: " + b64)
    return b64

def generate_qr(url):
    # Generate QR code
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(url)
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
    
    url = MESHTASTIC_URL_BASE + generate_channelset_protobuf()

    img_base64 = generate_qr(url)
    return jsonify({
        "img_data": img_base64,
        "url": url
    })



# AWS IoT MQTT connection setup
received_count = 0
received_all_event = threading.Event()

# Make mqtt_connection a global variable
mqtt_connection = None

# Callback when connection is accidentally lost.
def on_connection_interrupted(connection, error, **kwargs):
    print("IoT Core Connection interrupted. error: {}".format(error))

# Callback when an interrupted connection is re-established.
def on_connection_resumed(connection, return_code, session_present, **kwargs):
    print("IoT Core Connection resumed. return_code: {} session_present: {}".format(return_code, session_present))

    if return_code == mqtt.ConnectReturnCode.ACCEPTED and not session_present:
        print("IoT Core Session did not persist. Resubscribing to existing topics...")
        resubscribe_future, _ = connection.resubscribe_existing_topics()

        # Cannot synchronously wait for resubscribe result because we're on the connection's event-loop thread,
        # evaluate result with a callback instead.
        resubscribe_future.add_done_callback(on_resubscribe_complete)

def on_resubscribe_complete(resubscribe_future):
    resubscribe_results = resubscribe_future.result()
    print("IoT Core Resubscribe results: {}".format(resubscribe_results))

    for topic, qos in resubscribe_results['topics']:
        if qos is None:
            sys.exit("IoT Core Server rejected resubscribe to topic: {}".format(topic))

# Callback when the connection successfully connects
def on_connection_success(connection, callback_data):
    assert isinstance(callback_data, mqtt.OnConnectionSuccessData)
    print("IoT Core Connection Successful with return code: {} session present: {}".format(callback_data.return_code, callback_data.session_present))

# Callback when a connection attempt fails
def on_connection_failure(connection, callback_data):
    assert isinstance(callback_data, mqtt.OnConnectionFailureData)
    print("IoT Core Connection failed with error code: {}".format(callback_data.error))

# Callback when a connection has been disconnected or shutdown successfully
def on_connection_closed(connection, callback_data):
    print("IoT Core Connection closed")

def init_aws_iot_core():
    global mqtt_connection
    mqtt_connection = mqtt_connection_builder.mtls_from_path(
        endpoint="adl9zhdzxqx4m-ats.iot.eu-central-1.amazonaws.com",
        port=8883,
        cert_filepath="iot_core/central_dashboard.cert.pem",
        pri_key_filepath="iot_core/central_dashboard.private.key",
        ca_filepath="iot_core/root-CA.crt",
        on_connection_interrupted=None,
        on_connection_resumed=on_connection_resumed,
        # set client id to random UUID
        #client_id="{}".format(uuid.uuid4()),
        client_id="basicPubSub",
        clean_session=False,
        keep_alive_secs=30,
        http_proxy_options=None,
        on_connection_success=on_connection_success,
        on_connection_failure=on_connection_failure,
        on_connection_closed=on_connection_closed)

    connect_future = mqtt_connection.connect()

    # Future.result() waits until a result is available
    connect_future.result()
    print("Connected to IoT Core!")

    # Subscribe
    #print("Subscribing to topic '{}'...".format("cloud/anton"))
    #subscribe_future, packet_id = mqtt_connection.subscribe(
    #    topic="cloud/anton",
    #    qos=mqtt.QoS.AT_LEAST_ONCE,
    #    callback=None)

    #subscribe_result = subscribe_future.result()
    #print("Subscribed with {}".format(str(subscribe_result['qos'])))

def publish_to_aws_iot_core(topic, message):
    global mqtt_connection
    print("Publishing message to IoT Core topic '{}': {}".format(topic, message))
    message_json = json.dumps(message)
    mqtt_connection.publish(
        topic=topic,
        payload=message_json,
        qos=mqtt.QoS.AT_LEAST_ONCE)

if __name__ == '__main__':
    init_aws_iot_core()
    app.run(port=5001, debug=True)