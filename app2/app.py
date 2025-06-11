from flask import Flask, render_template, request, jsonify
from flask_socketio import SocketIO
import base64
import random
import math
import json
import requests
import hashlib

app = Flask(__name__)
socketio = SocketIO(app, cors_allowed_origins="*")

clients = {}  # sid -> { public_key }
webhooks = {
    'app1': 'http://127.0.0.1:5000/webhook_message'  # URL do webhook do app1
}

#RSA
def eh_primo(n):
    if n <= 1:
        return False
    for i in range(2, int(math.sqrt(n)) + 1):
        if n % i == 0:
            return False
    return True

def gerar_primo(min=1000, max=5000):
    while True:
        num = random.randint(min, max)
        if eh_primo(num):
            return num

def mdc(a, b):
    while b:
        a, b = b, a % b
    return a

def gerar_chaves():
    p = gerar_primo()
    q = gerar_primo()
    while q == p:
        q = gerar_primo()
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 3
    while mdc(e, phi) != 1:
        e += 2
    d = pow(e, -1, phi)
    return ((e, n), (d, n))

def cifra(mensagem, chave):
    e, n = chave
    cifra_nums = [pow(ord(char), e, n) for char in mensagem]
    return base64.b64encode(json.dumps(cifra_nums).encode('utf-8')).decode()

def decifra(cifrada, chave):
    d, n = chave
    try:
        lista = json.loads(base64.b64decode(cifrada).decode())
        return ''.join([chr(pow(int(num), d, n)) for num in lista])
    except Exception as e:
        print("Erro na descriptografia:", e)
        return "[ERRO NA DESCRIPTOGRAFIA]"

# Gera as chaves do servidor
publica_srv, privada_srv = gerar_chaves()

@app.route('/')
def index():
    return render_template('chat.html', public_key=publica_srv, app_name="App2")

@socketio.on('connect')
def handle_connect():
    sid = request.sid
    print(f"[App2] Cliente conectado: {sid}")

@socketio.on('disconnect')
def handle_disconnect():
    sid = request.sid
    if sid in clients:
        del clients[sid]
    print(f"[App2] Cliente desconectado: {sid}")

@socketio.on('public_key')
def receive_client_key(data):
    sid = request.sid
    clients[sid] = {
        'public_key': tuple(data['key'])
    }
    print(f"[App2] Recebeu chave pública de {sid}")

@socketio.on('send_message')
def handle_send_message(data):
    sender_sid = request.sid
    encrypted_message = data['message']

    decrypted_message = decifra(encrypted_message, privada_srv)
    print(f"[App2] Mensagem recebida: {decrypted_message}")

    # Geração do hash SHA-256 da mensagem
    hash_sha256 = hashlib.sha256(decrypted_message.encode('utf-8')).hexdigest()
    print(f"[App2] Hash SHA-256 da mensagem: {hash_sha256}")

    # Envia para outros clientes do app1
    for sid, info in clients.items():
        if sid != sender_sid:
            pubkey = info['public_key']
            encrypted_for_receiver = cifra(decrypted_message, pubkey)
            socketio.emit('receive_message', {'message': encrypted_for_receiver}, to=sid)

    # Envia para app1 via webhook
    try:
        webhook_url = webhooks['app1']
        requests.post(webhook_url, json={"message": decrypted_message})
    except Exception as e:
        print(f"[App1] Erro ao enviar para webhook app2: {e}")

@app.route('/webhook_message', methods=['POST'])
def webhook_message():
    data = request.json
    mensagem = data.get('message')
    if not mensagem:
        return jsonify({"error": "No message"}), 400

    print(f"[App2] Mensagem recebida via webhook: {mensagem}")

    # Envia para todos os clientes do app2
    for sid, info in clients.items():
        pubkey = info['public_key']
        encrypted = cifra(mensagem, pubkey)
        socketio.emit('receive_message', {'message': encrypted}, to=sid)

    return jsonify({"status": "ok"})

if __name__ == '__main__':
    socketio.run(app, debug=True, host='0.0.0.0', port=5001)
