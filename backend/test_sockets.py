import socketio
import requests
import time
import random

s1 = socketio.Client()
s2 = socketio.Client()

def test_chat():
    username1 = 'user' + str(random.randint(1000, 9999))
    username2 = 'user' + str(random.randint(1000, 9999))
    requests.post('http://localhost:5000/api/register', json={'username': username1, 'email': f'{username1}@test.com', 'password': 'password'})
    requests.post('http://localhost:5000/api/register', json={'username': username2, 'email': f'{username2}@test.com', 'password': 'password'})
    
    res1 = requests.post('http://localhost:5000/api/login', json={'username': username1, 'password': 'password'})
    res2 = requests.post('http://localhost:5000/api/login', json={'username': username2, 'password': 'password'})
    
    t1 = res1.json()['token']
    u1 = res1.json()['user']['id']
    
    t2 = res2.json()['token']
    u2 = res2.json()['user']['id']
    
    print(f"User 1 ID: {u1}")
    print(f"User 2 ID: {u2}")

    messages_received = []

    @s2.on('receive_message')
    def on_receive(data):
        print(f"User 2 received message: {data}")
        messages_received.append(data)
        
    @s2.on('user_online')
    def on_online(data):
        print(f"User 2 saw someone online: {data}")

    headers = {'Origin': 'http://localhost:3000'}

    s1.connect('http://localhost:5000', auth={'token': t1}, headers=headers)
    s2.connect('http://localhost:5000', auth={'token': t2}, headers=headers)
    
    time.sleep(1)
    
    s1.emit('send_message', {
        'token': t1,
        'recipient_id': u2,
        'encrypted_content': 'test',
        'encrypted_aes_key': 'test',
        'message_hash': 'test',
        'signature': 'test',
        'nonce': 'testnonce123'
    })
    
    time.sleep(2)
    
    print("Messages received:", len(messages_received))
    s1.disconnect()
    s2.disconnect()

if __name__ == '__main__':
    test_chat()
