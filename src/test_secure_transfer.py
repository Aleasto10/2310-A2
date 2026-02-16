import unittest
import threading
import time
import os
import hashlib

import server
import client



def hash_file(path):
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


class TestSecureFileTransfer(unittest.TestCase):

    def setUp(self):
        # Ensure old file removed
        if os.path.exists(client.FILE_RECEIVED):
            os.remove(client.FILE_RECEIVED)

        # Start server in background thread
        self.server_thread = threading.Thread(target=server.server_program)
        self.server_thread.daemon = True
        self.server_thread.start()

        # Give server time to start
        time.sleep(1)

    def test_file_transfer_success(self):
        """Test that file is transferred correctly and matches original"""

        client.client_program()

        self.assertTrue(os.path.exists(client.FILE_RECEIVED))

        original_hash = hash_file(client.FILE_REQUESTED)
        received_hash = hash_file(client.FILE_RECEIVED)

        self.assertEqual(original_hash, received_hash)

    def test_data_sent_is_encrypted(self):
        """Test that transmitted data is encrypted and not plaintext"""

        sent_data = bytearray()

        original_send = server.socket.socket.send

        def capture_send(self, data):
            sent_data.extend(data)
            return original_send(self, data)

        # Patch server socket send
        server.socket.socket.send = capture_send

        try:
            client.client_program()
        finally:
            # Restore original send
            server.socket.socket.send = original_send

        # Read original plaintext file
        with open(client.FILE_REQUESTED, "rb") as f:
            plaintext = f.read()

        transmitted = bytes(sent_data)

        # Ensure plaintext is not directly sent
        self.assertNotEqual(transmitted, plaintext)
        self.assertNotIn(plaintext, transmitted)

    def test_integrity_protection(self):
        """Simulate tampering and ensure decryption fails"""

        from Crypto.Cipher import AES
        from Crypto.Random import get_random_bytes

        key = get_random_bytes(32)
        cipher = AES.new(key, AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(b"test data")

        # Tamper with ciphertext
        tampered = bytearray(ciphertext)
        tampered[0] ^= 1

        cipher2 = AES.new(key, AES.MODE_GCM, nonce=cipher.nonce)

        with self.assertRaises(ValueError):
            cipher2.decrypt_and_verify(bytes(tampered), tag)


if __name__ == "__main__":
    unittest.main()
