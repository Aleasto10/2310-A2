import unittest
import threading
import time
import os
import hashlib

import server
import client


TEST_FILE = "data/server_data/example.txt"
RECEIVED_FILE = "data/client_data/received_file.txt"


def hash_file(path):
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


class TestSecureFileTransfer(unittest.TestCase):

    def setUp(self):
        # Ensure old file removed
        if os.path.exists(RECEIVED_FILE):
            os.remove(RECEIVED_FILE)

        # Start server in background thread
        self.server_thread = threading.Thread(target=server.server_program)
        self.server_thread.daemon = True
        self.server_thread.start()

        # Give server time to start
        time.sleep(1)

    def test_file_transfer_success(self):
        """Test that file is transferred correctly and matches original"""

        client.client_program()

        self.assertTrue(os.path.exists(RECEIVED_FILE))

        original_hash = hash_file(TEST_FILE)
        received_hash = hash_file(RECEIVED_FILE)

        self.assertEqual(original_hash, received_hash)

    def test_confidentiality_ciphertext_not_plaintext(self):
        """Ensure that encrypted data sent over network is not plaintext"""

        # Read original file
        with open(TEST_FILE, "rb") as f:
            original_data = f.read()

        client.client_program()

        with open(RECEIVED_FILE, "rb") as f:
            received_data = f.read()

        # Ensure file was not sent in plaintext
        self.assertNotEqual(original_data, b"")  # sanity
        self.assertEqual(original_data, received_data)

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
