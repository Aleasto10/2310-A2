# A2 Cryptographic File Sharing

This is the code for the second assignment for INF-2310 Computer security.
Which tasks with creating a client and server communicating using encryption to ensure confidentiality.

## How to run

### Software Requirements

- Python 3.8+
- PyCryptodome library
Install:
```
    pip install pycryptodome
```

### Running the server and client

Simply open two separate terminals in the *src* folder and then in the first one do:
```
    python server.py
```
Which starts the server. After that start the client on the second terminal:
```
    python client.py
```

### Running tests

To run the tests inside of the test class open a terminal in the *src* folder and run:
```
    python test_secure_transfer.py
```