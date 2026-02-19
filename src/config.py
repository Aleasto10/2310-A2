"data/server_data/example.txt"
"data/server_data/Analisis_del_Codigo_Fuente_y_Metricas_Asociadas_S2_20250319.txt"

# Chooses the file requested from the server and the name of the file received by the client
FILE_REQUESTED = "data/server_data/example.txt"
FILE_RECEIVED = "data/client_data/received_file.txt"

# Uses local RSA instead of the crypto library
LOCAL_RSA = True

# Range for the randomly generated P and Q when using local RSA
# Must be large enough so that n > 2^256 to safely hold 32-byte AES key
LOW_PRIME = 1000
HIGH_PRIME = 3000