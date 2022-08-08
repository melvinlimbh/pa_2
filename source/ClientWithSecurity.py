from http import server
import pathlib
import socket
import sys
import time
from datetime import datetime
import secrets
import traceback

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend

def convert_int_to_bytes(x):
    """
    Convenience function to convert Python integers to a length-8 byte representation
    """
    return x.to_bytes(8, "big")

def convert_bytes_to_int(xbytes):
    """
    Convenience function to convert byte value to integer value
    """
    return int.from_bytes(xbytes, "big")

def read_bytes(socket, length):
    """
    Reads the specified length of bytes from the given socket and returns a bytestring
    """
    buffer = []
    bytes_received = 0
    while bytes_received < length:
        data = socket.recv(min(length - bytes_received, 1024))
        if not data:
            raise Exception("Socket connection broken")
        buffer.append(data)
        bytes_received += len(data)

    return b"".join(buffer)

def main(args):
    port = int(args[0]) if len(args) > 0 else 4321
    server_address = args[1] if len(args) > 1 else "localhost"

    start_time = time.time()

    # try:
    print("Establishing connection to server...")
    # Connect to server
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((server_address, port))
        print("Connected")

        while True:
            filename = input(
                "Enter a filename to send (enter -1 to exit):"
            ).strip()
                

            while filename != "-1" :
                if filename == "3": 
                # When mode = 3, client send two message packets in bytes
                    s.sendall(convert_int_to_bytes(3))
                    print("In Mode 3")

                    m2 = "Client Request SecureStore ID"
                    m1 = convert_int_to_bytes(len(m2)) #size(bytes) of m2
                    s.sendall(m1)
                    m2_bytes = bytes(m2,encoding = "utf-8")
                    s.sendall(m2_bytes)
                    print(f"---------SENT----------")
                    print("1. length of message in bytes : ", m1)
                    print("2. message : ", m2)

                    print("\n----------RECEIVED-----------")
                    # m1_1 = s.recv(1024) # len(signed_message)
                    # print("1. size of signed message in bytes : ", convert_bytes_to_int(m1_1))
                    # m2_1 = s.recv(1024) # signed_message_bytes converted to int
                    # print("2. signed authentication message : ", m2_1)
                    
                    m1_2 = s.recv(1024) # len(server_signed_crt_bytes)
                    print("3. size of server_sign_crt : ", convert_bytes_to_int(m1_2))
                    m2_2 = s.recv(1024) # server_signed_crt_bytes converted to int
                    print("4. server_signed_crt : ", m2_2)
                    
                    ##################### CHECK SERVER ID ##########################
                    # Read certificate
                    f = open("auth/cacsertificate.crt", "rb")
                    ca_cert_raw = f.read()
                    ca_cert = x509.load_pem_x509_certificate(data=ca_cert_raw, 
                            backend=default_backend())          

                    ca_public_key = ca_cert.public_key()

                    # Verify signature
                    #m2_2 = server_cert_raw
                    f = open("auth/server_signed.crt","rb")
                    server_cert_raw = f.read() 
                    server_cert = x509.load_pem_x509_certificate( 
                        data = server_cert_raw, backend=default_backend())
                    decrypted_message = ca_public_key.verify(
                        signature=server_cert.signature, # signature bytes to  verify
                        data=server_cert.tbs_certificate_bytes, # certificate data bytes that was signed by CA
                        padding=padding.PKCS1v15(), # padding used by CA bot to sign the the server's csr
                        algorithm=server_cert.signature_hash_algorithm)
                    server_public_key = server_cert.public_key()

                #     decrypted_message = server_public_key.decrypt(
                #     convert_int_to_bytes(m1_2), # in bytes
                #     padding.OAEP(      # padding should match whatever used during encryption
                #     mgf=padding.MGF1(hashes.SHA256()),
                #     algorithm=hashes.SHA256(),
                #     label=None,
                # ),
                # )

                    # Verify message
                    if decrypted_message == "Client Request SecureStore ID":
                    #if output:
                        try:
                            assert server_cert.not_valid_before <= datetime.utcnow() <= server_cert.not_valid_after
                        except AssertionError:
                            break
                    else:
                        break
                    
                elif (not pathlib.Path(filename).is_file()):
                    filename = input("Invalid filename. Please try again:"
                    ).strip()

                elif (pathlib.Path(filename).is_file()): ##if file exists
                        filename_bytes = bytes(filename, encoding="utf8")
                     # Send the filename
                        s.sendall(convert_int_to_bytes(0))
                        s.sendall(convert_int_to_bytes(len(filename_bytes)))
                        s.sendall(filename_bytes)
                    # Send the file
                        with open(filename, mode="rb") as fp:
                            data = fp.read()
                            s.sendall(convert_int_to_bytes(1))
                            s.sendall(convert_int_to_bytes(len(data)))
                            s.sendall(data)
                            break

            if filename == "-1": 
                break;

        # Close the connection
        s.sendall(convert_int_to_bytes(2))
        print("Closing connection...")

    end_time = time.time()
    print(f"Program took {end_time - start_time}s to run.")


if __name__ == "__main__":
    main(sys.argv[1:])
