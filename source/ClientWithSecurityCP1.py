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
            # filename = input(
            #     "Enter a filename to send (enter -1 to exit):"
            # ).strip()
                
            # When mode = 3, client send two message packets in bytes
            s.sendall(convert_int_to_bytes(3))
            #print("In Mode 3")

            m2 = "Client Request SecureStore ID"
            m1 = convert_int_to_bytes(len(m2)) #size(bytes) of m2
            s.sendall(m1)
            m2_bytes = bytes(m2, encoding="utf-8")
            s.sendall(m2_bytes)
            # print(f"---------SENT----------")
            # print("1. length of message in bytes : ", m1)
            # print("2. message : ", m2)

            # print("\n----------RECEIVED-----------")

            # m1_1 = s.recv(1024) # len(signed_message)
            # print("1. size of signed message in bytes : ", convert_bytes_to_int(m1_1))
            # m2_1 = s.recv(1024) # signed_message_bytes converted to int
            # print("2. signed authentication message : ", m2_1)

            signed_message_len = read_bytes(s, 8)
            signed_message = read_bytes(s, convert_bytes_to_int(signed_message_len))
            #print(signed_message_len, signed_message)
            
            
            # m1_2 = s.recv(1024) # len(server_signed_crt)
            # print("3. size of server_sign_crt : ", convert_bytes_to_int(m1_2))
            # m2_2 = s.recv(1024) # server_signed_crt_bytes converted to int
            # print("4. server_signed_crt : ", m2_2)

            server_signed_crt_len = read_bytes(s, 8)
            server_signed_crt = read_bytes(s, convert_bytes_to_int(server_signed_crt_len))
            #print(server_signed_crt_len, server_signed_crt)
            
            ##################### CHECK SERVER ID ##########################
            # Read certificate
            f = open("auth/cacsertificate.crt", "rb")
            ca_cert_raw = f.read()
            ca_cert = x509.load_pem_x509_certificate(data=ca_cert_raw, backend=default_backend())          

            ca_public_key = ca_cert.public_key()

            # Verify signature
            #m2_2 = server_cert_raw

            # f = open("auth/server_signed.crt","rb")
            # server_cert_raw = f.read() 


            server_cert = x509.load_pem_x509_certificate(data = server_signed_crt, backend=default_backend())
            # server_cert = x509.load_pem_x509_certificate(data = m2_2, backend=default_backend())

            ca_public_key.verify(
                signature=server_cert.signature, # signature bytes to verify
                data=server_cert.tbs_certificate_bytes, # certificate data bytes that was signed by CA
                padding=padding.PKCS1v15(), # padding used by CA bot to sign the the server's csr
                algorithm=server_cert.signature_hash_algorithm
            )

            server_public_key = server_cert.public_key()                        
            server_public_key.verify(
                signed_message,
                m2_bytes,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH,
                ),
                hashes.SHA256(),
            )
            # server_public_key.verify(
            #     m2_1,
            #     m2_bytes,
            #     padding.PSS(
            #         mgf=padding.MGF1(hashes.SHA256()),
            #         salt_length=padding.PSS.MAX_LENGTH,
            #     ),
            #     hashes.SHA256(),
            # )

            # Check certificate validity
            assert server_cert.not_valid_before <= datetime.utcnow() <= server_cert.not_valid_after
                    
            filename = input("Enter a filename to send (enter -1 to exit):")

            while filename != "-1" and (not pathlib.Path(filename).is_file()):
                filename = input("Invalid filename. Please try again:")

            if filename == "-1":
                s.sendall(convert_int_to_bytes(2))
                break

            filename_bytes = bytes(filename, encoding="utf8")

            # Send the filename
            s.sendall(convert_int_to_bytes(0))
            s.sendall(convert_int_to_bytes(len(filename_bytes)))
            s.sendall(filename_bytes)

            # Send the file
            with open(filename, mode="rb") as fp:
                # data = fp.read()
                s.sendall(convert_int_to_bytes(1))

                message_ls = []

                boolean = True
                while boolean:
                    line = fp.read(62)
                    if line == b"":
                        s.sendall(convert_int_to_bytes(len(b"end")))
                        s.sendall(b"end")
                        boolean = False
                        break
                    encrypted_message = server_public_key.encrypt(
                        line,
                        padding.OAEP(
                            mgf=padding.MGF1(hashes.SHA256()),
                            algorithm=hashes.SHA256(),
                            label=None,
                        ),
                    )
                    message_ls.append(encrypted_message)
                    s.sendall(convert_int_to_bytes(len(encrypted_message)))
                    s.sendall(encrypted_message)

                message_output = b"".join(message_ls)

                filename = filename.split("/")[-1]
                with open(f"send_files_enc/enc_{filename}", mode="wb") as fp:
                                fp.write(message_output)

        # Close the connection
        s.sendall(convert_int_to_bytes(2))
        print("Closing connection...")

    end_time = time.time()
    print(f"Program took {end_time - start_time}s to run.")


if __name__ == "__main__":
    main(sys.argv[1:])