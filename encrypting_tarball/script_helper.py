
encrypt_usage = """
This script will encrypt a directory and store cryptographic hashes.

Usage:

$ (script_name) PASSWORD [delete]

If delete is specified the source directory will be deleted after encryption.
"""

from encrypting_tarball import Encryption
import sys

def encrypt_script(parent_path, folder_name):
    try:
        password = sys.argv[1]
        delete = ("delete" in sys.argv[2:])
        encryptor = Encryption(parent_path, folder_name, password)
        print ("Now encrypting in " + repr(parent_path) + " folder " + repr(folder_name))
        if delete:
            print("... and deleting the source folder afterwards.")
        encryptor.encrypt(delete_source=delete)
        print ("Encrypted archive: " + repr(encryptor.crypt_path))
        print ("Content checksum: " + repr(encryptor.signature_path))
        print ("Password checksum: " + repr(encryptor.pass_sig_path))
    except:
        print(encrypt_usage)
        raise

decrypt_usage = """
This script will encrypt a directory and check cryptographic hashes.

Usage:

$ (script_name) PASSWORD [delete]

If delete is specified the encryption artifacts will be deleted after successful decryption.
"""

def decrypt_script(parent_path, folder_name):
    try:
        password = sys.argv[1]
        delete = ("delete" in sys.argv[2:])
        decryptor = Encryption(parent_path, folder_name, password)
        print ("Now decrypting in " + repr(parent_path) + " folder " + repr(folder_name))
        if delete:
            print("... and deleting the encryption artifacts afterwards.")
        decryptor.decrypt()
        print("decryption complete")
        if delete:
            print ("removing artifacts")
            decryptor.remove_artifacts()
    except:
        print(decrypt_usage)
        raise