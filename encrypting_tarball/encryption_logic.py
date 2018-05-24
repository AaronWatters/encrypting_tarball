
import os
import hashlib
import shutil
from Crypto.Cipher import ARC4
import subprocess

def checksum(data):
    return hashlib.sha1(data).digest()

def get_encoder(password):
    return ARC4.new(password)

class Encryption:

    def __init__(self, parent_path, folder_name, password):
        self.parent_path = os.path.abspath(parent_path)
        self.folder_name = folder_name
        self.password = self.pad_password(password)
        self.source_path = self.extension_filepath("")
        self.crypt_path = self.extension_filepath(".crypt")
        self.tar_path = self.extension_filepath(".tar.gz")
        self.signature_path = self.extension_filepath(".sig")
        self.pass_sig_path = self.extension_filepath(".pass.sig")

    def encoder(self):
        return get_encoder(self.password)

    def encrypt(self, delete_source=False):
        self.check_password_signature(save=True)
        self.create_tarfile()
        self.check_tarfile_signature(save=True)
        self.encrypt_tarfile()
        self.delete_file(self.tar_path)
        if delete_source:
            self.remove_source()

    def encrypt_tarfile(self):
        tar_content = self.file_content(self.tar_path)
        encrypted_content = self.encoder().encrypt(tar_content)
        self.store_content(self.crypt_path, encrypted_content)

    def decrypt_tarfile(self):
        crypt_content = self.file_content(self.crypt_path)
        tar_content = self.encoder().decrypt(crypt_content)
        self.store_content(self.tar_path, tar_content)

    def create_tarfile(self):
        if self.exists(self.tar_path):
            self.delete_file(self.tar_path)
        create_tar_command = """
        cd %s; tar -czf %s %s
        """ % (self.parent_path, self.tar_path, self.folder_name)
        #print(create_tar_command)
        output = subprocess.check_output(create_tar_command, shell=True)
        assert self.exists(self.tar_path), (
            "No tar file created: " + self.tar_path + " :: " + output[:100]
        )

    def unpack_tarfile(self, delete_if_exists=False):
        assert self.exists(self.tar_path)
        if delete_if_exists and self.exists(self.source_path):
            self.delete_file(self.source_path)
        unpack_tar_command = """
        cd %s; tar -xzf %s
        """ % (self.parent_path, self.tar_path)
        #print (unpack_tar_command)
        output = subprocess.check_output(unpack_tar_command, shell=True)
        assert self.exists(self.source_path), (
            "untar did not create source path " + 
            repr((unpack_tar_command, self.source_path)) +
            "  " + output[:100]
        )

    def decrypt(self):
        self.check_password_signature()
        self.decrypt_tarfile()
        self.check_tarfile_signature()
        self.unpack_tarfile()

    def remove_artifacts(self):
        if not self.exists(self.source_path):
            raise OSError("Safety check -- no source: " + repr(self.source_path))
        for path in [self.crypt_path, self.tar_path, self.signature_path, self.pass_sig_path]:
            if self.exists(path):
                self.delete_file(path)

    def remove_source(self):
        self.check_password_signature()
        if not self.exists(self.crypt_path):
            raise OSError("Safety -- no crypt file: " + repr(self.crypt_path))
        self.delete_file(self.source_path)

    def delete_file(self, path):
        if os.path.isdir(path):
            shutil.rmtree(path)
        else:
            os.remove(path)

    def check_tarfile_signature(self, save=False):
        tfsp = self.signature_path
        tar_content = self.file_content(self.tar_path)
        computed_signature = checksum(tar_content)
        if self.exists(tfsp):
            saved_signature = self.file_content(tfsp)
            if saved_signature == computed_signature:
                return True
            else:
                raise ValueError("computed signature doesn't match stored: "+
                    repr((computed_signature, tfsp, self.tar_path)))
        elif save:
            self.store_content(tfsp, computed_signature)
            return False
        else:
            raise OSError("required signature file missing " + repr(tfsp))

    def check_password_signature(self, save=False):
        psp = self.pass_sig_path
        p_checksum = self.password_checksum()
        if self.exists(psp):
            psp_content = self.file_content(psp)
            if psp_content == p_checksum:
                return True
            else:
                raise ValueError("password checksum doesn't match " + repr(((p_checksum, psp))))
        elif save:
            self.store_content(psp, p_checksum)
            return False
        else:
            raise OSError("required checksum file not found " + repr(psp))

    def password_checksum(self):
        encrypted_password = self.encoder().encrypt(self.password)
        result = checksum(encrypted_password)
        return result

    def file_content(self, path):
        return open(path, "rb").read()

    def exists(self, path):
        return os.path.exists(path)

    def store_content(self, path, data):
        open(path, "wb").write(data)

    def pad_password(self, password, minlength=50):
        lp = len(password)
        if lp < minlength:
            password = password + ("x" * (minlength - lp))
        return password

    def extension_filepath(self, dot_extension):
        ext_filename = self.folder_name + dot_extension
        return os.path.join(self.parent_path, ext_filename)
