"""Test the encrypting_tarball package."""

import unittest
import encrypting_tarball
import os
import shutil

my_dir = os.path.dirname(__file__)
artifacts_dir = os.path.join(my_dir, "artifacts")

def test_version_is_string():
    import encrypting_tarball
    assert isinstance(encrypting_tarball.__version__, str)

class FakeFiles(encrypting_tarball.Encryption):

    path_to_content = None

    def get_path_to_content(self):
        p2c = self.path_to_content
        if p2c is None:
            p2c = self.path_to_content = {}
        return p2c

    def file_content(self, path):
        return self.get_path_to_content()[path]

    def exists(self, path):
        return path in self.get_path_to_content()

    def store_content(self, path, data):
        self.get_path_to_content()[path] = data

    def delete_file(self, path):
        del self.get_path_to_content()[path]

example_password = "password"
example_password_signature = b'\x833\x85\xa8\xef\xa4\xbf\x87q\x07tN\x80;Y\xd8_\x8e\xf2('
fake_tar_content = b"fake tar content "
fake_tar_signature = b'X\xd0C\x841\xb2\xf9R\xfd\x94\x12*\x01\xd0\x8c\x9e\\\xf7\xf7\x1b'
fake_crypt_content = b'"\x02\x15\x84H$\x19\xab&\xd9\x00\x9d\xbaLMEQ'

class TestEncryption0(unittest.TestCase):

    def test_decrypt_tarfile(self):
        f = FakeFiles("/a/b", "c", example_password)
        f.store_content(f.crypt_path, fake_crypt_content)
        f.decrypt_tarfile()
        decrypted = f.file_content(f.tar_path)
        self.assertEqual(decrypted, fake_tar_content)

    def test_encrypt_tarfile(self):
        f = FakeFiles("/a/b", "c", example_password)
        f.store_content(f.tar_path, fake_tar_content)
        f.encrypt_tarfile()
        encrypted = f.file_content(f.crypt_path)
        self.assertEqual(encrypted, fake_crypt_content)

    def test_check_tar_sig_create_file(self):
        f = FakeFiles("/a/b", "c", example_password)
        f.store_content(f.tar_path, fake_tar_content)
        self.assertFalse(f.check_tarfile_signature(save=True))
        self.assertEqual(fake_tar_signature, f.file_content(f.signature_path))

    def test_check_tar_sig(self):
        f = FakeFiles("/a/b", "c", example_password)
        f.store_content(f.tar_path, fake_tar_content)
        f.store_content(f.signature_path, fake_tar_signature)
        self.assertTrue(f.check_tarfile_signature())

    def test_check_bad_sig(self):
        f = FakeFiles("/a/b", "c", example_password)
        f.store_content(f.tar_path, fake_tar_content)
        f.store_content(f.signature_path, fake_tar_signature[1:]+b"5")
        with self.assertRaises(ValueError):
            f.check_tarfile_signature()

    def test_check_no_sig(self):
        f = FakeFiles("/a/b", "c", example_password)
        f.store_content(f.tar_path, fake_tar_content)
        with self.assertRaises(OSError):
            f.check_tarfile_signature()

    def test_check_password_create_file(self):
        f = FakeFiles("/a/b", "c", example_password)
        self.assertFalse(f.check_password_signature(save=True))
        self.assertEqual(example_password_signature, f.file_content(f.pass_sig_path))

    def test_check_password(self):
        f = FakeFiles("/a/b", "c", example_password)
        f.store_content(f.pass_sig_path, example_password_signature)
        f.check_password_signature()

    def test_check_bad_password(self):
        f = FakeFiles("/a/b", "c", "bad password")
        f.store_content(f.pass_sig_path, example_password_signature)
        with self.assertRaises(ValueError):
            f.check_password_signature()

    def test_check_no_password_sig(self):
        f = FakeFiles("/a/b", "c", "bad password")
        with self.assertRaises(OSError):
            f.check_password_signature()

    def test_remove_source(self):
        f = FakeFiles("/a/b", "c", example_password)
        f.store_content(f.pass_sig_path, example_password_signature)
        f.store_content(f.crypt_path, "anything value isn't checked")
        content = "abcdef"
        f.store_content(f.source_path, content)
        f.remove_source()
        self.assertFalse(f.exists(f.source_path))

    def test_safe_remove_source(self):
        f = FakeFiles("/a/b", "c", example_password)
        content = "abcdef"
        f.store_content(f.source_path, content)
        f.store_content(f.crypt_path, "anything value isn't checked")
        with self.assertRaises(OSError):
            f.remove_source()
        self.assertEqual(content, f.file_content(f.source_path))

    def test_remove_artifacts(self):
        f = FakeFiles("/a/b", "c", "password")
        content = "abcdef"
        f.store_content(f.crypt_path, content)
        f.store_content(f.source_path, content)
        f.remove_artifacts()
        self.assertFalse(f.exists(f.crypt_path))
        self.assertTrue(f.exists(f.source_path))

    def test_safe_remove_artifacts(self):
        f = FakeFiles("/a/b", "c", "password")
        content = "abcdef"
        f.store_content(f.crypt_path, content)
        with self.assertRaises(OSError):
            f.remove_artifacts()
        self.assertEqual(content, f.file_content(f.crypt_path))

def directory_to_dictionary(root_path):
    result = {}
    l_root = len(root_path)
    for (dirName, subdirList, fileList) in os.walk(root_path):
        for file_name in fileList:
            file_path = os.path.join(dirName, file_name)
            file_content = open(file_path, "rb").read()
            assert file_path[:l_root] == root_path
            file_path_suffix = file_path[l_root:]
            if file_path_suffix.startswith(os.path.sep):
                # trim off the path separator
                file_path_suffix = file_path_suffix[len(os.path.sep):]
            result[file_path_suffix] = file_content
    return result

def dictionary_to_directory(root_path, dictionary):
    assert not os.path.exists(root_path)
    for relative_file_path in dictionary:
        file_content = dictionary[relative_file_path]
        full_file_path = os.path.join(root_path, relative_file_path)
        (folder, _) = os.path.split(full_file_path)
        if not os.path.exists(folder):
            os.makedirs(folder)
        open(full_file_path, "wb").write(file_content)
    
def create_artifacts_dir():
    if not os.path.exists(artifacts_dir):
        os.mkdir(artifacts_dir)

def erase_artifacts_dir(path=artifacts_dir):
    if os.path.exists(path):
        shutil.rmtree(path)

class UseArtifactsDir(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        create_artifacts_dir()

    @classmethod
    def xxx_tearDownClass_disabled(cls):
        erase_artifacts_dir()

class TestTar(UseArtifactsDir):

    def test_helpers(self):
        D = {"a/b.bin": b"some binary content", "c/d.bin": b"more binary"}
        root_path = os.path.join(artifacts_dir, "helper_root")
        erase_artifacts_dir(root_path)
        dictionary_to_directory(root_path, D)
        D2 = directory_to_dictionary(root_path)
        self.assertEqual(D, D2, repr(D2))

    def test_roundtrip(self):
        D = {"a/b.bin": b"some binary content", "c/d.bin": b"more binary"}
        from_parent = "from_tar"
        to_parent = "to_tar"
        folder_name = "tar_folder"
        from_parent_path = os.path.join(artifacts_dir, from_parent)
        erase_artifacts_dir(from_parent_path)
        os.mkdir(from_parent_path)
        from_folder = os.path.join(from_parent_path, folder_name)
        dictionary_to_directory(from_folder, D)
        tarmaker = encrypting_tarball.Encryption(from_parent_path, folder_name, example_password)
        tarmaker.create_tarfile()
        to_parent_path = os.path.join(artifacts_dir, to_parent)
        erase_artifacts_dir(to_parent_path)
        os.mkdir(to_parent_path)
        untarmaker = encrypting_tarball.Encryption(to_parent_path, folder_name, example_password)
        shutil.copyfile(tarmaker.tar_path, untarmaker.tar_path)
        untarmaker.unpack_tarfile(delete_if_exists=True)
        to_path = os.path.join(to_parent_path, folder_name)
        D2 = directory_to_dictionary(to_path)
        self.assertEqual(D, D2, repr((D, D2)))

class TestEncrypt(UseArtifactsDir):

    def test_roundtrip(self):
        # set up the "from" directory
        D = {"a/b.bin": b"some binary content again", "c/d.bin": b"more binary again"}
        from_parent = "from_encrypt"
        to_parent = "to_encrypt"
        folder_name = "encrypt_folder"
        from_parent_path = os.path.join(artifacts_dir, from_parent)
        erase_artifacts_dir(from_parent_path)
        os.mkdir(from_parent_path)
        from_folder = os.path.join(from_parent_path, folder_name)
        dictionary_to_directory(from_folder, D)
        # encrypt the "from directory"
        encryptor = encrypting_tarball.Encryption(from_parent_path, folder_name, example_password)
        encryptor.encrypt(delete_source=True)
        # set up the "to" directory
        to_parent_path = os.path.join(artifacts_dir, to_parent)
        erase_artifacts_dir(to_parent_path)
        os.mkdir(to_parent_path)
        to_folder = os.path.join(to_parent_path, folder_name)
        # copy encryption related files to "to" directory
        decryptor = encrypting_tarball.Encryption(to_parent_path, folder_name, example_password)
        shutil.copyfile(encryptor.crypt_path, decryptor.crypt_path)
        shutil.copyfile(encryptor.signature_path, decryptor.signature_path)
        shutil.copyfile(encryptor.pass_sig_path, decryptor.pass_sig_path)
        # decrypt
        decryptor = encrypting_tarball.Encryption(to_parent_path, folder_name, example_password)
        decryptor.decrypt()
        # check the directories match
        D2 = directory_to_dictionary(to_folder)
        self.assertEqual(D, D2, repr((D, D2)))
