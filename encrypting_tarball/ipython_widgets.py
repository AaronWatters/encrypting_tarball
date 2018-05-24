

from encrypting_tarball import Encryption
from IPython.display import display

def decrypt_widget(parent_path, folder_name):
    import ipywidgets as widgets
    decrypt_button = widgets.Button(description="decrypt")
    key_text_area = widgets.Password(description="password")
    out = widgets.Output()
    def do_decrypt(*args):
        with out:
            key = key_text_area.value
            decryptor = Encryption(parent_path, folder_name, key)
            print("now decrypting " + repr(decryptor.crypt_path))
            decryptor.decrypt()
            print("decryption complete.")
    decrypt_button.on_click(do_decrypt)
    assembly = widgets.VBox(children=[decrypt_button, key_text_area])
    display(assembly)
    with out:
        print "Please provide password and press the decrypt button to decrypt the data."
