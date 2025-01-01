import os
import sys
from PyQt5.QtWidgets import (QApplication, QMainWindow, QLabel, QVBoxLayout,
                             QLineEdit, QPushButton, QTextEdit, QFileDialog, QWidget, QMessageBox, QInputDialog)
from PyQt5.QtCore import Qt
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from Crypto.Hash import HMAC, SHA256
import base64
import hashlib

class BeyondDeceptionGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.keys_folder = "keys"
        self.files_folder = "files"
        self.init_folders()
        self.initUI()

    def init_folders(self):
        """Ensure the keys and files folders exist."""
        os.makedirs(self.keys_folder, exist_ok=True)
        os.makedirs(self.files_folder, exist_ok=True)

    def initUI(self):
        self.setWindowTitle("Beyond Deception")
        self.setGeometry(100, 100, 800, 600)

        # Main widget and layout
        self.centralWidget = QWidget()
        self.setCentralWidget(self.centralWidget)
        self.layout = QVBoxLayout(self.centralWidget)

        # Labels and Text Inputs
        self.label = QLabel("Enter your intentions, reasoning, and action path:")
        self.layout.addWidget(self.label)

        self.inputField = QTextEdit()
        self.inputField.setFixedHeight(300)
        self.inputField.setVerticalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        self.inputField.setPlainText("""
Intention:

Reasoning:

Action Path:
""")
        self.layout.addWidget(self.inputField)

        # Encrypt Button
        self.encryptButton = QPushButton("Encrypt and Save")
        self.encryptButton.clicked.connect(self.encryptAndSave)
        self.layout.addWidget(self.encryptButton)

        # Decrypt Button
        self.decryptButton = QPushButton("Load and Decrypt")
        self.decryptButton.clicked.connect(self.loadAndDecrypt)
        self.layout.addWidget(self.decryptButton)

        # Quit Button
        self.quitButton = QPushButton("Quit")
        self.quitButton.clicked.connect(self.forceQuitApplication)
        self.layout.addWidget(self.quitButton)

        # Output Field
        self.outputField = QTextEdit()
        self.outputField.setReadOnly(True)
        self.outputField.setFixedHeight(200)
        self.outputField.setVerticalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        self.layout.addWidget(self.outputField)

    def encryptAndSave(self):
        plaintext = self.inputField.toPlainText()
        if not plaintext.strip():
            QMessageBox.warning(self, "Input Error", "Please enter some text to encrypt.")
            return

        # Prompt for a passphrase
        passphrase, ok = QInputDialog.getText(self, "Key Passphrase", "Enter a passphrase for key encryption:", echo=QLineEdit.Password)
        if not ok or not passphrase.strip():
            QMessageBox.warning(self, "Passphrase Error", "Passphrase is required to secure the key.")
            return

        # Generate a key for this file
        key = get_random_bytes(32)
        iv = get_random_bytes(16)  # Initialization vector

        # Encrypt the text
        cipher = AES.new(key, AES.MODE_CBC, iv)
        ciphertext = cipher.encrypt(pad(plaintext.encode(), AES.block_size))

        # Compute HMAC for integrity
        hmac = HMAC.new(key, digestmod=SHA256)
        hmac.update(ciphertext)
        mac = hmac.digest()

        encrypted_data = base64.b64encode(iv + ciphertext + mac).decode()

        # Prompt user for file name
        options = QFileDialog.Options()
        file_name, _ = QFileDialog.getSaveFileName(self, "Save Encrypted File", self.files_folder, "Text Files (*.txt)", options=options)
        if file_name:
            with open(file_name, "w") as file:
                file.write(encrypted_data)

            # Encrypt and save the key
            key_file_name = os.path.join(self.keys_folder, os.path.basename(file_name) + "_key")
            key_encryption = hashlib.pbkdf2_hmac('sha256', passphrase.encode(), b'salt', 100000)
            encrypted_key = AES.new(key_encryption, AES.MODE_ECB).encrypt(pad(key, AES.block_size))
            with open(key_file_name, "wb") as key_file:
                key_file.write(encrypted_key)

            QMessageBox.information(self, "Success", f"Encrypted data saved as {file_name} and its key stored securely in {key_file_name}.")

    def loadAndDecrypt(self):
        # Load encrypted file
        options = QFileDialog.Options()
        file_name, _ = QFileDialog.getOpenFileName(self, "Open Encrypted File", self.files_folder, "Text Files (*.txt)", options=options)
        if not file_name:
            return

        # Load corresponding key
        key_file_name = os.path.join(self.keys_folder, os.path.basename(file_name) + "_key")
        if not os.path.exists(key_file_name):
            QMessageBox.critical(self, "Key Error", f"Key file not found for {file_name}. Ensure the key exists in the keys folder.")
            return

        # Prompt for passphrase
        passphrase, ok = QInputDialog.getText(self, "Key Passphrase", "Enter the passphrase for key decryption:", echo=QLineEdit.Password)
        if not ok or not passphrase.strip():
            QMessageBox.warning(self, "Passphrase Error", "Passphrase is required to decrypt the key.")
            return

        try:
            with open(file_name, "r") as file:
                encrypted_data = base64.b64decode(file.read())

            with open(key_file_name, "rb") as key_file:
                encrypted_key = key_file.read()

            # Decrypt the key
            key_encryption = hashlib.pbkdf2_hmac('sha256', passphrase.encode(), b'salt', 100000)
            key = unpad(AES.new(key_encryption, AES.MODE_ECB).decrypt(encrypted_key), AES.block_size)

            # Extract IV, ciphertext, and HMAC
            iv, ciphertext, mac = encrypted_data[:16], encrypted_data[16:-32], encrypted_data[-32:]

            # Verify HMAC
            hmac = HMAC.new(key, digestmod=SHA256)
            hmac.update(ciphertext)
            hmac.verify(mac)

            # Decrypt the text
            cipher = AES.new(key, AES.MODE_CBC, iv)
            plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size).decode()

            self.outputField.setPlainText(plaintext)
            QMessageBox.information(self, "Success", "Decrypted successfully. The original intentions and reasoning are now legible.")
        except Exception as e:
            QMessageBox.critical(self, "Decryption Error", f"Decryption failed: {str(e)}. Ensure the encrypted file, key, and passphrase are correct.")

    def forceQuitApplication(self):
        QMessageBox.information(self, "Exiting", "Thank you for using Beyond Deception. Goodbye!")
        sys.exit(0)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    mainWindow = BeyondDeceptionGUI()
    mainWindow.show()
    sys.exit(app.exec_())


