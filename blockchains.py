import hashlib
import datetime as date
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

import time
import psutil  


class Block:
    def __init__(self, index, timestamp, data, previous_hash):
        self.index = index
        self.timestamp = timestamp
        self.data = data
        self.previous_hash = previous_hash
        self.hash = self.calculate_hash()

    def calculate_hash(self):
        sha3 = hashlib.sha3_256()
        sha3.update(str(self.index).encode('utf-8') +
                   str(self.timestamp).encode('utf-8') +
                   str(self.data).encode('utf-8') +
                   str(self.previous_hash).encode('utf-8'))
        return sha3.hexdigest()
    
class newBlockchain:
    def __init__(self):
        self.chain = [self.create_genesis_block()]

    def create_genesis_block(self):
        return Block(0, date.datetime.now(), "Genesis Block", "0")

    def get_latest_block(self):
        return self.chain[-1]

    def add_block(self, new_block):
        new_block.previous_hash = self.get_latest_block().hash
        new_block.hash = new_block.calculate_hash()
        self.chain.append(new_block)

    def is_chain_valid(self):
        for i in range(1, len(self.chain)):
            current_block = self.chain[i]
            previous_block = self.chain[i - 1]

            if current_block.hash != current_block.calculate_hash():
                return False

            if current_block.previous_hash != previous_block.hash:
                return False

        return True


class Transaction:
    def __init__(self, item, value, buyer, seller):
        self.item = item
        self.value = value
        self.buyer = buyer
        self.seller = seller

    def sign_transaction(self, private_key):
        serialized_data = str(self.item) + str(self.value) + str(self.buyer) + str(self.seller)
        signature = private_key.sign(serialized_data.encode(), ec.ECDSA(hashes.SHA256()))
        return signature

    def serialize_transaction(self):
        return {
            'item': self.item,
            'value': self.value,
            'buyer': self.buyer,
            'seller': self.seller
        }

    def encrypt_sensitive_data(self, key):
        cipher = Cipher(algorithms.AES(key), modes.CFB(os.urandom(16)))
        encryptor = cipher.encryptor()
        padder = padding.PKCS7(128).padder()
        serialized_data = str(self.item) + str(self.value) + str(self.buyer) + str(self.seller)
        padded_data = padder.update(serialized_data.encode()) + padder.finalize()
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
        return encrypted_data

    @staticmethod
    def decrypt_sensitive_data(encrypted_data, key):
        cipher = Cipher(algorithms.AES(key), modes.CFB(os.urandom(16)))
        decryptor = cipher.decryptor()
        unpadder = padding.PKCS7(128).unpadder()
        decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
        unpadded_data = unpadder.update(decrypted_data) + unpadder.finalize()
        return unpadded_data
    
class Block:
    def __init__(self, index, timestamp, data, previous_hash):
        self.index = index
        self.timestamp = timestamp
        self.data = data
        self.previous_hash = previous_hash
        self.hash = self.calculate_hash()

    def calculate_hash(self):
        sha = hashlib.sha256()
        sha.update(str(self.index).encode('utf-8') +
                   str(self.timestamp).encode('utf-8') +
                   str(self.data).encode('utf-8') +
                   str(self.previous_hash).encode('utf-8'))
        return sha.hexdigest()
    
class Blockchain:
    def __init__(self):
        self.chain = [self.create_genesis_block()]

    def create_genesis_block(self):
        return Block(0, date.datetime.now(), "Genesis Block", "0")

    def get_latest_block(self):
        return self.chain[-1]

    def add_block(self, new_block):
        new_block.previous_hash = self.get_latest_block().hash
        new_block.hash = new_block.calculate_hash()
        self.chain.append(new_block)

    def is_chain_valid(self):
        for i in range(1, len(self.chain)):
            current_block = self.chain[i]
            previous_block = self.chain[i - 1]

            if current_block.hash != current_block.calculate_hash():
                return False

            if current_block.previous_hash != previous_block.hash:
                return False

        return True

class Transaction:
    def __init__(self, item, value, buyer, seller):
        self.item = item
        self.value = value
        self.buyer = buyer
        self.seller = seller
        self.signature = None  # Adicionando atributo signature à transação

    def sign_transaction(self, private_key):
        serialized_data = str(self.item) + str(self.value) + str(self.buyer) + str(self.seller)
        self.signature = private_key.sign(serialized_data.encode(), ec.ECDSA(hashes.SHA256()))
        return self.signature

    def verify_transaction(self, public_key):
        serialized_data = str(self.item) + str(self.value) + str(self.buyer) + str(self.seller)
        try:
            public_key.verify(self.signature, serialized_data.encode(), ec.ECDSA(hashes.SHA256()))
            return True
        except Exception as e:
            print("Erro ao verificar a assinatura:", e)
            return False

    def serialize_transaction(self):
        return {
            'item': self.item,
            'value': self.value,
            'buyer': self.buyer,
            'seller': self.seller,
            'signature': self.signature  # Incluindo a assinatura na serialização da transação
        }

    def encrypt_sensitive_data(self, key):
        cipher = Cipher(algorithms.AES(key), modes.CFB(os.urandom(16)))
        encryptor = cipher.encryptor()
        padder = padding.PKCS7(128).padder()
        serialized_data = str(self.item) + str(self.value) + str(self.buyer) + str(self.seller)
        padded_data = padder.update(serialized_data.encode()) + padder.finalize()
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
        return encrypted_data

    @staticmethod
    def decrypt_sensitive_data(encrypted_data, key):
        cipher = Cipher(algorithms.AES(key), modes.CFB(os.urandom(16)))
        decryptor = cipher.decryptor()
        unpadder = padding.PKCS7(128).unpadder()
        decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
        unpadded_data = unpadder.update(decrypted_data) + unpadder.finalize()
        return unpadded_data