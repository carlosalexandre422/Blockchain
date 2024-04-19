import hashlib
import datetime as date
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

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

# Criação da chave privada e pública para assinatura digital
private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
public_key = private_key.public_key()

# Conversão das chaves para formato PEM para armazenamento seguro
private_key_pem = private_key.private_bytes(encoding=serialization.Encoding.PEM,
                                             format=serialization.PrivateFormat.PKCS8,
                                             encryption_algorithm=serialization.NoEncryption())
public_key_pem = public_key.public_bytes(encoding=serialization.Encoding.PEM,
                                         format=serialization.PublicFormat.SubjectPublicKeyInfo)

# Conversão das chaves de volta para objetos para uso posterior
private_key = serialization.load_pem_private_key(private_key_pem, password=None, backend=default_backend())
public_key = serialization.load_pem_public_key(public_key_pem, backend=default_backend())

my_blockchain = Blockchain()

compra1 = Transaction('Ford Mustang', 15000, 'João', 'Maria')
doc = Transaction('Documento', 1000, 'Maria', 'João')

# Assinando as transações com a chave privada
signature_compra1 = compra1.sign_transaction(private_key)
signature_doc = doc.sign_transaction(private_key)

# Serializando as transações para inclusão no bloco
serialized_compra1 = compra1.serialize_transaction()
serialized_doc = doc.serialize_transaction()

# Criptografando dados sensíveis nas transações
key = os.urandom(32)  # Chave de 256 bits para AES

encrypted_data_compra1 = compra1.encrypt_sensitive_data(key)
encrypted_data_doc = doc.encrypt_sensitive_data(key)

# Adicionando blocos com transações ao blockchain
my_blockchain.add_block(Block(1, date.datetime.now(), {'transaction': serialized_compra1, 'signature': signature_compra1}, my_blockchain.get_latest_block().hash))
my_blockchain.add_block(Block(2, date.datetime.now(), {'transaction': serialized_doc, 'signature': signature_doc}, my_blockchain.get_latest_block().hash))

for block in my_blockchain.chain:
    print("Index: " + str(block.index))
    print("Timestamp: " + str(block.timestamp))
    print("Data: " + str(block.data))
    print("Hash: " + str(block.hash))
    print("Previous Hash: " + str(block.previous_hash) + "\n")
import hashlib
import datetime as date
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

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
    
class BlockchainTester:
    @staticmethod
    def test_blockchain_integrity(blockchain):
        for i in range(1, len(blockchain.chain)):
            current_block = blockchain.chain[i]
            previous_block = blockchain.chain[i - 1]

            # Verifica se o hash do bloco está correto
            if current_block.hash != current_block.calculate_hash():
                return False

            # Verifica se o hash anterior está corretamente ligado
            if current_block.previous_hash != previous_block.hash:
                return False

        return True

    @staticmethod
    def test_hash_attack(blockchain, modified_block):
        # Modifica os dados do bloco
        modified_block.data = "Dados maliciosos"

        # Recalcula o hash do bloco modificado
        modified_block.hash = modified_block.calculate_hash()

        # Tenta inserir o bloco modificado na cadeia
        blockchain.add_block(modified_block)

        # Verifica se a cadeia ainda é válida após a modificação
        return BlockchainTester.test_blockchain_integrity(blockchain)

    @staticmethod
    def test_transaction_authentication(transaction, public_key):
        serialized_data = str(transaction.item) + str(transaction.value) + str(transaction.buyer) + str(transaction.seller)
        try:
            public_key.verify(transaction.signature, serialized_data.encode(), ec.ECDSA(hashes.SHA256()))
            return True
        except Exception as e:
            print("Erro ao verificar a assinatura:", e)
            return False

    @staticmethod
    def test_symmetric_encryption_decryption(transaction, key):
        encrypted_data = transaction.encrypt_sensitive_data(key)
        decrypted_data = Transaction.decrypt_sensitive_data(encrypted_data, key)
        return decrypted_data == transaction.serialize_transaction()

    @staticmethod
    def test_transaction_authentication(transaction, public_key):
        return transaction.verify_transaction(public_key)

    @staticmethod
    def test_symmetric_encryption_decryption(transaction, key):
        encrypted_data = transaction.encrypt_sensitive_data(key)
        decrypted_data = Transaction.decrypt_sensitive_data(encrypted_data, key)
        return decrypted_data == transaction.serialize_transaction()

# Criação da chave privada e pública para assinatura digital
private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
public_key = private_key.public_key()

# Conversão das chaves para formato PEM para armazenamento seguro
private_key_pem = private_key.private_bytes(encoding=serialization.Encoding.PEM,
                                             format=serialization.PrivateFormat.PKCS8,
                                             encryption_algorithm=serialization.NoEncryption())
public_key_pem = public_key.public_bytes(encoding=serialization.Encoding.PEM,
                                         format=serialization.PublicFormat.SubjectPublicKeyInfo)

# Conversão das chaves de volta para objetos para uso posterior
private_key = serialization.load_pem_private_key(private_key_pem, password=None, backend=default_backend())
public_key = serialization.load_pem_public_key(public_key_pem, backend=default_backend())

my_blockchain = Blockchain()

compra1 = Transaction('Ford Mustang', 15000, 'João', 'Maria')
doc = Transaction('Documento', 1000, 'Maria', 'João')

# Assinando as transações com a chave privada
signature_compra1 = compra1.sign_transaction(private_key)
signature_doc = doc.sign_transaction(private_key)

# Serializando as transações para inclusão no bloco
serialized_compra1 = compra1.serialize_transaction()
serialized_doc = doc.serialize_transaction()

# Criptografando dados sensíveis nas transações
key = os.urandom(32)  # Chave de 256 bits para AES

encrypted_data_compra1 = compra1.encrypt_sensitive_data(key)
encrypted_data_doc = doc.encrypt_sensitive_data(key)

# Adicionando blocos com transações ao blockchain
my_blockchain.add_block(Block(1, date.datetime.now(), {'transaction': serialized_compra1, 'signature': signature_compra1}, my_blockchain.get_latest_block().hash))
my_blockchain.add_block(Block(2, date.datetime.now(), {'transaction': serialized_doc, 'signature': signature_doc}, my_blockchain.get_latest_block().hash))

for block in my_blockchain.chain:
    print("Index: " + str(block.index))
    print("Timestamp: " + str(block.timestamp))
    print("Data: " + str(block.data))
    print("Hash: " + str(block.hash))
    print("Previous Hash: " + str(block.previous_hash) + "\n")


# Exemplo de uso:

key = os.urandom(32)  # Chave de 256 bits para AES

if BlockchainTester.test_blockchain_integrity(my_blockchain):
    print("Teste de integridade da cadeia de blocos passou.")
else:
    print("Teste de integridade da cadeia de blocos falhou.")

modified_block = Block(1, date.datetime.now(), "Dados modificados", my_blockchain.get_latest_block().hash)
if BlockchainTester.test_hash_attack(my_blockchain, modified_block):
    print("Teste de resistência a ataques de hash passou.")
else:
    print("Teste de resistência a ataques de hash falhou.")

signature = compra1.sign_transaction(private_key)
if BlockchainTester.test_transaction_authentication(compra1, public_key):
    print("Teste de autenticidade da transação passou.")
else:
    print("Teste de autenticidade da transação falhou.")

if BlockchainTester.test_symmetric_encryption_decryption(compra1, key):
    print("Teste de criptografia simétrica passou.")
else:
    print("Teste de criptografia simétrica falhou.")
