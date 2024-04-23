from blockchains import *
from tester import *
from cpu_e_consumo import *

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

print(40*"===")

for block in my_blockchain.chain:
    print("Index: " + str(block.index))
    print("Timestamp: " + str(block.timestamp))
    print("Data: " + str(block.data))
    print("Hash: " + str(block.hash))
    print("Previous Hash: " + str(block.previous_hash) + "\n")

print(40*"===")

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

print(40*"===")

# Teste de desempenho para Blockchain original
original_blockchain = Blockchain()
# Execute os testes várias vezes e tire a média
avg_original_transaction_time = sum(test_transaction_speed(original_blockchain) for _ in range(10)) / 10
avg_original_cpu_diff, avg_original_memory_diff = tuple(sum(x) / 10 for x in zip(*(test_resource_consumption(original_blockchain) for _ in range(10))))

# Teste de desempenho para o novo Blockchain
new_blockchain = newBlockchain()
# Execute os testes várias vezes e tire a média
avg_new_transaction_time = sum(test_transaction_speed(new_blockchain) for _ in range(10)) / 10
avg_new_cpu_diff, avg_new_memory_diff = tuple(sum(x) / 10 for x in zip(*(test_resource_consumption(new_blockchain) for _ in range(10))))

# Compare os resultados
print("Velocidade média de transação para Blockchain original:", avg_original_transaction_time)
print("Velocidade média de transação para o novo Blockchain:", avg_new_transaction_time)

print("Diferença média no uso de CPU para Blockchain original:", avg_original_cpu_diff)
print("Diferença média no uso de CPU para o novo Blockchain:", avg_new_cpu_diff)

print("Diferença média no uso de memória para Blockchain original:", avg_original_memory_diff)
print("Diferença média no uso de memória para o novo Blockchain:", avg_new_memory_diff)