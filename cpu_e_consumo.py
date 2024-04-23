from blockchains import *
import time
import psutil  

# Função para medir o tempo de adição de um bloco à blockchain
def test_transaction_speed(blockchain):
    start_time = time.time()
    # Adiciona um bloco à blockchain
    index = len(blockchain.chain)  # Definição da variável index
    blockchain.add_block(Block(index, date.datetime.now(), "Data", blockchain.get_latest_block().hash))
    end_time = time.time()
    return end_time - start_time

# Função para medir o consumo de recursos
def test_resource_consumption(blockchain):
    # Monitora o uso de CPU e memória antes de adicionar um bloco
    cpu_usage_before = psutil.cpu_percent()
    memory_usage_before = psutil.virtual_memory().used
    
    # Adiciona um bloco à blockchain
    index = len(blockchain.chain)  # Definição da variável index
    blockchain.add_block(Block(index, date.datetime.now(), "Data", blockchain.get_latest_block().hash))
    
    # Monitora o uso de CPU e memória depois de adicionar um bloco
    cpu_usage_after = psutil.cpu_percent()
    memory_usage_after = psutil.virtual_memory().used
    
    # Calcula a diferença de uso de CPU e memória
    cpu_diff = cpu_usage_after - cpu_usage_before
    memory_diff = memory_usage_after - memory_usage_before
    
    return cpu_diff, memory_diff
