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
        decrypted_data = transaction.decrypt_sensitive_data(encrypted_data, key)
        return decrypted_data == transaction.serialize_transaction()

    @staticmethod
    def test_transaction_authentication(transaction, public_key):
        return transaction.verify_transaction(public_key)

    @staticmethod
    def test_symmetric_encryption_decryption(transaction, key):
        encrypted_data = transaction.encrypt_sensitive_data(key)
        decrypted_data = transaction.decrypt_sensitive_data(encrypted_data, key)
        return decrypted_data == transaction.serialize_transaction()
