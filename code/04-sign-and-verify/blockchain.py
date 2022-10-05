import hashlib, json, copy, time
import bitcoinlib

DIFFICULTY = 4 # Quantidade de zeros (em hex) iniciais no hash valido.

class Blockchain(object):
    '''Classe utilizada para representar um blockchain privado baseado no protocolo Bitcoin.'''

    def __init__(self):
        self.chain = []
        self.memPool = []
        self.createGenesisBlock()

    def createGenesisBlock(self):
        '''Cria, minera e retorna o bloco gênesis do blockchain. Chamado somente no construtor.'''
        genesis_block = self.createBlock()
        self.mineProofOfWork(self.prevBlock)
        return genesis_block

    def createBlock(self):
        '''Cria um novo bloco, inclui todas as transações pendentes e adiciona ao chain. O bloco ainda não tem nonce válido.'''
        block = {
            'index': len(self.chain),
            'timestamp': int(time.time()),
            'transactions': self.memPool,
            'merkleRoot': '0'*64,
            'nonce': 0,
            'previousHash': self.getBlockID(self.chain[-1]) if (len(self.chain)) else '0'*64
        }
        self.memPool = []
        self.chain.append(block)
        return block

    def mineProofOfWork(self, block):
        '''Retorna um nonce válido para o bloco passado como argumento.'''
        nonce = 0
        while (Blockchain.isValidProof(block, nonce) is False):
            nonce += 1
        return nonce

    @staticmethod
    def isValidProof(block, nonce):
        '''Retorna `True` caso o nonce passado como argumento seja válido para o block passado como argumento, `False` caso contrário.'''
        block['nonce'] = nonce
        return Blockchain.getBlockID(block)[:DIFFICULTY] == '0'*DIFFICULTY

    @staticmethod
    def generateHash(data):
        '''Retorna a hash SHA256 dos dados passados como argumento.'''
        blkSerial = json.dumps(data, sort_keys=True).encode()
        return hashlib.sha256(blkSerial).hexdigest()

    @staticmethod
    def getBlockID(block):
        '''Retorna o ID do bloco passado como argumento. O ID de um bloco é o hash do seu cabeçalho.'''
        blockCopy = copy.copy(block)
        blockCopy.pop("transactions", None)
        return Blockchain.generateHash(blockCopy)

    def printChain(self):
        pass # Mantenha seu método de impressão do blockchain feito nas práticas passadas.

    @property
    def prevBlock(self):
        '''Retorna o último bloco da chain.'''
        return self.chain[-1]

    @staticmethod
    def getWifCompressedPrivateKey(private_key=None):
        '''Retorna a chave privada no formato WIF-compressed da chave privada hex.'''
        if private_key is None:
            private_key = bitcoinlib.random_key()
        return bitcoinlib.encode_privkey(bitcoinlib.decode_privkey((private_key + '01'), 'hex'), 'wif')
        
    @staticmethod
    def getBitcoinAddressFromWifCompressed(wif_pkey):
        '''Retorna o endereço Bitcoin da chave privada WIF-compressed.'''
        return bitcoinlib.pubkey_to_address(bitcoinlib.privkey_to_pubkey(wif_pkey))

    @staticmethod
    def sign(wifCompressedPrivKey, message):
        '''Retorna a assinatura digital da mensagem e a respectiva chave privada WIF-compressed.'''
        return bitcoinlib.ecdsa_sign(message, wifCompressedPrivKey)

    @staticmethod
    def verifySignature(address, signature, message):
        '''Verifica se a assinatura é correspondente a mensagem e o endereço BTC.
        Você pode verificar aqui também: https://www.bitcoin.com/tools/verify-message/'''
        return bitcoinlib.ecdsa_verify(message, signature, address)


# Teste
# Fique a vontade para criar outra chave privada aleatória
# Você pode usar o método getBitcoinAddressFromWifCompressed() para pegar o endereço WIF a partir da chave privada
# Ou use um gerador de chaves/endereços. Ex: https://www.bitaddress.org/

addr = '19sXoSbfcQD9K66f5hwP5vLwsaRyKLPgXF'
privKey = 'L1US57sChKZeyXrev9q7tFm2dgA2ktJe2NP3xzXRv6wizom5MN1U'
message = 'Bora assinar essa mensagem?'

signature = Blockchain.sign(privKey, message)

print('Mensagem: {}'.format(message))
print('Endereço BTC: {}'.format(addr))
print('Assinatura gerada: {}'.format(signature))
print('Assinatura válida para mensagem e endereço indicado? {}'.format(Blockchain.verifySignature(addr, signature, message)))
