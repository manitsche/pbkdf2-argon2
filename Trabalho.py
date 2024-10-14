# Alunos: Katley e Marco Antonio - 3º TADS

import secrets  # Módulo para gerar valores aleatórios seguros (ex. salt)
import hashlib  # Módulo para implementar algoritmos de hash, incluindo PBKDF2
from argon2 import PasswordHasher  # Biblioteca externa para Argon2, usada para hashing de senhas

# Classe responsável por operações com PBKDF2
class Pbkdf:
    @staticmethod
    def encrypt(senha) -> tuple:
        
        """
        Recebe uma senha e retorna uma tupla contendo o hash da senha e o salt usado.
        Utiliza o algoritmo PBKDF2 com HMAC-SHA256.
        """
        
        salt = secrets.token_bytes(16)  # Gera um salt aleatório de 16 bytes
        hash_senha = hashlib.pbkdf2_hmac(
            'sha256',       # Algoritmo hash HMAC-SHA256
            senha.encode(), # Converte a senha para bytes
            salt,           # Usa o salt gerado
            500             # Número de iterações (quanto maior, mais seguro, mas mais lento)
        )
        
        return (hash_senha, salt)  # Retorna o hash e o salt como uma tupla

    @staticmethod
    def verify_password(senha, hash_senha, salt) -> bool:
       
        """
        Verifica se a senha fornecida corresponde ao hash armazenado.
        Recalcula o hash com a senha fornecida e compara com o hash armazenado.
         """
        
        hash_verification = hashlib.pbkdf2_hmac(
            'sha256',       # Algoritmo hash HMAC-SHA256
            senha.encode(), # Converte a senha fornecida para bytes
            salt,           # Usa o mesmo salt que foi usado na geração original do hash
            500             # Mesmo número de iterações
        )
        return hash_verification == hash_senha  # Retorna True se os hashes coincidirem


# Classe responsável por operações com Argon2
class Argon:
    @staticmethod
    def encrypt(senha):
        
        """
        Recebe uma senha e retorna o hash utilizando o Argon2.
        Argon2 é um algoritmo de hashing de senhas resistente a ataques por GPU.
        """
        
        ph = PasswordHasher()  # Cria uma instância do Argon2 PasswordHasher
        return ph.hash(senha)  # Gera o hash da senha e retorna

    @staticmethod
    def verify_password(hash_senha, senha):
        
        """
        Verifica se a senha fornecida corresponde ao hash Argon2 armazenado.
        """

        ph = PasswordHasher()  # Cria uma instância do Argon2 PasswordHasher
        
        try:
            ph.verify(hash_senha, senha)  # Tenta verificar o hash com a senha fornecida
            return True  # Se não houver exceções, retorna True
        except:  # Se ocorrer qualquer exceção (ex. senha incorreta), retorna False
            return False

# Simulando a criação de usuários com senhas criptografadas usando PBKDF2

users_salvos = {
    "joao": Pbkdf.encrypt("1234"),  # João tem a senha "1234", que é hashada usando PBKDF2
    "maria": Pbkdf.encrypt("abcd"), # Maria tem a senha "abcd"
    "pedro": Pbkdf.encrypt("4321"), # Pedro tem a senha "4321"
    "ana": Pbkdf.encrypt("qwer"),   # Ana tem a senha "qwer"
    "paula": Pbkdf.encrypt("asdf")  # Paula tem a senha "asdf"
}

# Exibindo as senhas criptografadas com PBKDF2 (hash e salt em hexadecimal)

print("Senhas em PBKDF2:")
pbkdf_senhas = {
    usuario: (hash_senha.hex(), salt.hex())  # Converte os valores binários (hash e salt) para hexadecimal
    for usuario, (hash_senha, salt) in users_salvos.items()
}

for usuario, (hash_senha, salt) in pbkdf_senhas.items():
    print(f"Usuário: {usuario}, Hash: {hash_senha}, Salt: {salt}")  # Exibe o hash e o salt de cada usuário

# Simulando a migração das senhas para Argon2

argon_senhas = {
    usuario: Argon.encrypt(senha)  # Criptografa a senha original de cada usuário usando Argon2
    for usuario, senha in {
        "joao": "1234",  # João tem a senha original "1234"
        "maria": "abcd", # Maria tem a senha original "abcd"
        "pedro": "4321", # Pedro tem a senha original "4321"
        "ana": "qwer",   # Ana tem a senha original "qwer"
        "paula": "asdf"  # Paula tem a senha original "asdf"
    }.items()
}

# Exibindo as senhas criptografadas com Argon2
print("\nSenhas em Argon2:")
for usuario, hash_senha in argon_senhas.items():
    print(f"Usuário: {usuario}, Hash: {hash_senha}")  # Exibe o hash de cada usuário em Argon2