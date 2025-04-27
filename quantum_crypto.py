import numpy as np
from LDPC import LDPC
from McEliece import McEliece

def generate_quantum_key():
    n, d_v, d_c = 300, 6, 10
    ldpc = LDPC.from_params(n, d_v, d_c)
    crypto = McEliece.from_linear_code(ldpc, 12)
    binary_word = np.random.randint(2, size=ldpc.getG().shape[0])
    encrypted = crypto.encrypt(binary_word)
    decrypted = crypto.decrypt(encrypted)
    return bytes(decrypted)[:16]  # Truncate or pad if needed
