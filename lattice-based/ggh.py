from sage.all import matrix, vector, det
from utils import read_vector_from_file, write_vector_to_file
import secrets as sec
import math
import sys

def ggh_write_key_to_file(key: matrix, filename: str, public: bool) -> None:
    """
    Write a matrix key to a file.

    Parameters:
        key (Matrix): The matrix key to write.
        filename (str): The name of the file to write the key to.
        public (bool): Whether the key is a public key or private key.
    """
    
    # Append the extension based on key type
    if public:
        filename += '.pub'
    
    # Write the matrix to the file
    with open(filename, 'wb') as f:
        
        # Write the dimensions of the matrix
        f.write(int(key.nrows()).to_bytes(4, byteorder='little', signed=True))
        
        # Iterate through the rows of the matrix
        for i in range(key.nrows()):
            
            # Iterate through each value in the row
            for j in range(key.ncols()):
                
                # Write the value to the file
                f.write(int(key[i][j]).to_bytes(4, byteorder='little', signed=True))

def ggh_read_key_from_file(filename: str) -> matrix:
    """
    Read a matrix key from a file.

    Parameters:
        filename (str): The name of the file to read the key from.

    Returns:
        Matrix: The matrix key read from the file.
    """
    
    # Open the file for reading
    with open(filename, 'rb') as f:
        
        # Read the dimension of the matrix
        n = int.from_bytes(f.read(4), byteorder='little', signed=True)
        
        # Initialize an empty matrix
        m = []
        
        # Fill the matrix with values from the file
        for i in range(n):
            
            # Initialize an empty row
            row = []
            
            # Iterate through each value in the row
            for j in range(n):
                row.append(int.from_bytes(f.read(4), byteorder='little', signed=True))

            # Append the row to the matrix
            m.append(row)
            
    # Return the matrix key
    return matrix(m)

def ggh_hadamard_ratio(B: matrix) -> float:
    """
    Calculate the Hadamard ratio of a basis matrix.

    Parameters:
        B (Matrix): The basis matrix.

    Returns:
        float: The Hadamard ratio.
    """
    
    # Get the dimension of the basis
    n = B.nrows()
    
    # Compute the determinant of B
    det_b = det(B)

    # Compute the norms of the basis vectors
    norm_product = 1
    
    for i in range(n):
        norm_product *= B[i].norm()
        
    # Compute the Hadamard ratio
    hadamard_ratio = (abs(det_b) / norm_product) ** (1/n)
    
    # Return the Hadamard ratio
    return hadamard_ratio

def ggh_generate_private_key(n: int, l: int = 4, threshold: float = 0.75) -> matrix:
    """
    Generate a private key matrix for the GGH cryptosystem.

    Parameters:
        n (int): Dimension of the lattice.
        l (int): Number of bits for the entries in the basis vectors.
        threshold (float): Threshold for the orthogonality defect.

    Returns:
        Matrix: A private key matrix with the specified properties.
    """
    
    # Generate a random integer matrix
    R = matrix(n, [[sec.choice(range(-l, l+1)) for _ in range(n)] for _ in range(n)])
    
    # Generate the identity matrix
    I = matrix.identity(n)
    
    # Compute a multiplier K
    k = math.ceil(math.sqrt(n)) * l
    
    # Compute the generated basis matrix B
    B = k * I + R
    
    # Compute the Hadamard ratio
    hadamard_ratio = ggh_hadamard_ratio(B)
    
    # Check if the Hadamard ratio meets the threshold
    if hadamard_ratio < threshold:
        return ggh_generate_private_key(n, l, threshold)
    
    # Return the valid basis matrix
    return B

def ggh_generate_public_key(private_key: matrix) -> matrix:
    """
    Generate a public key matrix for the GGH cryptosystem from a private key.

    Parameters:
        private_key (Matrix): The private key matrix.

    Returns:
        Matrix: The public key matrix in Hermite Normal Form.
    """
    
    # Generate the hermite normal form of the private key
    return private_key.hermite_form()

def ggh_encrypt(public_key: matrix, r: vector) -> vector:
    """
    Encrypt a message vector using the GGH public key.

    Parameters:
        public_key (Matrix): The public key matrix.
        r (Vector): The message vector to encrypt.

    Returns:
        Vector: The encrypted message vector.
    """
    
    # Generate the cryptogram vector
    for i in range(len(r)):
        r = r - (r[i] // public_key[i][i]) * public_key[i]

    # Return the encrypted vector
    return r

def ggh_decrypt(private_key: matrix, c: vector) -> vector:
    """
    Decrypt a cryptogram vector using the GGH private key.

    Parameters:
        private_key (Matrix): The private key matrix.
        c (Vector): The encrypted message vector.

    Returns:
        Vector: The decrypted message vector.
    """
    
    # Calculate the inverse of the private key
    private_key_inv = private_key.inverse()
    
    # Calculate the first step of decryption
    cb = c * private_key_inv
    
    # Round the entries to the nearest integers
    cb = vector([round(cb[i]) for i in range(len(cb))])
    
    # Calculate the closest lattice vector
    v = cb * private_key
    
    # Calculate the decrypted vector
    r = c - v
    
    # Return the decrypted vector
    return r

def ggh_generate_secret_vector(n: int, l: int = 2) -> vector:
    """
    Generate a random secret vector for the GGH cryptosystem.

    Parameters:
        n (int): Dimension of the vector.
        l (int): Range limit for the vector entries.

    Returns:
        Vector: A random secret vector.
    """
    
    # Generate a random vector
    r = vector([sec.choice(range(0, l+1)) for _ in range(n)])
    
    # Return the secret vector
    return r

def ggh_generate_key_pair(n: int, l: int = 4, threshold: float = 0.75) -> tuple:
    """
    Generate a GGH key pair (private and public keys).

    Parameters:
        n (int): Dimension of the lattice.
        l (int): Number of bits for the entries in the basis vectors.
        threshold (float): Threshold for the orthogonality defect.

    Returns:
        tuple: A tuple containing the private key matrix and public key matrix.
    """
    
    # Generate the private key
    private_key = ggh_generate_private_key(n, l, threshold)
    
    # Generate the public key from the private key
    public_key = ggh_generate_public_key(private_key)
    
    # Return the key pair
    return private_key, public_key

if __name__ == "__main__":
    
    if (len(sys.argv) < 4):
        print("Usage:")
        print(" : key-gen -> python3 ggh.py key-gen <dimension> <keyname>")
        print(" : vector-gen -> python3 ggh.py vector-gen <dimension> <vectorname>")
        print(" : encrypt -> python3 ggh.py encrypt <keyname> <vectorname>")
        print(" : decrypt -> python3 ggh.py decrypt <keyname> <vectorname>")
        
    else:
        
        if (sys.argv[1] == "key-gen"):
            priv, pub = ggh_generate_key_pair(int(sys.argv[2]))
            ggh_write_key_to_file(priv, sys.argv[3], public=False)
            ggh_write_key_to_file(pub, sys.argv[3], public=True)
            
            print("Generated private key: \n", priv)
            print("Generated public key: \n", pub)

        elif (sys.argv[1] == "vector-gen"):
            r = ggh_generate_secret_vector(int(sys.argv[2]))
            write_vector_to_file(r, sys.argv[3])
            
            print("Generated vector: ", r)
            
        elif (sys.argv[1] == "encrypt"):
            pub = ggh_read_key_from_file(sys.argv[2])
            r = read_vector_from_file(sys.argv[3])
            c = ggh_encrypt(pub, r)
            write_vector_to_file(c, sys.argv[3] + '_enc')
            
            print("Encrypted vector: ", c)
            
        elif (sys.argv[1] == "decrypt"):
            priv = ggh_read_key_from_file(sys.argv[2])
            c = read_vector_from_file(sys.argv[3])
            r = ggh_decrypt(priv, c)
            write_vector_to_file(r, sys.argv[3] + '_dec')

            print("Decrypted vector: ", r)

        else:
            print("Usage:")
            print(" : key-gen -> python3 ggh.py key-gen <dimension> <keyname>")
            print(" : vector-gen -> python3 ggh.py vector-gen <dimension> <vectorname>")
            print(" : encrypt -> python3 ggh.py encrypt <keyname> <vectorname>")
            print(" : decrypt -> python3 ggh.py decrypt <keyname> <vectorname>")