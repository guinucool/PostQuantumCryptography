from sage.all import vector, matrix, ZZ, Zmod
from utils import write_vector_to_file, read_vector_from_file
import secrets as sec
import sys

def ntru_balanced_remainder(v: int, m: int):
    """
    Compute the balanced remainder of an integer v modulo m.
    
    Parameters:
        v (int): The integer to reduce.
        m (int): The modulus.
        
    Returns:
        int: The balanced remainder of v modulo m.
    """
    # Compute the standard remainder
    v = v.mod(m)
    
    # Compute and return the balanced remainder
    if v > m//2:
        return int(v) - int(m)
    else:
        return int(v)

def ntru_write_key_to_file(parameters: tuple, key: vector, filename: str, public: bool) -> None:
    """
    Write NTRU key parameters and key to a file.
    
    Parameters:
        parameters (tuple): NTRU parameters (n, p, q, df).
        key (Vector): The key to write.
        filename (str): The name of the file to write the key to.
        public (bool): True if the key is public, False if private.
    """
    
    # Append the appropriate extension
    if public:
        filename += '.pub'
        
    # Write the parameters and key to the file
    with open(filename, 'wb') as f:
        
        # Write the parameters
        for param in parameters:
            f.write(int(param).to_bytes(4, byteorder='little', signed=True))
        
        # Write the length of the key
        f.write(len(key).to_bytes(4, byteorder='little', signed=True))
        
        # Write each value in the key
        for i in range(len(key)):
            f.write(int(key[i]).to_bytes(4, byteorder='little', signed=True))
            
def ntru_read_key_from_file(filename: str) -> tuple:
    """
    Read NTRU key parameters and key from a file.
    
    Parameters:
        filename (str): The name of the file to read the key from.
    
    Returns:
        tuple: A tuple containing the parameters and the key vector.
    """
        
    # Open the file for reading
    with open(filename, 'rb') as f:
        
        # Read the parameters
        n = int.from_bytes(f.read(4), byteorder='little', signed=True)
        p = int.from_bytes(f.read(4), byteorder='little', signed=True)
        q = int.from_bytes(f.read(4), byteorder='little', signed=True)
        df = int.from_bytes(f.read(4), byteorder='little', signed=True)
        
        # Read the length of the key
        key_length = int.from_bytes(f.read(4), byteorder='little', signed=True)
        
        # Read each value in the key
        key_values = []
        for _ in range(key_length):
            key_values.append(int.from_bytes(f.read(4), byteorder='little', signed=True))
            
    # Return the parameters and the key vector
    return (n, p, q, df), vector(key_values)

def ntru_generate_parameters(n: int = 257, p: int = 3, q: int = 10, df: int = 77) -> tuple:
    """
    Generate NTRU parameters.
    
    Args:
        n (int): Degree of the polynomials.
        p (int): Small modulus.
        q (int): Large modulus. If -1, it will be set randomly.
        df (int): Number of non-zero coefficients in the private key polynomial. If -1, it will be set to randomly.
    
    Returns:
        tuple: A tuple containing (n, p, q, df).
    """
    
    # Set q as the power of two
    q = 2 ** q
        
    # Set df randomly if not provided
    if df == -1:
        df = sec.choice([i for i in range(0, (n+1) // 2)])
        
    # Return the generated parameters
    return n, p, q, df

def ntru_generate_random_vector(n: int, df: int, l: int = 1) -> vector:
    """
    Generate a random vector for the NTRU cryptosystem.
    
    Parameters:
        n (int): Dimension of the vector.
        df (int): Number of non-zero coefficients in the vector.
        l (int): Range limit for the vector entries.
    
    Returns:
        Vector: A random vector.
    """
    
    # Generate the random list with the possible entries
    
    entries = []
    
    # Generate positive entries
    for _ in range(df+1):
        entries.append(sec.choice(range(1, l+1)))
        
    # Generate negative entries
    for _ in range(df):
        entries.append(sec.choice(range(-l, 0)))
        
    # Fill the rest with zeros
    for _ in range(n - (2 * df + 1)):
        entries.append(0)
        
    # Generate the random vector by shuffling the entries
    final = []
    
    for _ in range(n):
        
        i = sec.choice(range(len(entries)))
        
        final.append(entries[i])
        
        entries.pop(i)
    
    # Return the random vector
    return vector(final)

def ntru_generate_private_keys(n: int, p: int, q: int, df: int) -> tuple:
    """
    Generate private keys for the NTRU cryptosystem.
    
    Parameters:
        n (int): Degree of the polynomials.
        p (int): Small modulus.
        q (int): Large modulus.
        df (int): Number of non-zero coefficients in the private key polynomials.
    
    Returns:
        tuple: A tuple containing the private key polynomials f and g.
    """
    
    # Generate the private key polynomials f and g
    e1 = vector([1] + [0 for _ in range(n-1)])
    
    # Generate f and ensure it's invertible mod p and mod q
    f = e1 + ntru_generate_random_vector(n, df, l=p-1)
    fT = matrix.circulant(f)
    
    # Check if f is invertible mod p and mod q
    while (fT.determinant().gcd(p) != 1) or (fT.determinant().gcd(q) != 1):
        f = e1 + ntru_generate_random_vector(n, df, l=p-1)
        fT = matrix.circulant(f)
    
    # Generate g
    g = ntru_generate_random_vector(n, df)
    
    # Return the private keys
    return f, g

def ntru_generate_public_key(f: vector, g: vector, q: int) -> vector:
    """
    Generate the public key for the NTRU cryptosystem.
    
    Parameters:
        f (Vector): Private key polynomial f.
        g (Vector): Private key polynomial g.
        q (int): Large modulus.
    
    Returns:
        Vector: The public key polynomial h.
    """
    
    # Create the circulant matrix from f
    Tf = matrix.circulant(vector(Zmod(q), list(f)))
    
    # Calculate the vector h
    h = g * Tf.inverse()
    
    # Return the public key
    return vector(ZZ, list(h))

def ntru_generate_key_pair(n: int, p: int, q: int, df: int) -> tuple:
    """
    Generate a NTRU key pair (private and public keys).

    Parameters:
        n (int): Degree of the polynomials.
        p (int): Small modulus.
        q (int): Large modulus.
        df (int): Number of non-zero coefficients in the private key polynomials.

    Returns:
        tuple: A tuple containing the private and public key.
    """
    
    # Generate the private keys
    private_keys = ntru_generate_private_keys(n, p, q, df)
    
    # Generate the public key from the private key
    public_key = ntru_generate_public_key(private_keys[0], private_keys[1], q)
    
    # Return the key pair
    return private_keys[0], public_key

def ntru_encapsulation(m: vector, h: vector, n: int, p: int, q: int, df: int) -> vector:
    """
    Encapsulate a message using the NTRU cryptosystem.
    
    Parameters:
        m (Vector): Message vector.
        h (Vector): Public key polynomial h.
        n (int): Degree of the polynomials.
        p (int): Small modulus.
        q (int): Large modulus.
        df (int): Number of non-zero coefficients in the random polynomial r.
    
    Returns:
        Vector: The ciphertext vector.
    """
    
    # Generate the random polynomial r
    r = ntru_generate_random_vector(n, df)
    
    # Create the circulant matrix from h
    Th = matrix.circulant(h)
    
    # Calculate the ciphertext c
    c = (m + vector(Zmod(q), list(p * r * Th)))
    
    # Return the ciphertext
    return c

def ntru_decapsulation(c: vector, p: int, q: int, f: vector = None, Tf: matrix = None) -> vector:
    """
    Decapsulate a ciphertext using the NTRU cryptosystem.
    
    Parameters:
        f (Vector): Private key polynomial f.
        c (Vector): Ciphertext vector.
        p (int): Small modulus.
        q (int): Large modulus.
        Tf (Matrix): The circulant matrix from polynomial f (optional).
    
    Returns:
        Vector: The decrypted message vector.
    """
    
    # Create the circulant matrix from f
    if (Tf is None):
        Tf = matrix.circulant(f)
    
    # Calculate the intermediate vector a
    a = vector(Zmod(q), list(c * Tf))
    
    # Calculate the balanced remainder vector
    a = vector([ntru_balanced_remainder(ele, q) for ele in list(a)])
    a = vector(Zmod(p), list(a))
    a = vector([ntru_balanced_remainder(ele, p) for ele in list(a)])
    
    # Calculate the message vector m
    m = a * (Tf.change_ring(Zmod(p))).inverse()
    
    # Return the decrypted message
    return vector([ntru_balanced_remainder(ele, p) for ele in list(m)])

if __name__ == "__main__":
    
    if (len(sys.argv) < 4):
        print("Usage:")
        print(" : key-gen -> python3 ntru.py key-gen <n> <p> <q> <df> <keyname>")
        print(" : vector-gen -> python3 ntru.py vector-gen <keyname> <vectorname>")
        print(" : encrypt -> python3 ntru.py encapsulate <keyname> <vectorname>")
        print(" : decrypt -> python3 ntru.py decapsulate <keyname> <vectorname>")
        
    else:
        
        if (sys.argv[1] == "key-gen"):
            params = ntru_generate_parameters(int(sys.argv[2]), int(sys.argv[3]), int(sys.argv[4]), int(sys.argv[5]))
            priv, pub = ntru_generate_key_pair(params[0], params[1], params[2], params[3])
            
            ntru_write_key_to_file(params, priv, sys.argv[6], public=False)
            ntru_write_key_to_file(params, pub, sys.argv[6], public=True)
            
            print("Generated private key: \n", priv)
            print("Generated public key: \n", pub)

        elif (sys.argv[1] == "vector-gen"):
            params, _ = ntru_read_key_from_file(sys.argv[2])
            m = ntru_generate_random_vector(params[0],params[3])
            
            write_vector_to_file(m, sys.argv[3])
            
            print("Generated vector: ", m)
            
        elif (sys.argv[1] == "encapsulate"):
            params, pub = ntru_read_key_from_file(sys.argv[2])
            m = read_vector_from_file(sys.argv[3])
            c = ntru_encapsulation(m, pub, params[0], params[1], params[2], params[3])
            write_vector_to_file(c, sys.argv[3] + '_enc')
            
            print("Encapsulated vector: ", c)
            
        elif (sys.argv[1] == "decapsulate"):
            params, priv = ntru_read_key_from_file(sys.argv[2])
            c = read_vector_from_file(sys.argv[3])
            d = ntru_decapsulation(c, params[1], params[2], f=priv)
            write_vector_to_file(d, sys.argv[3] + '_dec')

            print("Decapsulated vector: ", d)

        else:
            print("Usage:")
            print(" : key-gen -> python3 ntru.py key-gen <n> <p> <q> <df> <keyname>")
            print(" : vector-gen -> python3 ntru.py vector-gen <keyname> <vectorname>")
            print(" : encrypt -> python3 ntru.py encapsulate <keyname> <vectorname>")
            print(" : decrypt -> python3 ntru.py decapsulate <keyname> <vectorname>")