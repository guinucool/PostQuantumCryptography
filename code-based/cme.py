from sage.all import matrix, vector, GF, codes, identity_matrix
import secrets as sec
import hashlib as hl
import math
import sys

def classic_mceleice_encapsulate_parameters(n: int, t: int, m: int) -> tuple:
    """
    Encapsulate Classic McEleice parameters into a tuple.

    Parameters:
        n (int): Length of the code.
        t (int): Error correction capability.
        m (int): Degree of the finite field.

    Returns:
        tuple: A tuple containing all the CME parameters.
    """
    
    # Generate the code dimension parameter
    k = n - m * t
    
    # Return the parameters as a tuple
    return (n, t, m, k)

def classic_mceleice_generate_private_key(params: tuple) -> matrix:
    """
    Generate the private key matrix for the Classic McEleice cryptosystem.

    Parameters:
        params (tuple): A tuple containing Classic McEleice parameters.
        
    Returns:
        matrix: The private key matrix.
    """
    
    # Extract parameters from the tuple
    n, t, m, k = params
    
    # Define the finite field
    f2m = GF(2**m, 'z')
    
    # Generate the monic irreducible polynomial and the random support vector
    g = f2m['x'].irreducible_element(t)
    
    suport_list = []
    
    while len(suport_list) < n:
        
        # Choose a random element
        el = vector(GF(2), [sec.choice([0, 1]) for _ in range(m)])
        
        # Convert the list to a field element
        el = f2m(el)
        
        # Check if the element is already in the list or if g(el) == 0
        if el not in suport_list and g(el) != 0:
            suport_list.append(el)
    
    # Generate the support vector
    L = vector(f2m, suport_list)
    
    # Generate a random error vector
    s = [sec.choice([0, 1]) for _ in range(n)]
    s = vector(GF(2), s)
    
    # Return the private key tuple
    return (s, g, L)

def classic_mceleice_generate_public_key(private_key: tuple, params: tuple) -> matrix:
    """
    Generate the public key matrix for the Classic McEleice cryptosystem.

    Parameters:
        private_key (tuple): The private key tuple.
        params (tuple): A tuple containing Classic McEleice parameters.
        
    Returns:
        matrix: The public key matrix.
    """
    
    # Extract parameters from the tuple
    n, t, m, k = params
    
    # Extract private key components
    _, g, l = private_key
    
    # Generate the Goppa code
    bc = codes.GeneralizedReedSolomonCode(l, k)
    c = codes.SubfieldSubcode(bc, GF(2))
    #c = codes.GoppaCode(g, l)
    
    # Generate the Parity-Check Matrix
    Ht = c.parity_check_matrix()
    
    print(Ht)
    
    # Permutate the Parity-Check Matrix to get its echelon form
    H = Ht.echelon_form()
    
    print(H)
    print(identity_matrix(m * t) == H[:, :m * t])
    print(identity_matrix(m * t))
    print(H[:, :m * t])
    
    # Get the public key matrix and check if it is valid
    T = H[:, (m * t):]
    valid = identity_matrix(m * t) == H[:, :m * t]
    
    # Return the public key matrix
    return T if valid else None

def classic_mceleice_generate_key_pair(params: tuple) -> tuple:
    """
    Generate a key pair for the Classic McEleice cryptosystem.

    Parameters:
        params (tuple): A tuple containing Classic McEleice parameters.
        
    Returns:
        tuple: A tuple containing the private key and public key, respectively.
    """
    
    # Generate the private key
    private_key = classic_mceleice_generate_private_key(params)
    
    print("Private key generated.")
    
    # Generate the public key
    public_key = classic_mceleice_generate_public_key(private_key, params)
    
    print("Public key generated.")
    
    # Check if the public key is valid
    #if public_key is None:
    #    return classic_mceleice_generate_key_pair(params)
    
    # Return the key pair
    return (private_key, public_key)

def classic_mceleice_generate_error_vector(params: tuple) -> vector:
    """
    Generate a random error vector for the Classic McEleice cryptosystem.

    Parameters:
        params (tuple): A tuple containing Classic McEleice parameters.
    
    Returns:
        vector: A random error vector of weight t.
    """
    
    # Extract parameters from the tuple
    n, t, m, k = params
    
    # Initialize the error vector with zeros
    e = [0] * n
    
    # Randomly select t unique positions to set to 1
    available_positions = list(range(n))
    
    for _ in range(t):
        pos = sec.choice(available_positions)
        e[pos] = 1
        available_positions.remove(pos)
    
    # Return the error vector
    return vector(GF(2), e)

def classic_mceleice_encrypt(public_key: matrix, e: vector) -> vector:
    """
    Encrypt a message using the Classic McEleice cryptosystem.

    Parameters:
        public_key (matrix): The public key matrix.
        e (vector): The error vector.
    
    Returns:
        vector: The ciphertext vector.
    """
    
    # Compute the true public key
    I = matrix(GF(2), identity_matrix(public_key.nrows()))
    H = I.augment(public_key)
    
    # Compute the ciphertext as the product of the public key and the error vector
    c = H * e
    
    # Return the ciphertext
    return c

def classic_mceleice_encapsulate(public_key: matrix, e: vector) -> tuple:
    """
    Encapsulate a key using the Classic McEleice cryptosystem.

    Parameters:
        public_key (matrix): The public key matrix.
        e (vector): The error vector.
    
    Returns:
        tuple: The encapsulated key and the generated session key.
    """
    
    # Encrypt the error vector to get the ciphertext
    c0 = classic_mceleice_encrypt(public_key, e)
    
    # Generate the error hash
    h1 = hl.shake_256()
    h1.update(int(2).to_bytes(1, byteorder='little'))
    h1.update(bytes(e.list()))
    
    c1 = h1.digest(32)
    
    # Combine c0 and c1 to form the complete capsule
    c = (c0, c1)
    
    # Fetch the bytes form of the capsule
    c_bytes = bytes(c0.list()) + c1

    # Generate the session key hash
    h = hl.shake_256()
    h.update(int(1).to_bytes(1, byteorder='little'))
    h.update(bytes(e.list()))
    h.update(c_bytes)

    K = h.digest(32)

    # Return the capsule and the session key hash
    return (c, K)

def classic_mceleice_decrypt(params: tuple, private_key: tuple, c0: vector) -> vector:
    """
    Decrypt a ciphertext using the Classic McEleice cryptosystem.

    Parameters:
        params (tuple): A tuple containing Classic McEleice parameters.
        private_key (tuple): The private key tuple.
        c0 (vector): The ciphertext vector.
    
    Returns:
        vector: The decrypted message vector.
    """
    
    # Extract parameters from the tuple
    n, t, m, k = params
    
    # Extract private key components
    _, g, L = private_key
    
    # Generate the Goppa code
    #gc = codes.GoppaCode(g, L)
    
    # Generate the Generalized Reed-Solomon Code
    bc = codes.GeneralizedReedSolomonCode(L, k)
    gc = codes.SubfieldSubcode(bc, GF(2))
    
    # Extend the ciphertext to match the codeword length
    v = c0.list() + [0] * (n - len(c0))
    v = vector(GF(2), v)
    
    # Decode the ciphertext to retrieve the error vector
    c = bc.decode_to_code(v) # FOR FUTURE: Might return none, not sure
    
    # Check if the decoding distance was successful
    #if (v - c).norm() > t:
    #    return None
    
    print(c)
    
    # Retrieve the original message by subtracting the error vector
    e = v + c

    # Return the decrypted message
    return e

def classic_mceleice_decapsulate(params: tuple, private_key: tuple, c: tuple) -> vector:
    """
    Decrypt a ciphertext using the Classic McEleice cryptosystem.

    Parameters:
        params (tuple): A tuple containing Classic McEleice parameters.
        private_key (tuple): The private key tuple.
        c (tuple): The capsule containing the ciphertext and the error hash.
    
    Returns:
        vector: The decrypted message vector.
    """
    
    # Extract parameters from the tuple
    n, t, m, k = params
    
    # Extract private key components
    s, g, L = private_key
    
    # Extract ciphertext from the capsule
    c0, c1 = c
    
    # Set the initial decapsulation parameters
    b = 1
    
    # Decrypt the ciphertext using the private key
    e = classic_mceleice_decrypt(params, private_key, c0)
    
    # Check if decryption was successful
    if e is None:
        b = 0
        e = s
        
    # Generate the error hash
    h = hl.shake_256()
    h.update(int(2).to_bytes(1, byteorder='little'))
    h.update(bytes(e.list()))
    
    cl1 = h.digest(32)
    
    # Compare the generated hash with the received hash
    if cl1 != c1:
        b = 0
        e = s
        
    # Convert the capsule to bytes
    c_bytes = bytes(c0.list()) + c1
        
    # Generate the session key hash
    h = hl.shake_256()
    h.update(int(b).to_bytes(1, byteorder='little'))
    h.update(bytes(e.list()))
    h.update(c_bytes)

    K = h.digest(32)

    # Return the generated session key hash
    return K

#params = classic_mceleice_encapsulate_parameters(n=3488, t=64, m=12)
params = classic_mceleice_encapsulate_parameters(n=7, t=1, m=3)

print(params)

pair = classic_mceleice_generate_key_pair(params)

print("Key pair generated successfully.\n", pair)

e = classic_mceleice_generate_error_vector(params)

print("Error vector generated successfully.\n", e)

ct = classic_mceleice_encrypt(pair[1], e)

print("Ciphertext generated successfully.\n", ct)

d = classic_mceleice_decrypt(params, pair[0], ct)

print("Decrypted message successfully.\n", d)

#c, K = classic_mceleice_encapsulate(pair[1], e)

#print("Session generated successfully.\n", K)

#nK = classic_mceleice_decapsulate(params, pair[0], c)

#print("Decrypted message successfully.\n", nK)

#print("Session keys match:", K == nK)