from sage.all import matrix, vector, GF, codes, identity_matrix, PolynomialRing
import secrets as sec
import hashlib as hl

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
    c = codes.GoppaCode(g, l)
    
    # Generate the Parity-Check Matrix
    Ht = c.parity_check_matrix()
    
    # Permutate the Parity-Check Matrix to get its echelon form
    H = Ht.echelon_form()
    
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
    
    # Generate the public key
    public_key = classic_mceleice_generate_public_key(private_key, params)
    
    # Check if the public key is valid
    if public_key is None:
        return classic_mceleice_generate_key_pair(params)
    
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
        tuple: The encapsulated ciphertext and the generated session key.
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
    
    # Extend the ciphertext to match the codeword length
    v = c0.list() + [0] * (n - len(c0))
    v = vector(GF(2), v)
    
    # Define the polynomial ring for the finite field
    R = PolynomialRing(GF(2**m, 'z'), 'x')
    
    # Compute the syndrome
    syndrome = sum(v[i]*R(R((0,1)) - L[i]).inverse_mod(g**2) for i in range(n))
    
    # Solve the key equation using the Extended Euclidean Algorithm
    remainders = [g**2, R(syndrome)]
    coefs = [R(0),R(1)]
    
    while remainders[-1].degree() >= t:
        q, r = remainders[-2].quo_rem(remainders[-1])
        remainders.append(r)
        coefs.append(coefs[-2] - q * coefs[-1])
    
    # The error locator polynomial is the last coefficient
    locator = coefs[-1]
    
    # Find the error positions by evaluating the locator polynomial
    e = [0 for _ in range(n)]
    
    for i in range(n):
        
        if locator(L[i]) == 0:
            e[i] = 1

    # Return the decrypted message
    return vector(GF(2), e)

def classic_mceleice_decapsulate(params: tuple, private_key: tuple, c: tuple, e: vector = None) -> vector:
    """
    Decrypt a ciphertext using the Classic McEleice cryptosystem.

    Parameters:
        params (tuple): A tuple containing Classic McEleice parameters.
        private_key (tuple): The private key tuple.
        c (tuple): The capsule containing the ciphertext and the error hash.
        e (vector): The error vector (in case of attack).
    
    Returns:
        vector: The decrypted session key.
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
    if (e is None):
        e = classic_mceleice_decrypt(params, private_key, c0)
        
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