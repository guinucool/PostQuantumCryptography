from sage.all import vector, matrix, ZZ, Zmod
from sage.stats.distributions.discrete_gaussian_integer import DiscreteGaussianDistributionIntegerSampler
import secrets as sec

def lwe_encapsulate_parameters(n: int, m: int, l: int, t: int, r: int, q: int) -> tuple:
    """
    Encapsulate LWE parameters into a tuple.

    Parameters:
        n (int): Dimension of the secret vector.
        m (int): Number of samples.
        l (int): Length of the message vector.
        t (int): Some parameter t.
        r (int): Some parameter r.
        q (int): Modulus.

    Returns:
        tuple: A tuple containing all the LWE parameters.
    """
    
    # Return the parameters as a tuple
    return (n, m, l, t, r, q)

def lwe_generate_private_key(params: tuple) -> matrix:
    """
    Generate a private key for the LWE cryptosystem.

    Parameters:
        params (tuple): A tuple containing LWE parameters.

    Returns:
        Matrix: The private key matrix.
    """
    
    # Extract parameters
    n, _, l, _, _, q = params
    
    # Generate a random private key matrix
    private_key = matrix(Zmod(q), l, n, [sec.choice(range(q)) for _ in range(l*n)])
    
    # Return the private key
    return private_key

def lwe_generate_public_key(S: matrix, params: tuple, a: float) -> matrix:
    """
    Generate a public key for the LWE cryptosystem.

    Parameters:
        S (Matrix): The private key matrix.
        params (tuple): A tuple containing LWE parameters.
        a (float): Standard deviation for error distribution.

    Returns:
        Matrix: The public key matrix.
    """
    
    # Extract parameters
    n, m, l, _, _, q = params
    
    # Create the discrete Gaussian sampler
    D = DiscreteGaussianDistributionIntegerSampler(a)
    
    # Generate a random matrix A
    A = matrix(Zmod(q), n, m, [sec.choice(range(q)) for _ in range(n*m)])
    
    # Generate an error matrix E
    E = matrix(Zmod(q), l, m, [D() for _ in range(l*m)])
    
    # Calculate the public key P
    P = S * A + E
    
    # Return the public key
    return (A, P)

def lwe_generate_key_pair(params: tuple, a: float) -> tuple:
    """
    Generate a key pair for the LWE cryptosystem.

    Parameters:
        params (tuple): A tuple containing LWE parameters.
        a (float): Standard deviation for error distribution.

    Returns:
        tuple: A tuple containing the private key and public key.
    """
    
    # Generate the private key
    S = lwe_generate_private_key(params)
    
    # Generate the public key
    P = lwe_generate_public_key(S, params, a)
    
    # Return the key pair
    return (S, P)

def lwe_f(v: vector, params: tuple) -> vector:
    """
    Apply the LWE function f to a vector.

    Parameters:
        v (Vector): The input vector.
        params (tuple): A tuple containing LWE parameters.

    Returns:
        Vector: The output vector after applying f.
    """
    
    # Extract parameters
    _, _, _, t, _, q = params
    
    # Return the result of f
    return vector(Zmod(q), [round((q * int(elem)) / t) for elem in list(v)])

def lwe_f_inverse(v: vector, params: tuple) -> vector:
    """
    Apply the inverse of the LWE function f to a vector.

    Parameters:
        v (Vector): The input vector.
        params (tuple): A tuple containing LWE parameters.

    Returns:
        Vector: The output vector after applying f inverse.
    """
    
    # Extract parameters
    _, _, _, t, _, q = params
    
    # Return the result of f inverse
    return vector(Zmod(t), [round((t * int(elem)) / q) for elem in list(v)])

def lwe_encrypt(v: vector, public_key: tuple, params: tuple) -> tuple:
    """
    Encrypt a message vector using the LWE public key.

    Parameters:
        v (Vector): The message vector to encrypt.
        public_key (tuple): The public key tuple (A, P).
        params (tuple): A tuple containing LWE parameters.
        a (float): Standard deviation for error distribution.

    Returns:
        Vector: The encrypted message pair.
    """
    
    # Extract parameters
    _, m, _, _, r, q = params
    
    # Unpack the public key
    A, P = public_key
    
    # Generate a random vector a
    a = vector(ZZ, [sec.choice(range(-r, r+1)) for _ in range(m)])
    
    # Calculate vector u
    u = vector(Zmod(q), list(a * A.T))
    
    # Calculate the cryptogram vector
    c = a * P.T + lwe_f(v, params)
    
    # Return the encrypted tuple
    return (u, c)

def lwe_decrypt(ct: tuple, S: matrix, params: tuple) -> vector:
    """
    Decrypt a cryptogram tuple using the LWE private key.

    Parameters:
        c (tuple): The encrypted message tuple (u, c).
        S (Matrix): The private key matrix.
        params (tuple): A tuple containing LWE parameters.

    Returns:
        Vector: The decrypted message vector.
    """
    
    # Unpack the cryptogram
    u, c = ct
    
    # Calculate the intermediate vector
    temp = c - u * S.T
    
    # Apply the inverse function f
    v = lwe_f_inverse(temp, params)
    
    # Return the decrypted vector
    return v

def lwe_generate_random_vector(params: tuple) -> vector:
    """
    Generate a random message vector for the LWE cryptosystem.

    Parameters:
        params (tuple): A tuple containing LWE parameters.

    Returns:
        Vector: A random message vector.
    """
    
    # Extract parameters
    _, _, l, t, _, _ = params
    
    # Generate a random vector
    r = vector(Zmod(t), [sec.choice(range(t)) for _ in range(l)])
    
    # Return the random vector
    return r