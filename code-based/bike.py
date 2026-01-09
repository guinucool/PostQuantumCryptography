from sage.all import GF, vector, PolynomialRing, xgcd
import secrets as sec
import random as rnd
import hashlib as hl
import sys
from utils import bytes_xor

def bike_encapsulate_parameters(r: int, w: int, t: int, l: int) -> tuple:
    """
    Encapsulate BIKE parameters into a tuple.

    Parameters:
        r (int): Block size.
        w (int): Row weight.
        t (int): Error weight.
        l (int): Key and message length in bits.

    Returns:
        tuple: A tuple containing all the BIKE parameters.
    """
    
    # Generate the binary finite field
    F2 = GF(2)
    
    # Generate the polynomial ring field
    PR = PolynomialRing(F2, 'x')
    
    # Compute the modulus polynomial
    modulus = PR.gen() ** r - PR(1)
    
    # Generate the cyclic polynomial ring field
    R = PR.quotient(modulus, 'x')
    
    # Return the parameters as a tuple
    return (r, w, t, l, F2, PR, R, modulus)

def bike_generate_random_vector(r: int, weight: int, seed: int = None) -> vector:
    """
    Generate a random binary vector of length r with a specified weight.

    Parameters:
        r (int): Length of the vector.
        weight (int): The hamming weight of the vector.
        seed (int): Seed for the position picker.

    Returns:
        vector: A binary vector of length r with the specified weight.
    """
    
    # Define the used randomizer
    randomizer = sec.SystemRandom()
    
    # Override the randomizer with the seeded one if provided
    if seed is not None:
        randomizer = rnd.Random(seed)
    
    # Pick unique random positions to set to 1
    vec = [0] * r
    available_positions = list(range(r))
    
    while weight > 0:
        
        # Pick a random position
        pos = randomizer.choice(available_positions)
        
        # Set the position to 1
        vec[pos] = 1
        
        # Remove the position from the available positions
        available_positions.remove(pos)
        weight -= 1
    
    # Return the generated vector
    return vec

def bike_generate_private_key(params: tuple) -> tuple:
    """
    Generate the private key for the BIKE cryptosystem.

    Parameters:
        params (tuple): A tuple containing BIKE parameters.
    
    Returns:
        tuple: A tuple containing the private key components (h0, h1, o).
    """
    
    # Extract parameters from the tuple
    r, w, t, l, F2, PR, R, modulus = params
    
    # Generate the private vectors
    h0 = R(bike_generate_random_vector(r, w // 2))
    h1 = R(bike_generate_random_vector(r, w // 2))
    o = sec.token_bytes(l // 8)
    
    # Return the private key as a tuple
    return (h0, h1, o)
    
def bike_generate_public_key(hw: tuple) -> object:
    """
    Generate the public key for the BIKE cryptosystem.

    Parameters:
        hw (tuple): A tuple containing the private key components (h0, h1, o).
    
    Returns:
        object: The public key.
    """
    
    # Extract private key components
    h0, h1, _ = hw
    
    # Compute the inverse of the private key in the polynomial ring
    h0_poly = h0.lift()
    g, h0_inv_poly, _ = xgcd(h0_poly, h0.parent().modulus())
    
    # If the private key is not invertible, raise an exception
    if g != 1:
        return None
    
    # Convert the inverse back to the cyclic polynomial ring
    h0_inv = h0.parent()(h0_inv_poly)

    # Compute the public key
    h = h1 * (h0_inv)

    # Return the public key
    return h

def bike_generate_key_pair(params: tuple) -> tuple:
    """
    Generate a key pair for the BIKE cryptosystem.

    Parameters:
        params (tuple): A tuple containing BIKE parameters.

    Returns:
        tuple: A tuple containing the private and public keys.
    """
    
    # Generate the private key
    private_key = bike_generate_private_key(params)
    
    # Generate the public key
    public_key = bike_generate_public_key(private_key)
        
    # If the public key could not be generated, retry
    if public_key is None:
        return bike_generate_key_pair(params)
    
    # Return the key pair
    return (private_key, public_key)

def bike_generate_error_vector_pair(params: tuple, m: bytes) -> tuple:
    """
    Generate the tuple of error vectors for the BIKE cryptosystem.
    
    Parameters:
        params (tuple): The BIKE cryptosystem parameters.
        m (bytes): The message to generate the error vectors.
        
    Returns:
        tuple: The pair of error vectors.
    """
    
    # Extract parameters from tuple
    r, w, t, l, F2, PR, R, modulus = params
    
    # Convert the message into a seed
    seed = int.from_bytes(m, 'little')
    
    # Create a randomizer with this seed
    randomizer = rnd.Random(seed)
    
    # Decide the weight of the error vectors
    t0 = randomizer.randrange(0, t)
    t1 = t - t0
    
    # Generate the error vectors from the message
    e0 = R(bike_generate_random_vector(r, t0, randomizer.randint(0, sys.maxsize)))
    e1 = R(bike_generate_random_vector(r, t1, randomizer.randint(0, sys.maxsize)))
    
    # Return the error vectors pair
    return (e0, e1)
    

def bike_hash_errors(params: tuple, e0: object, e1: object) -> bytes:
    """
    Hash two error vectors.
    
    Parameters:
        params (tuple): The BIKE parameter tuple.
        e0 (object): First error vector.
        e1 (object): Second error vector.
        
    Returns:
        bytes: The hash obtained with the error vectors.
    """
    
    # Extract parameters from tuple
    r, w, t, l, F2, PR, R, modulus = params
    
    # Join and convert the error vectors into a single format
    e = e0 + e1
    data = bytes(list(vector(e)))
    
    # Use the generate format to create a unique hash
    h = hl.shake_256()
    h.update(data)

    # Return the generated hash
    return h.digest(l // 8)

def bike_generate_session_key(params: tuple, m: bytes, c: tuple) -> bytes:
    """
    Generate the session key given the message and capsule
    
    Parameters:
        params (tuple): The BIKE parameters.
        m (bytes): The message.
        c (tuple): The capsule.
        
    Returns:
        bytes: The generated session key.
    """
    
    # Extract parameters from tuple
    r, w, t, l, F2, PR, R, modulus = params
    
    # Generate the session key
    h = hl.shake_256()
    h.update(m)
    h.update(bytes(list(vector(c[0]))))
    h.update(c[1])
    
    # Return the generated session key
    return h.digest(l // 8)
    
def bike_encrypt(h: object, e: tuple) -> object:
    """
    Encrypt a message using the BIKE cryptosystem.

    Parameters:
        h (object): The public key.
        e (tuple): The error vectors (e0, e1).
    
    Returns:
        object: The ciphertext.
    """
    
    # Extract error vectors
    e0, e1 = e
    
    # Compute the ciphertext
    c = e0 + e1 * h
    
    # Return the ciphertext
    return c

def bike_encapsulate(params: tuple, h: object) -> tuple:
    """
    Encapsulate a key using the BIKE cryptosystem.

    Parameters:
        params (tuple): A tuple containing BIKE parameters.
        h (object): The public key.
    
    Returns:
        tuple: A tuple containing the shared secret and the capsule.
    """
    
    # Extract parameters from the tuple
    r, w, t, l, F2, PR, R, modulus = params
    
    # Generate a random messsage
    #m = sec.token_bytes(l // 8)
    m = b"Hello BIKE!"
    
    # Generate the error vectors from the message
    e0, e1 = bike_generate_error_vector_pair(params, m)
    
    # Encrypt the error vectors
    c0 = bike_encrypt(h, (e0, e1))
    
    # Create the hash part of the capsule
    c1 = bytes_xor(m, bike_hash_errors(params, e0, e1))
    
    # Create the capsule
    c = (c0, c1)
    
    # Generate the session key
    K = bike_generate_session_key(params, m, c)
    
    # Return the generated session key and capsule
    return (K, c)

def bike_decrypt(params: tuple, hw: tuple, s: object, max_iterations: int = 30, a: float = 0.6) -> tuple:
    """
    Decrypt a ciphertext using the BIKE cryptosystem.

    Parameters:
        params (tuple): The BIKE parameters.
        hw (tuple): A tuple containing the private key components (h0, h1, o).
        s (object): The syndrome ciphertext vector.
        max_iterations (int): Maximum number of iterations.
        a (float): Threshold adjustment parameter.

    Returns:
        tuple: The error vectors (e0, e1).
    """
    
    # Extract parameters from the tuple
    r, w, t, l, F2, PR, R, modulus = params
    
    # Extract private key components
    h0, h1, _ = hw
    
    # Compute the syndrome
    syndrome = s * h0
    
    # Decode the syndrome
    return bike_decode(params, syndrome, hw, max_iterations, a)

def bike_decode(params: tuple, s: object, hw: tuple, max_iterations: int = 30, a: float = 0.6) -> tuple:
    """
    BIKE Decoder using the Black-Gray-Flip (BGF) algorithm.
    
    Parameters:
        params (tuple): The BIKE parameters.
        s (object): The syndrome to decode.
        hw (tuple): The private key components.
        max_iterations (int): Maximum number of iterations.
        a (float): Threshold adjustment parameter.
        
    Returns:
        tuple: The decoded error vectors (e0, e1).
    """
    
    # Extract parameters from tuple
    r, w, t, l, F2, PR, R, modulus = params
    
    # Compute algorithm parameters
    d = w // 2
    
    # Extract private key components
    h0, h1, _ = hw
    
    # Convert syndrome to list
    syndrome = list(s)
    
    # Calculate weighted positions of private keys
    h0_pos = [i for i, c in enumerate(list(h0)) if c == 1]
    h1_pos = [i for i, c in enumerate(list(h1)) if c == 1]
    
    # Initialize error vectors
    e0 = [F2(0)] * r
    e1 = [F2(0)] * r
    
    # Initialize the algorithm
    for i in range(max_iterations):
        
        # Calculate syndrome weight
        syndrome_weight = sum(1 for bit in syndrome if bit == 1)
        
        # Check for successful decoding
        if syndrome_weight == 0:
            
            # Return the decoded error vectors
            return (R(e0), R(e1))
        
        # Calculate the thresholds
        noise_floor = syndrome_weight * d // r
        base_threshold = max(int(d * a), noise_floor + 2)
        
        # Compute unsatisfied parity checks (UPCs)
        candidates = []
        
        for j in range(r):
            upc0 = sum(1 for bit in h0_pos if syndrome[(j + bit) % r] == 1)
            upc1 = sum(1 for bit in h1_pos if syndrome[(j + bit) % r] == 1)
            candidates.append((upc0, 'e0', j))
            candidates.append((upc1, 'e1', j))
            
        # Sort candidates by UPC (highest first)
        candidates.sort(reverse=True, key=lambda x: x[0])
        
        # Compute the bit flips to perform
        flips_e0 = []
        flips_e1 = []
        total_flips = 0
        threshold_decrease = 0
        
        while total_flips == 0:
            
            # Calculate the current threshold
            threshold = max(base_threshold - threshold_decrease, noise_floor + 1, 3)
            
            for (upc, error, j) in candidates:
                
                # Select only positions above the threshold
                if upc < threshold:
                    break
                
                # Limit the number of flips
                if total_flips >= t:
                    break
                
                # Check which error vector to flip
                if error == 'e0':
                    flips_e0.append(j)
                else:
                    flips_e1.append(j)
                    
                # Increment the total flips
                total_flips += 1
                
            # Lower the threshold in case no flips were selected
            threshold_decrease += 1
            
        # Perform the bit flips and update the syndrome
        for j in flips_e0:
            
            # Flip the bit
            e0[j] = e0[j] + F2(1)
            
            # Update the syndrome
            for bit in h0_pos:
                pos = (j + bit) % r
                syndrome[pos] = syndrome[pos] + F2(1)
                
        for j in flips_e1:
            
            # Flip the bit
            e1[j] = e1[j] + F2(1)
            
            # Update the syndrome
            for bit in h1_pos:
                pos = (j + bit) % r
                syndrome[pos] = syndrome[pos] + F2(1)
                
    # In case of failure, return zero vectors
    return (R([0] * r), R([0] * r))

def bike_decapsulate(params: tuple, hw: tuple, c: tuple, max_iterations: int = 30, a: float = 0.6, e: tuple = None) -> bytes:
    """
    Decapsulate a capsule and generate a session key using BIKE cryptosystem.
    
    Parameters:
        params (tuple): The tuple containing the BIKE parameters.
        hw (tuple): The tuple containing the private key.
        c (tuple): The capsule.
        max_iterations (int): Maximum number of iterations.
        a (float): Threshold adjustment parameter.
        e (tuple): Error tuple in case of attack.
        
    Returns:
        bytes: The generated session key.
    """
    
    # Extract parameters from the tuple
    r, w, t, l, F2, PR, R, modulus = params
    
    # Decapsulate the capsule
    c0, c1 = c
    
    # Extract private key components
    h0, h1, o = hw
    
    # Decrypt the cryptogram
    if e is None:
        e0, e1 = bike_decrypt(params, hw, c0, max_iterations, a)
    else:
        e0, e1 = (R(e[0]), R(e[1]))
    
    # Generate the recovered message
    m = bytes_xor(c1, bike_hash_errors(params, e0, e1))
    
    # Verify if the message was obtained correctly
    if (e0, e1) != bike_generate_error_vector_pair(params, m):
        m = o
        
    # Generate the session key
    return bike_generate_session_key(params, m, c)