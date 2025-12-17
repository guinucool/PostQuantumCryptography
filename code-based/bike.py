from sage.all import GF, vector, matrix
import secrets as sec
import random as rnd
import hashlib as hl
import math
import sys
from utils import bytes_xor, list_bitwise_xor, list_hamming_weight, list_rotate_left, list_bitwise_and

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
    
    # Generate the ring field
    R = GF(2**r, 'z')
    
    # Return the parameters as a tuple
    return (r, w, t, l, R)

def bike_encapsulate_decoding_parameters(nb: int, de: int, a: float, b: float) -> tuple:
    """
    Encapsulate BIKE decoding parameters into a tuple.

    Parameters:
        nb (int): Maximum number of iterations.
        de (int): Auxiliar value.
        a (float): Auxiliar value.
        b (float): Auxiliar value.

    Returns:
        tuple: A tuple containing all the BIKE decoding parameters.
    """
    
    # Return the parameters as a tuple
    return (nb, de, lambda x: a * x + b)

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
    return vector(GF(2), vec)

def bike_generate_private_key(params: tuple) -> tuple:
    """
    Generate the private key for the BIKE cryptosystem.

    Parameters:
        params (tuple): A tuple containing BIKE parameters.
    
    Returns:
        tuple: A tuple containing the private key components (h0, h1, o).
    """
    
    # Extract parameters from the tuple
    r, w, t, l, R = params
    
    # Generate the private vectors
    h0 = R(bike_generate_random_vector(r, w/2))
    h1 = R(bike_generate_random_vector(r, w/2))
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
    
    # Compute the public key
    h = h1 * (h0 ** (-1))

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
    r, w, t, l, R = params
    
    # Convert the message into a seed
    seed = int.from_bytes(m, 'little')
    
    # Create a randomizer with this seed
    randomizer = rnd.Random(seed)
    
    # Decide the weight of the error vectors
    t0 = randomizer.randrange(0, t)
    t1 = t - t0
    
    # Generate the error vectors from the message
    e0 = R(bike_generate_random_vector(r, t0, int.from_bytes(m, 'little')))
    e1 = R(bike_generate_random_vector(r, t1, int.from_bytes(m, 'little')))
    
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
    r, w, t, l, R = params
    
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
    r, w, t, l, R = params
    
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
    r, w, t, l, R = params
    
    # Generate a random messsage
    m = sec.token_bytes(l // 8)
    
    # Generate the error vectors from the message
    e0, e1 = bike_generate_error_vector_pair(params, m)
    
    print("Gen")
    print("e0: ", e0)
    print("e1: ", e1)
    
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

def bike_decrypt(params: tuple, decod: tuple, hw: tuple, c0: object) -> tuple:
    """
    Decrypt a ciphertext using the BIKE cryptosystem.

    Parameters:
        params (tuple): The BIKE parameters.
        decod (tuple): The tuple containing the BIKE decoding parameters.
        private_key (tuple): A tuple containing the private key components (h0, h1, o).
        c0 (object): The ciphertext.
    
    Returns:
        tuple: The error vectors (e0, e1).
    """
    
    # Extract parameters from the tuple
    r, w, t, l, R = params
    
    # Extract parameters from the tuple
    nb, de, f = decod
    
    # Extract private key components
    h0, h1, _ = hw
    
    # Define auxilary functions for the algorithm
    def ctr(H: matrix, s: vector, j: int) -> int:
        """
        Calculate the hamming weight of the AND between the j-th column of H and s.
        
        Parameters:
            H: The circulant matrix originated from the keys.
            s: The syndrome vector.
            j: The current iteration.
            
        Returns:
            int: The hamming weight.
        """
        
        # Placeholder for the weight
        weight = 0
        
        # Count the number of matching ones
        for i in range(len(s)):
            
            # Check if the one matches
            if H[i][j] == 1 and H[i][j] == s[i]:
                
                # Add this count to the weight
                weight += 1
                
        # Return the final weight
        return weight
    
    def BFiter(s: vector, e: vector, T: int, H: matrix) -> vector:
        """
        Perform an iteration in the calculation of the error vector.
        
        Parameters:
            s: The current syndrome vector.
            e: The current error vector.
            T: The threshold for the current iteration.
            H: The circulant matrix. 
            
        Returns:
            vector: The updated error vector.
        """
        
        # Run through all the vector positions
        for j in range(len(e)):
            
            # Check if the position requires a bit flip
            if ctr(H, s, j) >= T:
                
                # Flip the bit
                e[j] += 1
        
        # Return the updated error vector
        return e
    
    def threshold(S: int, i: int, S0: int) -> int:
        """
        Compute the threshold for the current iteration.
        
        Parameters:
            S: The hamming weight of the current syndrome.
            i: The current iteration.
            S0: The hamming weight of the starting syndrome.
            
        Returns:
            int: The calculated threshold.
        """
        
        # Define thershold auxiliar function
        def Taux(x: int, i: int) -> float:
            
            if i == 0:
                return f(x) + de
                
            if i == 1:
                return (1/3 * (2 * f(x) + (w/2 + 1)/2)) + de
            
            if i == 2:
                return (1/3 * (f(x) + w/2 + 1)) + de
            
            if i >= 3:
                return ((w/2 + 1)/2) + de
            
        # Return the calculated threshold
        return int(max(f(S), Taux(S0, i)))
    
    def hamming_weight(v: vector) -> int:
        """
        Compute the hamming weight of a binary vector.
        
        Parameters:
            v (vector): The binary vector.
            
        Returns:
            int: The hamming weight.
        """
        
        # Placeholder for the weight
        weight = 0
        
        # Compute the weight
        for i in range(len(v)):
            if v[i] == 1:
                weight += 1
                
        # Return the calculated weight
        return weight
    
    # Initialize the algorithm parameters
    s0 = vector(c0 * h0)
    s = vector(s0)
    H0 = matrix.circulant(vector(h0))
    H1 = matrix.circulant(vector(h1))
    H = H0.augment(H1)
    e = vector(GF(2), [0] * 2 * r)
    
    # Execute the BIKE bit flipping algorithm
    print("BIKE Bit Flipping")
    print(H)
    
    for i in range(nb):
        
        # Update the syndrome for this iteration
        s = s + e * H.transpose()
        
        # Calculate the threshold for this iteration
        T = threshold(hamming_weight(s), i, hamming_weight(s0))
        
        print("Threshold: ", T)
        
        # Update the error vector for this iteration
        e = BFiter(s, e, T, H)    
        
        print("New e: ", e)
        
        # Check if algorithm reached solution
        if s == e * H.transpose():
            
            # Return the error tuple
            return (e[:r], e[r:])
        
    print("Hello")
    
    # In case the algorithm fails, return failure results
    return (R(vector(GF(2), [0] * r)), R(vector(GF(2), [0] * r)))

def bike_decapsulate(params: tuple, decod: tuple, hw: tuple, c: tuple) -> bytes:
    """
    Decapsulate a capsule and generate a session key using BIKE cryptosystem.
    
    Parameters:
        params (tuple): The tuple containing the BIKE parameters.
        decod (tuple): The tuple containing the BIKE decoding parameters.
        hw (tuple): The tuple containing the private key.
        c (tuple): The capsule.
        
    Returns:
        bytes: The generated session key.
    """
    
    # Extract parameters from the tuple
    r, w, t, l, R = params
    
    # Decapsulate the capsule
    c0, c1 = c
    
    # Extract private key components
    h0, h1, o = hw
    
    # Decrypt the cryptogram
    e0, e1 = bike_decrypt(params, decod, hw, c0 * h0)
    
    # Generate the recovered message
    m = bytes_xor(c1, bike_hash_errors(params, e0, e1))
    
    # Verify if the message was obtained correctly
    if (e0, e1) != bike_generate_error_vector_pair(params, m):
        m = o
        
    # Generate the session key
    return bike_generate_session_key(params, m, c)

params = bike_encapsulate_parameters(3000, 70, 60, 256)
decod = bike_encapsulate_decoding_parameters(7, 3, 0.006254868353074983, 11.101432337243956)

print("Parameters")
#print(params)
#print(decod)
#print(decod[2](10))

hw, h = bike_generate_key_pair(params)

print("Keys - Private and Public")
#print(hw)
#print(h)

k, c = bike_encapsulate(params, h)

print("Session key + cryptogram")
print(k)
#print(c)

kn = bike_decapsulate(params, decod, hw, c)

print("Decrypted Session key")
print(kn)