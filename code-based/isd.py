from sage.all import matrix, vector, sample

def isd_prange(H: matrix, s: vector, t: int, max_iterations: int = 800) -> vector:
    """
    Perform the Prange Information Set Decoding algorithm to find an error vector e such that H * e^T = s^T.
    
    Parameters:
        H (matrix): The parity-check (public key) matrix.
        s (vector): The syndrome vector.
        t (int): The error hamming weight.
        max_iterations (int): Maximum number of iterations to attempt.
        
    Returns:
        vector: The error vector e.
    """
    
    # Check if iterations exceed maximum allowed
    if max_iterations <= 0:
        return None
    
    # Extract the parameters
    n = H.ncols()
    k = n - H.nrows()
    
    # Generate the random information set
    I = sample(range(n), k)
    J = [i for i in range(n) if i not in I]
    
    # Calculate the auxiliary matrix
    H_J = H[:, J]
    
    # Check if Hj matrix is invertible
    if H_J.rank() < H_J.nrows():
        return isd_prange(H, s, t, max_iterations - 1)
    
    # Calculate the inverse of matrix Hj
    U = H_J.inverse()
    
    # Compute auxiliary syndrome vector
    s_ = s * U.transpose()
    
    # Check if the weight condition is satisfied
    if s_.hamming_weight() != t:
        return isd_prange(H, s, t, max_iterations - 1)
    
    # Create the error vector
    e = [0] * n
    
    for i in range(len(J)):
        e[J[i]] = s_[i]
        
    # Return the error vector
    return vector(e)