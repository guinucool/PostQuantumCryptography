from sage.all import matrix, vector

def lll_reduce_matrix(m: matrix = None, f: vector = None) -> matrix:
    """
    Compute the LLL-reduced form of a lattice basis.

    Parameters:
        m (Matrix): A matrix whose rows represent a lattice basis.
        f (Vector): A vector used to generate a circulant matrix (optional).

    Returns:
        Matrix: The LLL-reduced matrix corresponding to the input lattice basis.
    """
    
    # Check if it was a polynomial form a matrix given
    if (m is None):
        m = matrix.circulant(f)
        
    # Calculate the LLL-reduced matrix form
    m_lll = m.LLL()
    
    # Return the LLL-reduced matrix form
    return m_lll