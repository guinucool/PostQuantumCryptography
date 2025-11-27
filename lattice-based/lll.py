from sage.all import matrix, vector
from ggh import ggh_decrypt, ggh_read_key_from_file
from ntru import ntru_decapsulation, ntru_read_key_from_file
from utils import read_vector_from_file, write_vector_to_file
import sys

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

if __name__ == "__main__":
    
    if (len(sys.argv) < 4):
        print("Usage:")
        print(" : attack-ggh -> python3 lll.py ggh <keyname> <vectorname>")
        print(" : attack-ntru -> python3 lll.py ntru <keyname> <vectorname>")
        
    else:
            
        if (sys.argv[1] == "ggh"):
            public = ggh_read_key_from_file(sys.argv[2])
            c = read_vector_from_file(sys.argv[3])
            
            attack = lll_reduce_matrix(m = public)
            r = ggh_decrypt(attack, c)
            write_vector_to_file(r, sys.argv[3] + '_att')

            print("Attack Decrypted vector: ", r)
            
        elif (sys.argv[1] == "ntru"):
            params, public = ntru_read_key_from_file(sys.argv[2])
            c = read_vector_from_file(sys.argv[3])
            
            attack = lll_reduce_matrix(f = public)
            r = ntru_decapsulation(c, params[1], params[2], Tf = attack)
            write_vector_to_file(r, sys.argv[3] + '_att')

            print("Attack Decapsulated vector: ", r)

        else:
            print("Usage:")
            print(" : attack-ggh -> python3 lll.py ggh <keyname> <vectorname>")
            print(" : attack-ntru -> python3 lll.py ntru <keyname> <vectorname>")