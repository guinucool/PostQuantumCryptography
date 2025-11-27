from sage.all import vector

def write_vector_to_file(v: vector, filename: str) -> None:
    """
    Write a vector to a file.

    Parameters:
        v (Vector): The vector to write.
        filename (str): The name of the file to write the vector to.
    """
    
    # Append the .vec extension
    filename += '.vec'
    
    # Write the vector to the file
    with open(filename, 'wb') as f:
        
        # Write the length of the vector
        f.write(len(v).to_bytes(4, byteorder='little', signed=True))
        
        # Iterate through each value in the vector
        for i in range(len(v)):
            
            # Write the value to the file
            f.write(int(v[i]).to_bytes(4, byteorder='little', signed=True))
            
def read_vector_from_file(filename: str) -> vector:
    """
    Read a vector from a file.

    Parameters:
        filename (str): The name of the file to read the vector from.

    Returns:
        Vector: The vector read from the file.
    """
    
    # Append the .vec extension
    filename += '.vec'
    
    # Open the file for reading
    with open(filename, 'rb') as f:
        
        # Read the length of the vector
        n = int.from_bytes(f.read(4), byteorder='little', signed=True)
        
        # Initialize an empty list
        l = []
        
        # Fill the list with values from the file
        for _ in range(n):
            l.append(int.from_bytes(f.read(4), byteorder='little', signed=True))

    # Return the vector
    return vector(l)