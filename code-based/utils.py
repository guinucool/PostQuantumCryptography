def bytes_xor(a: bytes, b: bytes) -> bytes:
    """
    Execute the XOR operation between two bytes objects.
    
    Parameters:
        a (bytes): First byte object.
        b (bytes): Second byte object.
        
    Returns:
        bytes: The XORed bytes object.
    """
    
    # XOR the two objects
    return bytes(x ^ y for x, y in zip(a, b))

def list_rotate_left(l: list, n: int) -> list:
    """
    Rotate a bit wise list a certain number of times to the left
    
    Parameters:
        l (list): The list to rotate.
        n (int): Number of times to rotate.
        
    Returns:
        list: The rotated list.
    """
    
    # Associate the final list with the starting list
    lr = l
    
    # Only rotate if n is different than 0
    if (n != 0):
        
        # Do recursion to rotate the list
        if (n != 1):
            l = list_rotate_left(l, n - 1)
        
        # Create placeholder for rotated list
        lr = [0] * len(l)
        
        # Place the first element in the last of the new list
        lr[-1] = l[0]
        
        # Fill the list with the rotation
        for i in range(len(lr) - 1):
            lr[i] = l[i+1]
        
    # Return the rotated list
    return lr

def list_hamming_weight(l: list) -> int:
    """
    Calculte the hamming weight of a bit wise list.
    
    Parameters:
        l (list): The list to calculate the weight.
        
    Returns:
        int: The hamming weight.
    """
    
    # Calculate the hamming weight of a list
    return sum(l)

def list_bitwise_xor(l1: list, l2: list) -> list:
    """
    Perform the bitwise xor between two binary lists (assuming they have the same size).
    
    Parameters:
        l1 (list): The first list.
        l2 (list): The second list.
        
    Returns:
        list: The bitwise xor list.
    """
    
    # Create the result list
    l = [0] * (len(l1))
    
    # Populate the result list
    for i in range(len(l)):
        
        # Perform the xor operation
        l[i] = int(l1[i] != l2[i])
        
    # Return the xor list
    return l

def list_bitwise_and(l1: list, l2: list) -> list:
    """
    Perform the bitwise and between two binary lists (assuming they have the same size).
    
    Parameters:
        l1 (list): The first list.
        l2 (list): The second list.
        
    Returns:
        list: The bitwise and list.
    """
    
    # Create the result list
    l = [0] * (len(l1))
    
    # Populate the result list
    for i in range(len(l)):
        
        # Perform the xor operation
        l[i] = int(l1[i] and l2[i])
        
    # Return the xor list
    return l