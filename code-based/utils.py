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