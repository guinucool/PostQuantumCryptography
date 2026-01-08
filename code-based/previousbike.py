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