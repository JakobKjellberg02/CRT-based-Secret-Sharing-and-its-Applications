def gcd(a : int, b : int) -> int:
    """
    Greatest Common Divisor for two integers using Euclidean algorithm.

    Parameters
    ----------
        a : int
            First integer.
        b : int
            Second integer.
    
    Returns
    -------
        a : int
            The greatest common divisor for a and b.

    """

    # Euclidean algorithm
    while b: 
        a, b = b, a % b
    return a

def extended_gcd(a : int, b : int) -> tuple[int, int, int]:
    """
    Extended GCD iterative. Python is not the best with tail recursion so it is designed this way to avoid 
    recursion limit.

    Parameters
    ----------
        a : int
            First integer.
        b : int
            Second integer.
    
    Returns
    -------
        a : int
            GCD.
        x0, y0 ->
            Coefficients for a*x0 + b*y0 = gcd(a,b)
        
    """
    # Bezout coefficients
    x0, x1, y0, y1 = 1, 0, 0, 1
    while b != 0:
        # Compute quotient and update using Euclidean algorithm
        q, a, b = a // b, b, a % b

        # Update coefficients
        x0, x1 = x1, x0 - q * x1
        y0, y1 = y1, y0 - q * y1
    return a, x0, y0

def modinv(a : int, m : int) -> int:
    """
    Modular multiplicative inverse of a modulo m.

    Parameters
    ----------
        a : int
            First integer.
        m : int
            Modulo.
    
    Returns
    -------
        result : int
            Modular multiplicative inverse.

    """
    # Find coefficients using extended_gcd
    g, x, y = extended_gcd(a, m)
    # coprime if gcd=1
    if g != 1:
        raise ValueError(f"Modular inverse does not exist for {a} mod {m}")
    else:
        return x % m

