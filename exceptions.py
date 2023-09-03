class NoIpToScan(Exception):
    """Exception raised when no IP address is provided for scanning."""
    pass

class RangeError(Exception):
    """Exception raised for invalid port range."""
    pass

class AlreadySpecified(Exception):
    """Exception raised when ports are specified more than once."""
    pass