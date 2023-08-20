from PortScanner import ip_checker

def test_valid_local_ip():
    assert ip_checker('192.168.0.1') == '192.168.0.1'

def test_invalid_ip_parts():
    assert ip_checker('192.168..1') == False

def test_nonnumeric_parts():
    assert ip_checker('192.168.a.1') == False

def test_out_of_range_parts():
    assert ip_checker('192.168.300.1') == False

def test_valid_non_local_ip():
    assert ip_checker('10.0.0.1') == False

def test_invalid_ip_length():
    assert ip_checker('192.168.0') == False
    assert ip_checker('192.168.0.1.1') == False
    assert ip_checker('192.168') == False

def test_empty_parts():
    assert ip_checker('192.168..1') == False
    assert ip_checker('..') == False

def test_mixed_valid_ip():
    assert ip_checker('192.168.1.1') == '192.168.1.1'

def test_mixed_invalid_ip():
    assert ip_checker('192.168.256.1') == False

def test_valid_local_ip_prefix():
    assert ip_checker('192.168.0.1') == '192.168.0.1'
    assert ip_checker('192.168.255.1') == '192.168.255.1'

def test_invalid_local_ip_prefix():
    assert ip_checker('192.169.0.1') == False
    assert ip_checker('193.168.0.1') == False
    assert ip_checker('191.168.0.1') == False
