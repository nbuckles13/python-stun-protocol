import unittest

from stun_protocol import message, attribute


class MessageTestCase(unittest.TestCase):
    def test_parse_binding_request(self):
        binding_request = (
            b"\x00\x01\x00\x64\x21\x12\xa4\x42\xcf\xac\xb2\xa4\x3a\xa2\xde\x5a"
            b"\x9d\x56\xd8\x5a\x00\x25\x00\x00\x00\x24\x00\x04\x6e\x20\x00\xff"
            b"\x80\x2a\x00\x08\x1b\x0a\xb9\x8b\x6e\x8e\xff\xa6\x00\x06\x00\x25"
            b"\x6f\x4e\x70\x68\x3a\x48\x74\x31\x31\x4d\x61\x52\x5a\x48\x63\x34"
            b"\x47\x4f\x4c\x4a\x55\x73\x62\x75\x31\x52\x33\x59\x43\x73\x37\x32"
            b"\x48\x59\x4e\x32\x35\x20\x20\x20\x00\x08\x00\x14\xfc\xbc\x47\x21"
            b"\x68\x1f\xdb\x59\x91\x33\x42\xbe\x96\x19\x9e\x7f\x3e\xf0\xe7\x77"
            b"\x80\x28\x00\x04\x87\x18\xc3\xa4"
        )
        m = message.Message.create(binding_request)
        assert len(m.attributes) == 6, "Incorrect amount of attributes"
        use_candidate, priority, ice_controlling, username, message_integrity, fingerprint = m.attributes
        assert isinstance(use_candidate, attribute.UseCandidateAttribute), "Should be USE-CANDIDATE"
        assert isinstance(priority, attribute.PriorityAttribute), "Shoul be PRIORITY"
        assert priority.priority == 1847591167, "Bad priority value parsed"
        assert isinstance(ice_controlling, attribute.IceControllingAttribute), "Should be ICE-CONTROLLING"
        assert ice_controlling.random_number == 0x1b0ab98b6e8effa6, "Bad tie breaker value"
        assert isinstance(username, attribute.UsernameAttribute), "Should be USERNAME"
        assert username.username == b"oNph:Ht11MaRZHc4GOLJUsbu1R3YCs72HYN25", "Bad username value"
        assert isinstance(message_integrity, attribute.MessageIntegrityAttribute), "Should be MESSAGE-INTEGRITY"
        assert message_integrity.hmac == b"\xfc\xbc\x47\x21\x68\x1f\xdb\x59\x91\x33\x42\xbe\x96\x19\x9e\x7f\x3e\xf0\xe7\x77", "Bad HMAC value"
        assert isinstance(fingerprint, attribute.FingerprintAttribute), "Should be FINGERPRINT"
        assert fingerprint.value == b"\x87\x18\xc3\xa4", "Bad CRC-32 value"

    def test_parse_binding_request_2(self):
        binding_request = (
            b"\x00\x01\x00\x6c\x21\x12\xa4\x42\x34\x79\x47\x65\x34\x63\x59\x36"
            b"\x31\x6a\x79\x6a\x00\x06\x00\x25\x48\x74\x31\x31\x4d\x61\x52\x5a"
            b"\x48\x63\x34\x47\x4f\x4c\x4a\x55\x73\x62\x75\x31\x52\x33\x59\x43"
            b"\x73\x37\x32\x48\x59\x4e\x32\x35\x3a\x6f\x4e\x70\x68\x00\x00\x00"
            b"\xc0\x57\x00\x04\x00\x00\x03\xe7\x80\x29\x00\x08\xa6\x96\x81\x9e"
            b"\x91\xc9\x37\xda\x00\x25\x00\x00\x00\x24\x00\x04\x6e\x00\x1e\xff"
            b"\x00\x08\x00\x14\x05\x41\x1b\xc3\xdc\x87\xb2\xdc\x35\xda\x8b\xa7"
            b"\xde\x1b\xad\xea\x59\x6e\x4c\x35\x80\x28\x00\x04\x21\x60\x1a\x41"
        )
        m = message.Message.create(binding_request)
        assert len(m.attributes) == 7
        goog_network_info = m.attributes[1]
        assert isinstance(goog_network_info, attribute.GoogNetworkInfoAttribute)
        assert goog_network_info.network_id == 0
        assert goog_network_info.network_cost == 999

    def test_parse_binding_success_response(self):
        binding_response = (
            b"\x01\x01\x00\x2c\x21\x12\xa4\x42\xcf\xac\xb2\xa4\x3a\xa2\xde\x5a"
            b"\x9d\x56\xd8\x5a\x00\x20\x00\x08\x00\x01\xb4\x92\x2b\x18\xae\x41"
            b"\x00\x08\x00\x14\x69\xd3\x97\x5e\x33\xdb\x4a\x81\x8a\xfd\xa3\x30"
            b"\xa7\xa2\xa8\xc6\x4e\x0e\x6f\xa0\x80\x28\x00\x04\x0a\x8c\x5c\x64"
        )
        m = message.Message.create(binding_response)
        assert len(m.attributes) == 3
        xor_mapped_address, message_int, fingerprint = m.attributes
        assert isinstance(xor_mapped_address, attribute.XorMappedAddressAttribute), "Should be XOR-MAPPED-ADDRESS"
        assert isinstance(message_int, attribute.MessageIntegrityAttribute), "Should be MESSAGE-INTEGRITY"
        assert isinstance(fingerprint, attribute.FingerprintAttribute), "Should be FINGERPRINT"
        assert xor_mapped_address.port == 38272
        assert xor_mapped_address.address == '10.10.10.3'
        assert xor_mapped_address.family == attribute.XorMappedAddressAttribute.family_ipv4
