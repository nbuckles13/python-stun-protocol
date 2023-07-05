import struct
import unittest

import stun_protocol.attribute as attribute


class AttributeDerived(attribute.Attribute):
    def __init__(self, value: bytes = b'', **kwargs):
        super().__init__(**kwargs)
        self._value = value

    @property
    def value(self):
        return self._value

    @staticmethod
    def attribute_type() -> attribute.AttributeType:
        return 0

    def _unpack_value(self, buffer: bytes):
        self._value = buffer


class AttributeTestCase(unittest.TestCase):
    def test_empty_value(self):
        a = AttributeDerived(b'')
        self.assertEqual(a.type, 0)
        self.assertEqual(a.length, 0)
        self.assertEqual(a._value, b'')

    def test_nonempty_value(self):
        a = AttributeDerived(b'\x01\x02\x03\x04')
        self.assertEqual(a.type, 0)
        self.assertEqual(a.length, 4)
        self.assertEqual(a._value, b'\x01\x02\x03\x04')

    def test_pack_empty_value(self):
        a = AttributeDerived(b'')
        self.assertEqual(a.pack(), b'\x00\x00\x00\x00')

    def test_pack_nonempty_value(self):
        a = AttributeDerived(b'\x01\x02\x03\x04')
        self.assertEqual(a.pack(), b'\x00\x00\x00\x04\x01\x02\x03\x04')

    def test_pack_padding(self):
        a = AttributeDerived(b'\x01\x02\x03')
        self.assertEqual(a.pack(), b'\x00\x00\x00\x03\x01\x02\x03\x00')

    def test_pack_padding_value(self):
        a = AttributeDerived(b'\x01\x02\x03', padding_byte=b'\x90')
        self.assertEqual(a.pack(), b'\x00\x00\x00\x03\x01\x02\x03\x90')

    def test_packed_length_empty(self):
        a = AttributeDerived(b'')
        self.assertEqual(a.packed_length(), 4)

    def test_packed_length_nonempty_value(self):
        a = AttributeDerived(b'\x01\x02\x03\x04')
        self.assertEqual(a.packed_length(), 8)

    def test_packed_length_padding(self):
        a = AttributeDerived(b'\x01\x02\x03')
        self.assertEqual(a.packed_length(), 8)

    def test_create_empty_value(self):
        a = AttributeDerived.create(b'\x00\x00\x00\x00')
        self.assertEqual(a.type, 0)
        self.assertEqual(a.length, 0)
        self.assertEqual(a._value, b'')

    def test_create_nonempty_value(self):
        a = AttributeDerived.create(b'\x00\x00\x00\x04\x01\x02\x03\x04')
        self.assertEqual(a.type, 0)
        self.assertEqual(a.length, 4)
        self.assertEqual(a._value, b'\x01\x02\x03\x04')

    def test_create_invalid_type(self):
        self.assertRaises(ValueError, AttributeDerived.create, b'\x00\x01\x00\x00')

    def test_create_invalid_length_too_long(self):
        self.assertRaises(ValueError, AttributeDerived.create, b'\x00\x00\x00\x01')


class MappedAddressAttributeTestCase(unittest.TestCase):
    def test_construct(self):
        maa = attribute.MappedAddressAttribute(1, 2, b'\x03')
        self.assertEqual(maa.type, attribute.AttributeType.MAPPED_ADDRESS)
        self.assertEqual(maa.family, 1)
        self.assertEqual(maa._port, 2)
        self.assertEqual(maa._address, b'\x03')

    def test_value(self):
        maa = attribute.MappedAddressAttribute(4, 5, b'\x06\x07')
        self.assertEqual(maa.value, b'\x00\x04\x00\x05\x06\x07')

    def test_pack(self):
        maa = attribute.MappedAddressAttribute(8, 9, b'\x0A\x0B\x0C\x0D')
        self.assertEqual(maa.pack(), b'\x00\x01\x00\x08\x00\x08\x00\x09\x0A\x0B\x0C\x0D')

    def test_create(self):
        maa = attribute.MappedAddressAttribute.create(
            b'\x00\x01\x00\x0C\x00\x01\x11\x22\x0E\x0F\x0F\x0E\x0E\x0F\x0F\x0E')
        self.assertEqual(maa.family, 1)
        self.assertEqual(maa.port, 0x1122)
        self.assertEqual(maa.address, b'\x0E\x0F\x0F\x0E\x0E\x0F\x0F\x0E')

    def test_create_fail(self):
        self.assertRaises(ValueError, attribute.MappedAddressAttribute.create,
                          b'\x00\x02\x00\x08\x00\x08\x00\x09\x0A\x0B\x0C\x0D')


class XorMappedAddressAttributeTestCase(unittest.TestCase):
    def test_construct(self):
        maa = attribute.XorMappedAddressAttribute(1, 2, b'\x03')
        self.assertEqual(maa.type, attribute.AttributeType.XOR_MAPPED_ADDRESS)
        self.assertEqual(maa.family, 1)
        self.assertEqual(maa._port, 2)
        self.assertEqual(maa._address, b'\x03')

    def test_construct_from_setters(self):
        m = attribute.XorMappedAddressAttribute()
        m.port = 38272
        m.address = "10.10.10.3"
        assert m.port == 38272
        assert m.address == "10.10.10.3"
        assert m.value == b'\x00\x01\xb4\x92+\x18\xaeA'


class UsernameAttributeTestCase(unittest.TestCase):
    def test_construct(self):
        una = attribute.UsernameAttribute(b'username')
        self.assertEqual(una.type, attribute.AttributeType.USERNAME)
        self.assertEqual(una.username, b'username')

    def test_set_username(self):
        una = attribute.UsernameAttribute(b'username')
        una.username = b'somethingDifferent'
        self.assertEqual(una.username, b'somethingDifferent')

    def test_value(self):
        una = attribute.UsernameAttribute(b'username1')
        self.assertEqual(una.value, b'username1')

    def test_pack(self):
        una = attribute.UsernameAttribute(b'username12')
        self.assertEqual(una.pack(), b'\x00\x06\x00\x0Ausername12\x00\x00')

    def test_create(self):
        una = attribute.UsernameAttribute.create(b'\x00\x06\x00\x0Busername123\x00')
        self.assertEqual(una.username, b'username123')


class UserhashAttributeTestCase(unittest.TestCase):
    def test_construct(self):
        uha = attribute.UserhashAttribute(b'userhashuserhashuserhashuserhash')
        self.assertEqual(uha.type, attribute.AttributeType.USERHASH)
        self.assertEqual(uha.userhash, b'userhashuserhashuserhashuserhash')

    def test_fixed_value(self):
        self.assertEqual(attribute.UserhashAttribute.fixed_length(), 32)

    def test_value(self):
        uha = attribute.UserhashAttribute(b'userhashuserhashuserhashuserhash')
        self.assertEqual(uha.value, b'userhashuserhashuserhashuserhash')

    def test_set_userhash_invalid(self):
        uha = attribute.UserhashAttribute(b'userhashuserhashuserhashuserhash')
        with self.assertRaises(ValueError):
            uha.userhash = b'foo'

    def test_set_userhash_valid(self):
        uha = attribute.UserhashAttribute(b'userhashuserhashuserhashuserhash')
        uha.userhash = b'0' * uha.fixed_length()


class MessageIntegrityAttributeTestCase(unittest.TestCase):
    def test_construct(self):
        mia = attribute.MessageIntegrityAttribute(b'1' * 20)
        self.assertEqual(mia.type, attribute.AttributeType.MESSAGE_INTEGRITY)
        self.assertEqual(mia.hmac, b'1' * 20)

    def test_fixed_value(self):
        self.assertEqual(attribute.MessageIntegrityAttribute.fixed_length(), 20)

    def test_value(self):
        mia = attribute.MessageIntegrityAttribute(b'2' * 20)
        self.assertEqual(mia.value, b'2' * 20)

    def test_set_hmac_invalid(self):
        mia = attribute.MessageIntegrityAttribute(b'3' * 20)
        with self.assertRaises(ValueError):
            mia.hmac = b'foo'

    def test_set_hmac_valid(self):
        mia = attribute.MessageIntegrityAttribute(b'4' * 20)
        mia.hmac = b'5' * mia.fixed_length()


class MessageIntegritySha256AttributeTestCase(unittest.TestCase):
    def test_construct(self):
        mia = attribute.MessageIntegritySha256Attribute(b'1' * 20)
        self.assertEqual(mia.type, attribute.AttributeType.MESSAGE_INTEGRITY_SHA256)
        self.assertEqual(mia.hmac, b'1' * 20)

    def test_minimum_value(self):
        self.assertEqual(attribute.MessageIntegritySha256Attribute.minimum_length(), 16)

    def test_maximum_value(self):
        self.assertEqual(attribute.MessageIntegritySha256Attribute.maximum_length(), 32)

    def test_value(self):
        mia = attribute.MessageIntegritySha256Attribute(b'2' * 20)
        self.assertEqual(mia.value, b'2' * 20)

    def test_set_hmac_invalid_minimum(self):
        mia = attribute.MessageIntegritySha256Attribute(b'3' * 20)
        with self.assertRaises(ValueError):
            mia.hmac = b'4'*1

    def test_set_hmac_invalid_maximum(self):
        mia = attribute.MessageIntegritySha256Attribute(b'5' * 20)
        with self.assertRaises(ValueError):
            mia.hmac = b'6' * 40

    def test_set_hmac_valid(self):
        mia = attribute.MessageIntegritySha256Attribute(b'4' * 20)
        mia.hmac = b'7' * mia.minimum_length()
        mia.hmac = b'8' * mia.maximum_length()


class FingerprintAttributeTestCase(unittest.TestCase):
    def test_construct(self):
        fp = attribute.FingerprintAttribute(0x12345678)
        self.assertEqual(fp.type, attribute.AttributeType.FINGERPRINT)
        self.assertEqual(fp.fingerprint, 0x12345678)

    def test_value(self):
        fp = attribute.FingerprintAttribute(0x12345678)
        self.assertEqual(fp.value, b'\x12\x34\x56\x78')

    def test_unpack_value(self):
        fp = attribute.FingerprintAttribute(0x12345678)
        fp._unpack_value(b'\xF2\x34\x56\x79')
        self.assertEqual(fp.fingerprint, 0xF2345679)


class ErrorCodeAttributeTestCase(unittest.TestCase):
    def test_construct(self):
        eca = attribute.ErrorCodeAttribute(301, b'foo')
        self.assertEqual(eca.type, attribute.AttributeType.ERROR_CODE)
        self.assertEqual(eca.error_code, 301)
        self.assertEqual(eca.error_class, 3)
        self.assertEqual(eca.error_number, 1)
        self.assertEqual(eca.reason_phrase, b'foo')

    def test_value(self):
        eca = attribute.ErrorCodeAttribute(301, b'foo')
        self.assertEqual(eca.value, b'\x00\x00\x03\x01' + b'foo')

    def test_value_too_large(self):
        # error code can only carry values < 800
        eca = attribute.ErrorCodeAttribute(801, b'foo')
        self.assertEqual(eca.value, b'\x00\x00\x00\x01' + b'foo')

    def test_unpack_value(self):
        eca = attribute.ErrorCodeAttribute(301, b'foo')
        eca._unpack_value(b'\x00\x00\x04\x02' + b'foobar')
        self.assertEqual(eca.error_code, 402)
        self.assertEqual(eca.error_class, 4)
        self.assertEqual(eca.error_number, 2)
        self.assertEqual(eca.reason_phrase, b'foobar')

    def test_unpack_value_too_large(self):
        eca = attribute.ErrorCodeAttribute(301, b'foo')
        eca._unpack_value(b'\x01\x01\xFF\xFF' + b'foobar')
        self.assertEqual(eca.error_code, 755)
        self.assertEqual(eca.error_class, 7)
        self.assertEqual(eca.error_number, 55)
        self.assertEqual(eca.reason_phrase, b'foobar')


class RealmAttributeTestCase(unittest.TestCase):
    def test_construct(self):
        ra = attribute.RealmAttribute(b'realm')
        self.assertEqual(ra.type, attribute.AttributeType.REALM)
        self.assertEqual(ra.realm, b'realm')

    def test_set_realm(self):
        ra = attribute.RealmAttribute(b'realm')
        ra.realm = b'somethingDifferent'
        self.assertEqual(ra.realm, b'somethingDifferent')

    def test_value(self):
        ra = attribute.RealmAttribute(b'realm1')
        self.assertEqual(ra.value, b'realm1')


class NonceAttributeTestCase(unittest.TestCase):
    def test_construct(self):
        na = attribute.NonceAttribute(b'nonce')
        self.assertEqual(na.type, attribute.AttributeType.NONCE)
        self.assertEqual(na.nonce, b'nonce')

    def test_set_nonce(self):
        na = attribute.NonceAttribute(b'nonce')
        na.nonce = b'somethingDifferent'
        self.assertEqual(na.nonce, b'somethingDifferent')

    def test_value(self):
        na = attribute.NonceAttribute(b'nonce1')
        self.assertEqual(na.value, b'nonce1')


class PasswordAlgorithmsAttributeTestCase(unittest.TestCase):
    def test_construct(self):
        algorithms = [attribute.Algorithm(1, b'1234'), attribute.Algorithm(2, b'567')]
        paa = attribute.PasswordAlgorithmsAttribute(algorithms)
        self.assertEqual(paa.type, attribute.AttributeType.PASSWORD_ALGORITHMS)
        self.assertEqual(paa.algorithms, algorithms)

    def test_value(self):
        algorithms = [attribute.Algorithm(1, b'1234'), attribute.Algorithm(2, b'567')]
        paa = attribute.PasswordAlgorithmsAttribute(algorithms)
        self.assertEqual(paa.value, b'\x00\x01\x00\x04' + b'1234' + b'\x00\x02\x00\x03' + b'567' + b'\x00')

    def test_value_empty(self):
        paa = attribute.PasswordAlgorithmsAttribute([])
        self.assertEqual(paa.value, b'')

    def test_unpack_value(self):
        paa = attribute.PasswordAlgorithmsAttribute([])
        paa._unpack_value(b'\x00\x07\x00\x04' + b'aaaa' + b'\xFF\xFF\x00\x01' + b'bbbb')
        self.assertEqual(len(paa.algorithms), 2)
        self.assertEqual(paa.algorithms[0], attribute.Algorithm(7, b'aaaa'))
        self.assertEqual(paa.algorithms[1], attribute.Algorithm(0xFFFF, b'b'))

    def test_unpack_value_empty(self):
        algorithms = [attribute.Algorithm(1, b'1234'), attribute.Algorithm(2, b'567')]
        paa = attribute.PasswordAlgorithmsAttribute(algorithms)
        paa._unpack_value(b'')
        self.assertEqual(paa.algorithms, [])


class PasswordAlgorithmAttributeTestCase(unittest.TestCase):
    def test_construct(self):
        algorithm = attribute.Algorithm(1, b'1234')
        paa = attribute.PasswordAlgorithmAttribute(algorithm)
        self.assertEqual(paa.type, attribute.AttributeType.PASSWORD_ALGORITHM)
        self.assertEqual(paa.algorithm, algorithm)

    def test_value(self):
        algorithm = attribute.Algorithm(1, b'1234')
        paa = attribute.PasswordAlgorithmAttribute(algorithm)
        self.assertEqual(paa.value, b'\x00\x01\x00\x04' + b'1234')

    def test_unpack_value(self):
        algorithm = attribute.Algorithm(1, b'1234')
        paa = attribute.PasswordAlgorithmAttribute(algorithm)
        paa._unpack_value(b'\x00\x07\x00\x04' + b'aaaa')
        self.assertEqual(paa.algorithm, attribute.Algorithm(7, b'aaaa'))


class UnknownAttributesAttributeTestCase(unittest.TestCase):
    def test_construct(self):
        uaa = attribute.UnknownAttributesAttribute([1, 2, 3])
        self.assertEqual(uaa.type, attribute.AttributeType.UNKNOWN_ATTRIBUTES)
        self.assertEqual(uaa.unknown_attributes, [1, 2, 3])

    def test_value(self):
        uaa = attribute.UnknownAttributesAttribute([1, 2, 3])
        self.assertEqual(uaa.value, b'\x00\x01\x00\x02\x00\x03')

    def test_value_empty(self):
        uaa = attribute.UnknownAttributesAttribute([])
        self.assertEqual(uaa.value, b'')

    def test_unpack_value(self):
        uaa = attribute.UnknownAttributesAttribute([1, 2, 3])
        uaa._unpack_value(b'\x12\x34\xFF\x00')
        self.assertEqual(uaa.unknown_attributes, [0x1234, 0xFF00])


class SoftwareAttributeTestCase(unittest.TestCase):
    def test_construct(self):
        na = attribute.SoftwareAttribute(b'software')
        self.assertEqual(na.type, attribute.AttributeType.SOFTWARE)
        self.assertEqual(na.software, b'software')

    def test_set_software(self):
        na = attribute.SoftwareAttribute(b'software')
        na.software = b'somethingDifferent'
        self.assertEqual(na.software, b'somethingDifferent')


class AlternateServerAttributeTestCase(unittest.TestCase):
    def test_construct(self):
        asa = attribute.AlternateServerAttribute(1, 2, b'\x03')
        self.assertEqual(asa.type, attribute.AttributeType.ALTERNATE_SERVER)
        self.assertEqual(asa.family, 1)
        self.assertEqual(asa._port, 2)
        self.assertEqual(asa._address, b'\x03')


class AlternateDomainAttributeTestCase(unittest.TestCase):
    def test_construct(self):
        ada = attribute.AlternateDomainAttribute(b'domain')
        self.assertEqual(ada.type, attribute.AttributeType.ALTERNATE_DOMAIN)
        self.assertEqual(ada.alternate_domain, b'domain')

    def test_set_alternate_domain(self):
        ada = attribute.AlternateDomainAttribute(b'domain')
        ada.alternate_domain = b'somethingDifferent'
        self.assertEqual(ada.alternate_domain, b'somethingDifferent')


class PriorityAttributeTestCase(unittest.TestCase):
    def test_construct(self):
        pa = attribute.PriorityAttribute(0x12345678)
        self.assertEqual(pa.type, attribute.AttributeType.PRIORITY)
        self.assertEqual(pa.priority, 0x12345678)

    def test_set_priority(self):
        pa = attribute.PriorityAttribute(0x12345678)
        pa.priority = 0x90ABCDEF
        self.assertEqual(pa.priority, 0x90ABCDEF)

    def test_value(self):
        pa = attribute.PriorityAttribute(0x12345678)
        self.assertEqual(pa.value, b'\x12\x34\x56\x78')

    def test_pack(self):
        pa = attribute.PriorityAttribute(0x12345678)
        self.assertEqual(pa.pack(), b'\x00\x24\x00\x04\x12\x34\x56\x78')

    def test_create(self):
        pa = attribute.PriorityAttribute.create(b'\x00\x24\x00\x04\x12\x34\x56\x79')
        self.assertEqual(pa.priority, 0x12345679)


class UseCandidateAttributeTestCase(unittest.TestCase):
    def test_construct(self):
        uca = attribute.UseCandidateAttribute()
        self.assertEqual(uca.type, attribute.AttributeType.USE_CANDIDATE)

    def test_value(self):
        uca = attribute.UseCandidateAttribute()
        self.assertEqual(uca.value, b'')

    def test_pack(self):
        uca = attribute.UseCandidateAttribute()
        self.assertEqual(uca.pack(), b'\x00\x25\x00\x00')

    def test_create(self):
        uca = attribute.UseCandidateAttribute.create(b'\x00\x25\x00\x00')
        self.assertEqual(uca.type, attribute.AttributeType.USE_CANDIDATE)


class IceControlledAttributeTestCase(unittest.TestCase):
    def test_construct(self):
        ica = attribute.IceControlledAttribute(0x1234567890ABCDEF)
        self.assertEqual(ica.type, attribute.AttributeType.ICE_CONTROLLED)
        self.assertEqual(ica.random_number, 0x1234567890ABCDEF)

    def test_set_random_number(self):
        ica = attribute.IceControlledAttribute(0x1234567890ABCDEF)
        ica.random_number = 0x12
        self.assertEqual(ica.random_number, 0x12)

    def test_value(self):
        ica = attribute.IceControlledAttribute(0x1234567890ABCDEF)
        self.assertEqual(ica.value, b'\x12\x34\x56\x78\x90\xAB\xCD\xEF')

    def test_pack(self):
        ica = attribute.IceControlledAttribute(0x1234567890ABCDEF)
        self.assertEqual(ica.pack(), b'\x80\x29\x00\x08\x12\x34\x56\x78\x90\xAB\xCD\xEF')

    def test_create(self):
        ica = attribute.IceControlledAttribute.create(b'\x80\x29\x00\x08\x12\x34\x56\x78\x90\xAB\xCD\xEE')
        self.assertEqual(ica.random_number, 0x1234567890ABCDEE)


class IceControllingAttributeTestCase(unittest.TestCase):
    def test_construct(self):
        ica = attribute.IceControllingAttribute(0x1234567890ABCDEF)
        self.assertEqual(ica.type, attribute.AttributeType.ICE_CONTROLLING)
        self.assertEqual(ica.random_number, 0x1234567890ABCDEF)


class AttributeCreateTestCase(unittest.TestCase):
    def test_create_valid(self):
        attribute_classes = [attribute.MappedAddressAttribute,
                             attribute.UsernameAttribute,
                             attribute.MessageIntegrityAttribute,
                             attribute.ErrorCodeAttribute,
                             attribute.UnknownAttributesAttribute,
                             attribute.RealmAttribute,
                             attribute.NonceAttribute,
                             attribute.MessageIntegritySha256Attribute,
                             attribute.PasswordAlgorithmAttribute,
                             attribute.UserhashAttribute,
                             attribute.XorMappedAddressAttribute,
                             attribute.PasswordAlgorithmsAttribute,
                             attribute.AlternateDomainAttribute,
                             attribute.SoftwareAttribute,
                             attribute.AlternateServerAttribute,
                             attribute.FingerprintAttribute]
        for cls in attribute_classes:
            a1 = cls()
            a2 = attribute.create(a1.pack())
            self.assertEqual(a1, a2, f'{cls}')

    def test_create_empty_buffer(self):
        self.assertRaises(struct.error, attribute.create, b'')

    def test_create_invalid_type(self):
        self.assertRaises(ValueError, attribute.create, b'\x00\x00\x00\x00')
