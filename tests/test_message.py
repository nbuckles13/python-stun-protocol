import unittest

import stun_protocol.message as message
from stun_protocol.attribute import FingerprintAttribute, IceControlledAttribute, MappedAddressAttribute, MappedAddressAttributeBase, PriorityAttribute, \
    SoftwareAttribute, UsernameAttribute, XorMappedAddressAttribute, UndefinedAttribute


class MessageTestCase(unittest.TestCase):
    def test_pack_message_type(self):
        m = message.Message(message.MessageClass.REQUEST,
                            message.MessageMethod.BINDING)
        self.assertEqual(m._pack_message_type(), 0b000000000001)

        m = message.Message(message.MessageClass.INDICATION,
                            message.MessageMethod.BINDING)
        self.assertEqual(m._pack_message_type(), 0b000000010001)

        m = message.Message(
            message.MessageClass.SUCCESS_RESPONSE, message.MessageMethod.BINDING)
        self.assertEqual(m._pack_message_type(), 0b000100000001)

        m = message.Message(message.MessageClass.ERROR_RESPONSE,
                            message.MessageMethod.BINDING)
        self.assertEqual(m._pack_message_type(), 0b000100010001)

        m = message.Message(message.MessageClass.REQUEST,
                            message.MessageMethod.CONNECTION_BIND)
        self.assertEqual(m._pack_message_type(), 0b000000001011)

        m = message.Message(message.MessageClass.INDICATION,
                            message.MessageMethod.CONNECTION_BIND)
        self.assertEqual(m._pack_message_type(), 0b000000011011)

        m = message.Message(message.MessageClass.SUCCESS_RESPONSE,
                            message.MessageMethod.CONNECTION_BIND)
        self.assertEqual(m._pack_message_type(), 0b000100001011)

        m = message.Message(message.MessageClass.ERROR_RESPONSE,
                            message.MessageMethod.CONNECTION_BIND)
        self.assertEqual(m._pack_message_type(), 0b000100011011)

        m = message.Message(message.MessageClass.REQUEST,
                            message.MessageMethod.GOOG_PING)
        self.assertEqual(m._pack_message_type(), 0b001000000000)

        m = message.Message(message.MessageClass.INDICATION,
                            message.MessageMethod.GOOG_PING)
        self.assertEqual(m._pack_message_type(), 0b001000010000)

        m = message.Message(message.MessageClass.SUCCESS_RESPONSE,
                            message.MessageMethod.GOOG_PING)
        self.assertEqual(m._pack_message_type(), 0b001100000000)

        m = message.Message(message.MessageClass.ERROR_RESPONSE,
                            message.MessageMethod.GOOG_PING)
        self.assertEqual(m._pack_message_type(), 0b001100010000)

    def test_packed_length_no_attributes(self):
        m = message.Message(message.MessageClass.REQUEST,
                            message.MessageMethod.BINDING)
        self.assertEqual(m.packed_length(), 20)

    def test_packed_length_with_attributes(self):
        una = UsernameAttribute(b'123')
        fa = FingerprintAttribute(0xA5A5A5A5)
        m = message.Message(message.MessageClass.REQUEST,
                            message.MessageMethod.BINDING, attributes=[una, fa])
        self.assertEqual(m.packed_length(), 36)

    def test_message_length_no_attributes(self):
        m = message.Message(message.MessageClass.REQUEST,
                            message.MessageMethod.BINDING)
        self.assertEqual(m.message_length, 0)

    def test_message_length_with_attributes(self):
        una = UsernameAttribute(b'123')
        fa = FingerprintAttribute(0xA5A5A5A5)
        m = message.Message(message.MessageClass.REQUEST,
                            message.MessageMethod.BINDING, attributes=[una, fa])
        self.assertEqual(m.message_length, 16)

    def test_pack_no_attributes(self):
        m = message.Message(message.MessageClass.REQUEST,
                            message.MessageMethod.BINDING, b'\x01' * 12)
        self.assertEqual(
            m.pack(), b'\x00\x01\x00\x00\x21\x12\xA4\x42' + b'\x01' * 12)

    def test_pack_with_attributes(self):
        una = UsernameAttribute(b'123')
        fa = FingerprintAttribute(0xA5A5A5A5)

        m = message.Message(message.MessageClass.REQUEST,
                            message.MessageMethod.BINDING, b'\x01' * 12, [una, fa])
        self.assertEqual(m.pack(), b'\x00\x01\x00\x10\x21\x12\xA4\x42' +
                         b'\x01' * 12 + una.pack() + fa.pack())

    def test_unpack_no_attributes(self):
        m1 = message.Message(message.MessageClass.REQUEST,
                             message.MessageMethod.BINDING)
        m2 = message.Message(message.MessageClass.INDICATION,
                             message.MessageMethod.CHANNEL_BIND)

        m2.unpack(m1.pack())
        self.assertEqual(m1, m2)

    def test_unpack_with_attributes(self):
        una = UsernameAttribute(b'123')
        fa = FingerprintAttribute(0xA5A5A5A5)

        m1 = message.Message(message.MessageClass.REQUEST,
                             message.MessageMethod.BINDING, b'\x01' * 12, [una, fa])
        m2 = message.Message(message.MessageClass.INDICATION,
                             message.MessageMethod.CHANNEL_BIND)

        m2.unpack(m1.pack())
        self.assertEqual(m1, m2)

    def test_unpack_with_undefined_attributes(self):
        ua = UndefinedAttribute(0, b'\x01' * 8)
        fa = FingerprintAttribute(0xA5A5A5A5)

        m1 = message.Message(message.MessageClass.REQUEST,
                             message.MessageMethod.BINDING, b'\x01' * 12, [ua, fa])
        m2 = message.Message(message.MessageClass.INDICATION,
                             message.MessageMethod.CHANNEL_BIND)

        m2.unpack(m1.pack(), unpack_undefined_attributes=True)
        self.assertEqual(m1, m2)

    def test_create(self):
        m1 = message.Message(message.MessageClass.REQUEST,
                             message.MessageMethod.BINDING)
        m2 = message.Message.create(m1.pack())
        self.assertEqual(m1, m2)

    def test_add_attribute(self):
        una = UsernameAttribute(b'123')

        m = message.Message(message.MessageClass.REQUEST,
                            message.MessageMethod.BINDING)
        m.add_attribute(una)
        self.assertEqual(len(m.attributes), 1)

    def test_add_message_integrity_attribute(self):
        m = message.Message(message.MessageClass.REQUEST,
                            message.MessageMethod.BINDING, transaction_id=b'\x00' * 12)
        m.add_message_integrity_attribute(b'0' * 20)
        self.assertEqual(len(m.attributes), 1)
        self.assertEqual(
            m.attributes[0].hmac, b'\xc5\x1f\xc5\xe7\x5a\xf0\xe7\x94\x2d\xc1\xdf\x5e\xf6\x15\xcb\xbc\x39\x46\x44\x85')

    def test_add_message_integrity_sha256_attribute(self):
        m = message.Message(message.MessageClass.REQUEST,
                            message.MessageMethod.BINDING, transaction_id=b'\x00' * 12)
        m.add_message_integrity_sha256_attribute(b'0' * 64)
        self.assertEqual(len(m.attributes), 1)
        self.assertEqual(
            m.attributes[0].hmac,
            b'\x73\x15\xe4\x58\xc0\x29\x4b\x23\x96\x2c\x5e\x5b\x03\x02\x36\xb7\x73\xa8\x00\x75\xa4\x24\xc6\xbd\x82\x66' +
            b'\x29\x61\x39\x42\xfb\x56')

    def test_add_fingerprint_attribute(self):
        m = message.Message(message.MessageClass.REQUEST,
                            message.MessageMethod.BINDING, transaction_id=b'\x00' * 12)
        m.add_fingerprint_attribute()
        self.assertEqual(len(m.attributes), 1)
        self.assertEqual(m.attributes[0].fingerprint, 0xb2aaf9f6)

    def test_add_xor_mapped_address_attribute_v4(self):
        m = message.Message(message.MessageClass.REQUEST,
                            message.MessageMethod.BINDING, transaction_id=b'\x00' * 12)
        m.add_xor_mapped_address_attribute_v4(0x1234, 0x567890AB)
        self.assertEqual(len(m.attributes), 1)
        self.assertEqual(m.attributes[0].family,
                         MappedAddressAttributeBase.family_ipv4)
        self.assertEqual(m.attributes[0].port, 0x3326)
        self.assertEqual(m.attributes[0].address, b'\x77\x6A\x34\xE9')

    def test_sample_request_rfc5769_2_dot_1(self):
        # Taken from https://datatracker.ietf.org/doc/html/rfc5769#section-2.1
        test_vector = b'' + \
            b'\x00\x01\x00\x58' + \
            b'\x21\x12\xa4\x42' + \
            b'\xb7\xe7\xa7\x01' + \
            b'\xbc\x34\xd6\x86' + \
            b'\xfa\x87\xdf\xae' + \
            b'\x80\x22\x00\x10' + \
            b'\x53\x54\x55\x4e' + \
            b'\x20\x74\x65\x73' + \
            b'\x74\x20\x63\x6c' + \
            b'\x69\x65\x6e\x74' + \
            b'\x00\x24\x00\x04' + \
            b'\x6e\x00\x01\xff' + \
            b'\x80\x29\x00\x08' + \
            b'\x93\x2f\xf9\xb1' + \
            b'\x51\x26\x3b\x36' + \
            b'\x00\x06\x00\x09' + \
            b'\x65\x76\x74\x6a' + \
            b'\x3a\x68\x36\x76' + \
            b'\x59\x20\x20\x20' + \
            b'\x00\x08\x00\x14' + \
            b'\x9a\xea\xa7\x0c' + \
            b'\xbf\xd8\xcb\x56' + \
            b'\x78\x1e\xf2\xb5' + \
            b'\xb2\xd3\xf2\x49' + \
            b'\xc1\xb5\x71\xa2' + \
            b'\x80\x28\x00\x04' + \
            b'\xe5\x7a\x3b\xcf'

        m = message.Message(message.MessageClass.REQUEST, message.MessageMethod.BINDING,
                            transaction_id=b'\xb7\xe7\xa7\x01\xbc\x34\xd6\x86\xfa\x87\xdf\xae',
                            attribute_padding_byte=b'\x20')
        m.add_attribute(SoftwareAttribute(b'STUN test client'))
        m.add_attribute(PriorityAttribute(0x6e0001ff))
        m.add_attribute(IceControlledAttribute(0x932ff9b151263b36))
        m.add_attribute(UsernameAttribute(b'evtj:h6vY'))
        m.add_message_integrity_attribute(b'VOkJxbRl1RmTxUk/WvJxBt')
        m.add_fingerprint_attribute()
        self.assertEqual(m.pack(), test_vector)

    def test_sample_request_rfc5769_2_dot_2(self):
        # Taken from https://datatracker.ietf.org/doc/html/rfc5769#section-2.2
        test_vector = b'' + \
            b'\x01\x01\x00\x3c' + \
            b'\x21\x12\xa4\x42' + \
            b'\xb7\xe7\xa7\x01' + \
            b'\xbc\x34\xd6\x86' + \
            b'\xfa\x87\xdf\xae' + \
            b'\x80\x22\x00\x0b' + \
            b'\x74\x65\x73\x74' + \
            b'\x20\x76\x65\x63' + \
            b'\x74\x6f\x72\x20' + \
            b'\x00\x20\x00\x08' + \
            b'\x00\x01\xa1\x47' + \
            b'\xe1\x12\xa6\x43' + \
            b'\x00\x08\x00\x14' + \
            b'\x2b\x91\xf5\x99' + \
            b'\xfd\x9e\x90\xc3' + \
            b'\x8c\x74\x89\xf9' + \
            b'\x2a\xf9\xba\x53' + \
            b'\xf0\x6b\xe7\xd7' + \
            b'\x80\x28\x00\x04' + \
            b'\xc0\x7d\x4c\x96'

        m = message.Message(message.MessageClass.SUCCESS_RESPONSE, message.MessageMethod.BINDING,
                            transaction_id=b'\xb7\xe7\xa7\x01\xbc\x34\xd6\x86\xfa\x87\xdf\xae',
                            attribute_padding_byte=b'\x20')
        m.add_attribute(SoftwareAttribute(b'test vector'))
        m.add_xor_mapped_address_attribute_v4(32853, 0xC0000201)
        m.add_message_integrity_attribute(b'VOkJxbRl1RmTxUk/WvJxBt')
        m.add_fingerprint_attribute()

        self.assertEqual(m.pack(), test_vector)
