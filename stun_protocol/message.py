import binascii

import hmac
import secrets
import struct

from enum import IntEnum
from hashlib import sha1, sha256
from typing import List, Type
from stun_protocol import attribute

from stun_protocol.attribute import Attribute, FingerprintAttribute, MessageIntegrityAttribute, \
    MessageIntegritySha256Attribute, XorMappedAddressAttribute, MappedAddressAttributeBase
from stun_protocol.common import MAGIC_COOKIE

class MessageClass(IntEnum):
    'https://datatracker.ietf.org/doc/html/rfc8489#section-5'
    REQUEST = 0b00
    INDICATION = 0b01
    SUCCESS_RESPONSE = 0b10
    ERROR_RESPONSE = 0b11


class MessageMethod(IntEnum):
    'https://www.iana.org/assignments/stun-parameters/stun-parameters.xhtml'
    BINDING = 0x001
    ALLOCATE = 0x003
    REFRESH = 0x004
    SEND = 0x006
    DATA = 0x007
    CREATE_PERMISSION = 0x008
    CHANNEL_BIND = 0x009
    CONNECT = 0x00A
    CONNECTION_BIND = 0x00B
    CONNECTION_ATTEMPT = 0x0C
    GOOG_PING = 0x080


class Message():
    STRUCT_HEADER_FORMAT = '!HHI12s'

    def __init__(self,
                 message_class: MessageClass,
                 message_method: MessageMethod,
                 transaction_id: bytes = None,
                 attributes: List[Attribute] = [],
                 attribute_padding_byte=b'\x00'):
        self.message_class = message_class
        self.message_method = message_method
        self.transaction_id = transaction_id if transaction_id is not None else self.generate_transaction_id()
        self.attribute_padding_byte = attribute_padding_byte
        self.attributes = []

        [self.add_attribute(a) for a in attributes]

    def __eq__(self, o: 'Message') -> bool:
        if isinstance(o, Message):
            return ((self.message_class == o.message_class) and (self.message_method == o.message_method) and
                    (self.transaction_id == o.transaction_id) and (self.attributes == o.attributes))

    @property
    def message_length(self) -> int:
        return sum(a.packed_length() for a in self.attributes)

    @classmethod
    def generate_transaction_id(cls: 'Message') -> bytes:
        return secrets.token_bytes(12)

    def _pack_message_type(self) -> int:
        message_type = 0

        # message class is encoded into the 11th and 7th bits
        message_type |= (self.message_class & 0x0001) << 4
        message_type |= (self.message_class & 0x0002) << 7

        # message method is encoded into the 2nd-6th, 8th-10th, and 12th-15th bits
        message_type |= (self.message_method & 0x000F) << 0
        message_type |= (self.message_method & 0x0070) << 1
        message_type |= (self.message_method & 0x0180) << 2

        return message_type

    def _unpack_message_type(self, message_type) -> None:
        # message class is encoded into the 11th and 7th bits
        self.message_class = ((message_type & 0x0100) >> 7) | ((message_type & 0x0010) >> 4)

        # message method is encoded into the 2nd-6th, 8th-10th, and 12th-15th bits
        self.message_method = ((message_type & 0x3E00) >> 2) | (
            (message_type & 0x00E0) >> 1) | ((message_type & 0x000F) >> 0)

    def packed_length(self) -> int:
        return struct.calcsize(self.STRUCT_HEADER_FORMAT) + sum([a.packed_length() for a in self.attributes])

    def pack(self) -> bytes:
        packed_attributes = b''.join(a.pack() for a in self.attributes)
        return struct.pack(self.STRUCT_HEADER_FORMAT, self._pack_message_type(), self.message_length,
                           MAGIC_COOKIE, self.transaction_id) + packed_attributes

    def unpack(self, buffer: bytes):
        (message_type, message_length, _, self.transaction_id) = struct.unpack(self.STRUCT_HEADER_FORMAT, buffer[:20])
        self._unpack_message_type(message_type)

        remaining_buffer = buffer[20:]
        remaining_length = len(remaining_buffer)
        if message_length > remaining_length:
            raise ValueError(
                f'STUN message length {message_length} is longer than the remainder of the given buffer {remaining_length}')

        offset = 0
        while offset < remaining_length:
            a = attribute.create(remaining_buffer[offset:])

            self.attributes.append(a)
            offset += a.packed_length()

    @classmethod
    def create(cls: 'Message', buffer: bytes) -> 'Message':
        m = Message(MessageClass.REQUEST, MessageMethod.BINDING)
        m.unpack(buffer)
        return m

    def add_attribute(self, attribute: Type[Attribute]) -> None:
        attribute.padding_byte = self.attribute_padding_byte
        self.attributes.append(attribute)

    def add_message_integrity_attribute(self, key: bytes) -> None:
        # 1. add a message integrity attribute with an arbitrary value
        mia = MessageIntegrityAttribute(b'0' * MessageIntegrityAttribute.fixed_length())
        self.attributes.append(mia)

        # 2. pack the stun message
        packed_message = self.pack()

        # 3. run hmac-sha1 over the packed stun message, up to the start of the message integrity attribute itself
        mia_value = hmac.new(key, packed_message[0:-mia.packed_length()], sha1).digest()
        self.attributes[-1].hmac = mia_value

    def add_message_integrity_sha256_attribute(self, key: bytes) -> None:
        # 1. add a message integrity sha 256 attribute with an arbitrary value
        mia = MessageIntegritySha256Attribute(b'0' * MessageIntegritySha256Attribute.maximum_length())
        self.attributes.append(mia)

        # 2. pack the stun message
        packed_message = self.pack()

        # 3. run hmac-sha256 over the packed stun message, up to the start of the message integrity attribute itself
        mia_value = hmac.new(key, packed_message[0:-mia.packed_length()], sha256).digest()
        self.attributes[-1].hmac = mia_value

    def add_fingerprint_attribute(self) -> None:
        # 1. add a fingerprint attribute with an arbitrary value
        fpa = FingerprintAttribute(0)
        self.attributes.append(fpa)

        # 2. pack the stun message
        packed_message = self.pack()

        # 3. run crc32 over the packed stun message, up to the start of the fingerprint attribute itself
        fpa_value = binascii.crc32(packed_message[0:-fpa.packed_length()], 0) ^ 0x5354554e
        self.attributes[-1].fingerprint = fpa_value

    def add_xor_mapped_address_attribute_v4(self, port: int, address: int) -> None:
        # 1. xor the port with the most 16 significant bits of the cookie
        port = port ^ ((MAGIC_COOKIE & 0xFFFF0000) >> 16)

        # 2. xor the address with the magic cookie and convert to bytes
        address = address ^ MAGIC_COOKIE
        address = address.to_bytes(length=4, byteorder='big')

        # 3. add an XorMappedAddressAttribute with the calculated values
        xmaa = XorMappedAddressAttribute(MappedAddressAttributeBase.family_ipv4, port, address)
        self.add_attribute(xmaa)
