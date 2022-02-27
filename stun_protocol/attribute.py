from __future__ import annotations
from random import random

import struct

from abc import ABC, abstractmethod
from enum import IntEnum
from typing import List, Type, TypeVar


class AttributeType(IntEnum):
    'https://datatracker.ietf.org/doc/html/rfc8489#section-18.3'

    'Comprehension-required range (0x0000-0x7FFF):'
    RESERVED = 0x0000
    MAPPED_ADDRESS = 0x0001
    USERNAME = 0x0006
    MESSAGE_INTEGRITY = 0x0008
    ERROR_CODE = 0x0009
    UNKNOWN_ATTRIBUTES = 0X000a
    REALM = 0X0014
    NONCE = 0X0015
    MESSAGE_INTEGRITY_SHA256 = 0x001C
    PASSWORD_ALGORITHM = 0x001D
    USERHASH = 0x001E
    XOR_MAPPED_ADDRESS = 0x0020

    'Comprehension-optional range (0x8000-0xFFFF)'
    PASSWORD_ALGORITHMS = 0x8002
    ALTERNATE_DOMAIN = 0x8003
    SOFTWARE = 0x8022
    ALTERNATE_SERVER = 0x8023
    FINGERPRINT = 0x8028

    'https://datatracker.ietf.org/doc/html/rfc8445#section-16'
    PRIORITY = 0x0024
    USE_CANDIDATE = 0x0025
    ICE_CONTROLLED = 0x8029
    ICE_CONTROLLING = 0x802A


def _padding_length(length: int) -> int:
    return [0, 3, 2, 1][length % 4]


class Attribute(ABC):
    'https://datatracker.ietf.org/doc/html/rfc8489#section-14'

    def __init__(self, padding_byte: bytes = b'\x00'):
        self.padding_byte = padding_byte

    def __eq__(self, o: object) -> bool:
        if isinstance(o, Attribute):
            return ((self.type == o.type) and (self.length == o.length) and (self.value == o.value))

        return False

    def __str__(self) -> str:
        return f'{self.type} {self.length} {self.value}'

    @property
    def type(self) -> AttributeType:
        return self.attribute_type()

    @property
    def length(self) -> int:
        return len(self.value)

    @property
    @abstractmethod
    def value(self) -> bytes:
        return b''

    @classmethod
    @abstractmethod
    def attribute_type(cls: Type[Attribute]) -> AttributeType:
        return AttributeType.RESERVED

    def packed_length(self) -> int:
        return 4 + self.length + _padding_length(self.length)

    def pack(self) -> bytes:
        value = self.value
        length = len(value)
        padding_length = _padding_length(length)
        return struct.pack(f'!HH{length}s{padding_length}s', self.type, length, value, self.padding_byte * padding_length)

    def _unpack(self, buffer: bytes) -> None:
        (attribute_type, attribute_length) = struct.unpack('!HH', buffer[:4])
        if attribute_type != self.attribute_type():
            # maybe return a custom exception here
            raise ValueError(
                f'Invalid STUN attribute type {attribute_type}, expected {self.attribute_type()} for {type(self).__name__}')

        buffer_length = len(buffer)
        max_attribute_length = buffer_length - 4
        if attribute_length > max_attribute_length:
            # maybe return a custom exception here
            raise ValueError(
                f'STUN attribute length {attribute_length} is longer than the remainder of the given buffer {max_attribute_length}')

        self._unpack_value(buffer[4:attribute_length+4])

    @abstractmethod
    def _unpack_value(self, buffer: bytes) -> None:
        pass

    @classmethod
    def create(cls: Type[Attribute], buffer: bytes) -> Type[Attribute]:
        a = cls()
        a._unpack(buffer)
        return a


class MappedAddressAttributeBase(Attribute):
    _fixed_format_string = '!BBH'
    _full_format_string = _fixed_format_string + '%ds'

    family_ipv4 = 0x01
    family_ipv6 = 0x02

    def __init__(self, family: int = family_ipv4, port: int = 0, address: bytes = bytes(), **kwargs):
        super().__init__(**kwargs)
        self.family = family
        self.port = port
        self.address = address

    @property
    def value(self) -> bytes:
        return struct.pack(self._full_format_string % len(self.address), 0, self.family, self.port, self.address)

    def _unpack_value(self, buffer: bytes) -> None:
        address_length = len(buffer) - struct.calcsize(self._fixed_format_string)
        (_, self.family, self.port, self.address) = struct.unpack(self._full_format_string % address_length, buffer)


class IntAttributeBase(Attribute):
    def __init__(self, int_value: int, struct_format_letter: str, **kwargs):
        super().__init__(**kwargs)
        self._int_value = int_value
        self._struct_format_string = '!' + struct_format_letter

    def _unpack_value(self, buffer: bytes) -> None:
        (self._int_value,) = struct.unpack(self._struct_format_string, buffer)

    @property
    def value(self) -> bytes:
        return struct.pack(self._struct_format_string, self._int_value)


class StringAttributeBase(Attribute):
    def __init__(self, string_value: bytes = bytes(), **kwargs):
        super().__init__(**kwargs)
        self._string_value = string_value

    def _unpack_value(self, buffer: bytes) -> None:
        self._string_value = buffer

    @property
    def value(self) -> bytes:
        return self._string_value


class LengthCheckedAttributeBase(Attribute):
    def __init__(self, bytes_value: bytes, **kwargs):
        super().__init__(**kwargs)
        self._set_value(bytes_value if bytes_value else b'\x00' * self.minimum_length())

    @classmethod
    @abstractmethod
    def minimum_length(cls: Type[Attribute]) -> int:
        return 0

    @classmethod
    @abstractmethod
    def maximum_length(cls: Type[Attribute]) -> int:
        return 0

    def _check_length(self, value: bytes) -> None:
        actual_length = len(value)
        minimum_length = self.minimum_length()
        maximum_length = self.maximum_length()

        if actual_length < minimum_length or actual_length > maximum_length:
            raise ValueError(
                f'{type(self).__name__} requires a value of length >= {minimum_length} and <= {maximum_length} bytes, found {actual_length}')

    def _unpack_value(self, buffer: bytes) -> None:
        self._set_value(buffer)

    def _set_value(self, value: bytes) -> None:
        self._check_length(value)
        self._bytes_value = value

    @property
    def value(self) -> bytes:
        return self._bytes_value


class LengthFixedAttributeBase(LengthCheckedAttributeBase):
    @classmethod
    def minimum_length(cls: Type[LengthCheckedAttributeBase]) -> int:
        return cls.fixed_length()

    @classmethod
    def maximum_length(cls: Type[LengthCheckedAttributeBase]) -> int:
        return cls.fixed_length()

    @classmethod
    @abstractmethod
    def fixed_length(cls: Type[LengthFixedAttributeBase]) -> int:
        return 0


class IceControlAttributeBase(IntAttributeBase):
    def __init__(self, random_number: int = 0, **kwargs):
        super().__init__(random_number, 'Q', **kwargs)

    @property
    def random_number(self) -> int:
        return self._int_value

    @random_number.setter
    def random_number(self, random_number) -> None:
        self._int_value = random_number


class MappedAddressAttribute(MappedAddressAttributeBase):
    'https://datatracker.ietf.org/doc/html/rfc8489#section-14.1'
    @classmethod
    def attribute_type(cls: Type[Attribute]) -> AttributeType:
        return AttributeType.MAPPED_ADDRESS


class XorMappedAddressAttribute(MappedAddressAttributeBase):
    @classmethod
    def attribute_type(cls: Type[Attribute]) -> AttributeType:
        return AttributeType.XOR_MAPPED_ADDRESS


class UsernameAttribute(StringAttributeBase):
    def __init__(self, username: bytes = bytes(), **kwargs):
        super().__init__(username, **kwargs)

    @classmethod
    def attribute_type(cls: Type[Attribute]) -> AttributeType:
        return AttributeType.USERNAME

    @property
    def username(self) -> bytes:
        return self._string_value

    @username.setter
    def username(self, value: bytes) -> None:
        self._string_value = value


class UserhashAttribute(LengthFixedAttributeBase):
    def __init__(self, userhash: bytes = bytes(), **kwargs):
        super().__init__(userhash, **kwargs)

    @staticmethod
    def fixed_length() -> int:
        return 32

    @classmethod
    def attribute_type(cls: Type[Attribute]) -> AttributeType:
        return AttributeType.USERHASH

    @property
    def userhash(self) -> bytes:
        return self._bytes_value

    @userhash.setter
    def userhash(self, value: bytes) -> None:
        self._set_value(value)


class MessageIntegrityAttribute(LengthFixedAttributeBase):
    def __init__(self, userhash: hmac = bytes(), **kwargs):
        super().__init__(userhash, **kwargs)

    @staticmethod
    def fixed_length() -> int:
        return 20

    @classmethod
    def attribute_type(cls: Type[Attribute]) -> AttributeType:
        return AttributeType.MESSAGE_INTEGRITY

    @property
    def hmac(self) -> bytes:
        return self._bytes_value

    @hmac.setter
    def hmac(self, value: bytes) -> None:
        self._set_value(value)


class MessageIntegritySha256Attribute(LengthCheckedAttributeBase):
    def __init__(self, userhash: hmac = bytes(), **kwargs):
        super().__init__(userhash, **kwargs)

    @classmethod
    def minimum_length(cls: Type[Attribute]) -> int:
        return 16

    @classmethod
    def maximum_length(cls: Type[Attribute]) -> int:
        return 32

    @classmethod
    def attribute_type(cls: Type[Attribute]) -> AttributeType:
        return AttributeType.MESSAGE_INTEGRITY_SHA256

    @property
    def hmac(self) -> bytes:
        return self._bytes_value

    @hmac.setter
    def hmac(self, value: bytes) -> None:
        self._set_value(value)


class FingerprintAttribute(Attribute):
    def __init__(self, fingerprint: int = 0, **kwargs):
        super().__init__(**kwargs)
        self.fingerprint = fingerprint

    @classmethod
    def attribute_type(cls: Type[Attribute]) -> AttributeType:
        return AttributeType.FINGERPRINT

    @property
    def value(self) -> bytes:
        return struct.pack('!I', self.fingerprint)

    def _unpack_value(self, buffer: bytes) -> None:
        (self.fingerprint,) = struct.unpack('!I', buffer)


class ErrorCodeAttribute(Attribute):
    def __init__(self, error_code: int = 0, reason_phrase: bytes = bytes(), **kwargs):
        super().__init__(**kwargs)
        self.error_code = error_code
        self.reason_phrase = reason_phrase

    @classmethod
    def attribute_type(cls: Type[Attribute]) -> AttributeType:
        return AttributeType.ERROR_CODE

    @property
    def error_class(self) -> int:
        return int(self.error_code // 100)

    @property
    def error_number(self) -> int:
        return self.error_code % 100

    @property
    def value(self) -> bytes:
        error_data = (((self.error_class & 0x07) << 8) | (self.error_number & 0xFF))
        return struct.pack(f'!i{len(self.reason_phrase)}s', error_data, self.reason_phrase)

    def _unpack_value(self, buffer: bytes) -> None:
        (error_data, self.reason_phrase) = struct.unpack(f'!i{len(buffer) - 4}s', buffer)
        error_class = ((error_data & 0x0700) >> 8)
        error_number = ((error_data & 0x00FF) % 100)
        self.error_code = (error_class * 100) + error_number


class RealmAttribute(StringAttributeBase):
    def __init__(self, realm: bytes = bytes(), **kwargs):
        super().__init__(realm, **kwargs)

    @classmethod
    def attribute_type(cls: Type[Attribute]) -> AttributeType:
        return AttributeType.REALM

    @property
    def realm(self) -> bytes:
        return self._string_value

    @realm.setter
    def realm(self, value: bytes) -> None:
        self._string_value = value


class NonceAttribute(StringAttributeBase):
    def __init__(self, nonce: bytes = bytes(), **kwargs):
        super().__init__(nonce, **kwargs)

    @classmethod
    def attribute_type(cls: Type[Attribute]) -> AttributeType:
        return AttributeType.NONCE

    @property
    def nonce(self) -> bytes:
        return self._string_value

    @nonce.setter
    def nonce(self, value: bytes) -> None:
        self._string_value = value


class Algorithm:
    def __init__(self, algorithm_number: int = 0, algorithm_parameters: bytes = bytes(), **kwargs) -> None:
        super().__init__(**kwargs)
        self.algorithm_number = algorithm_number
        self.algorithm_parameters = algorithm_parameters

    def __str__(self) -> str:
        return f'{self.algorithm_number} {self.algorithm_parameters}'

    def __repr__(self) -> str:
        return f'Algorithm({self.algorithm_number}, {self.algorithm_parameters})'

    def __eq__(self, other: Algorithm) -> bool:
        if isinstance(other, Algorithm):
            return (self.algorithm_number == other.algorithm_number) and (self.algorithm_parameters == other.algorithm_parameters)

    @property
    def algorithm_parameters_length(self):
        return len(self.algorithm_parameters)

    def pack(self) -> bytes:
        padding_length = _padding_length(self.algorithm_parameters_length)
        return struct.pack(f'!HH{self.algorithm_parameters_length}s{padding_length}s', self.algorithm_number, self.algorithm_parameters_length, self.algorithm_parameters, b'\x00' * padding_length)

    def unpack(self, buffer: bytes) -> int:
        (self.algorithm_number, length) = struct.unpack(f'!HH', buffer[:4])
        self.algorithm_parameters = buffer[4:(length + 4)]
        return 4 + length + _padding_length(length)


class PasswordAlgorithmsAttribute(Attribute):
    def __init__(self, algorithms: List[Algorithm] = [], **kwargs):
        super().__init__(**kwargs)
        self.algorithms = algorithms

    @classmethod
    def attribute_type(cls: Type[Attribute]) -> AttributeType:
        return AttributeType.PASSWORD_ALGORITHMS

    @property
    def value(self) -> bytes:
        return b''.join([a.pack() for a in self.algorithms])

    def _unpack_value(self, buffer: bytes) -> None:
        self.algorithms.clear()

        buffer_offset = 0
        buffer_length = len(buffer)
        while buffer_offset < buffer_length:
            algorithm = Algorithm()
            buffer_offset += algorithm.unpack(buffer[buffer_offset:])
            self.algorithms.append(algorithm)


class PasswordAlgorithmAttribute(Attribute):
    def __init__(self, algorithm: Algorithm = Algorithm(0, bytes()), **kwargs):
        super().__init__(**kwargs)
        self.algorithm = algorithm

    @classmethod
    def attribute_type(cls: Type[Attribute]) -> AttributeType:
        return AttributeType.PASSWORD_ALGORITHM

    @property
    def value(self) -> bytes:
        return self.algorithm.pack()

    def _unpack_value(self, buffer: bytes) -> None:
        self.algorithm.unpack(buffer)


class UnknownAttributesAttribute(Attribute):
    def __init__(self, unknown_attributes: List[int] = [], **kwargs):
        super().__init__(**kwargs)
        self.unknown_attributes = unknown_attributes

    @classmethod
    def attribute_type(cls: Type[Attribute]) -> AttributeType:
        return AttributeType.UNKNOWN_ATTRIBUTES

    @property
    def value(self) -> bytes:
        return struct.pack(f'!{len(self.unknown_attributes)}H', *self.unknown_attributes)

    def _unpack_value(self, buffer: bytes) -> None:
        self.unknown_attributes = list(struct.unpack(f'!{len(buffer) // 2}H', buffer))


class SoftwareAttribute(StringAttributeBase):
    @classmethod
    def attribute_type(cls: Type[Attribute]) -> AttributeType:
        return AttributeType.SOFTWARE

    @property
    def software(self) -> bytes:
        return self._string_value

    @software.setter
    def software(self, value: bytes) -> None:
        self._string_value = value


class AlternateServerAttribute(MappedAddressAttributeBase):
    'https://datatracker.ietf.org/doc/html/rfc8489#section-14.1'
    @classmethod
    def attribute_type(cls: Type[Attribute]) -> AttributeType:
        return AttributeType.ALTERNATE_SERVER


class AlternateDomainAttribute(StringAttributeBase):
    @classmethod
    def attribute_type(cls: Type[Attribute]) -> AttributeType:
        return AttributeType.ALTERNATE_DOMAIN

    @property
    def alternate_domain(self) -> bytes:
        return self._string_value

    @alternate_domain.setter
    def alternate_domain(self, value: bytes) -> None:
        self._string_value = value


class PriorityAttribute(IntAttributeBase):
    def __init__(self, priority: int = 0, **kwargs):
        super().__init__(priority, 'I', **kwargs)

    @classmethod
    def attribute_type(cls: Type[Attribute]) -> AttributeType:
        return AttributeType.PRIORITY

    @property
    def priority(self) -> int:
        return self._int_value

    @priority.setter
    def priority(self, value: int):
        self._int_value = value


class UseCandidateAttribute(Attribute):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    @classmethod
    def attribute_type(cls: Type[Attribute]) -> AttributeType:
        return AttributeType.USE_CANDIDATE

    @property
    def value(self) -> bytes:
        return b''

    def _unpack_value(self, buffer: bytes) -> None:
        pass


class IceControlledAttribute(IceControlAttributeBase):
    @classmethod
    def attribute_type(cls: Type[Attribute]) -> AttributeType:
        return AttributeType.ICE_CONTROLLED


class IceControllingAttribute(IceControlAttributeBase):
    @classmethod
    def attribute_type(cls: Type[Attribute]) -> AttributeType:
        return AttributeType.ICE_CONTROLLING


def create(buffer: bytes) -> Type[Attribute]:
    (attribute_type,) = struct.unpack('!H', buffer[:2])

    if attribute_type == AttributeType.MAPPED_ADDRESS:
        return MappedAddressAttribute.create(buffer)
    elif attribute_type == AttributeType.USERNAME:
        return UsernameAttribute.create(buffer)
    elif attribute_type == AttributeType.MESSAGE_INTEGRITY:
        return MessageIntegrityAttribute.create(buffer)
    elif attribute_type == AttributeType.ERROR_CODE:
        return ErrorCodeAttribute.create(buffer)
    elif attribute_type == AttributeType.UNKNOWN_ATTRIBUTES:
        return UnknownAttributesAttribute.create(buffer)
    elif attribute_type == AttributeType.REALM:
        return RealmAttribute.create(buffer)
    elif attribute_type == AttributeType.NONCE:
        return NonceAttribute.create(buffer)
    elif attribute_type == AttributeType.MESSAGE_INTEGRITY_SHA256:
        return MessageIntegritySha256Attribute.create(buffer)
    elif attribute_type == AttributeType.PASSWORD_ALGORITHM:
        return PasswordAlgorithmAttribute.create(buffer)
    elif attribute_type == AttributeType.USERHASH:
        return UserhashAttribute.create(buffer)
    elif attribute_type == AttributeType.XOR_MAPPED_ADDRESS:
        return XorMappedAddressAttribute.create(buffer)
    elif attribute_type == AttributeType.PASSWORD_ALGORITHMS:
        return PasswordAlgorithmsAttribute.create(buffer)
    elif attribute_type == AttributeType.ALTERNATE_DOMAIN:
        return AlternateDomainAttribute.create(buffer)
    elif attribute_type == AttributeType.SOFTWARE:
        return SoftwareAttribute.create(buffer)
    elif attribute_type == AttributeType.ALTERNATE_SERVER:
        return AlternateServerAttribute.create(buffer)
    elif attribute_type == AttributeType.FINGERPRINT:
        return FingerprintAttribute.create(buffer)
    elif attribute_type == AttributeType.PRIORITY:
        return PriorityAttribute.create(buffer)
    elif attribute_type == AttributeType.USE_CANDIDATE:
        return UseCandidateAttribute.create(buffer)
    elif attribute_type == AttributeType.ICE_CONTROLLED:
        return IceControlledAttribute.create(buffer)
    elif attribute_type == AttributeType.ICE_CONTROLLING:
        return IceControllingAttribute.create(buffer)

    raise ValueError(f'Unknown STUN attribute type {attribute_type}')
