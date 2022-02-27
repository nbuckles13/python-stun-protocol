# Python Stun Protocol

A python module for creating and parsing [STUN](https://datatracker.ietf.org/doc/html/rfc8489) packets.

## Message

The `Message` class, defined in message.py, is the main interface to the module.  To parse a packet from a buffer, simply do:

```
from stun_protocol.message import Message

# get a buffer from somewhere (perhaps received over a network)
buffer = ...

# create a message
message = Message.create(buffer)
```

Stun messages have 4 main components.

1. The message type, composed of the class and method
    1. The message type class (`message.message_class`)
    2. The message type method (`message.message_method`)
2. The message length (`message.length`)
3. The message transaction id (`message.transaction_id`)
4. The message attributes (`message.attributes`)

When creating a message from a buffer, all fields are automatically populated as the buffer is parsed.  When constructing a message object directly, the caller must provide the message class and method.  The length is dynamically calculated by the message object as needed.  The transaction id is optional, a random transaction id will be created if one is not provided.  The attributes are also optional and may be added later using the `message.add_attribute()` function.  For example:

```
from stun_protocol.message import Message
from stun_protocol.attribute import UsernameAttribute

# create a message object with a random transaction id and no attributes
m = Message(MessageClass.REQUEST, MessageMethod.BINDING)

# add a username attribute, note that attributes are defined fully below
m.add_attribute(UsernameAttribute(b'username'))

# some attributes are best added via the explicit helper functions as they have somewhat complex rules
m.add_fingerprint_attribute()
```

To turn a STUN message into a buffer suitable for sending over a network, use the `pack()` method:

```
from stun_protocol.message import Message

m = Message(MessageClass.REQUEST, MessageMethod.BINDING)
buffer = m.pack()
```

## Attributes

Attributes are defined in attribute.py.  Different attributes have different rules for the valid values that may be contained in those attributes.  All such rules are taken from https://datatracker.ietf.org/doc/html/rfc8489#section-14.  When creating attributes, be sure to follow the restrictions for that attribute.  For example, the `UserhashAttribute` requires a bytes value with length 32.  Any other length will trigger an exception.

```
from stun_protocol.attribute import UserhashAttribute

# Below will cause the following exception
# ValueError: UserhashAttribute requires a value of length >= 32 and <= 32 bytes, found 3
attr = UserhashAttribute(b'foo')
```

Attributes, like messages can be created from buffers.  If you know the expected attribute type then you can call `create()` directly on that type.

```
from stun_protocol.attribute import UserhashAttribute

# get a buffer from somewhere (perhaps received over a network)
buffer = ...

attr = UserhashAttribute.create(buffer)
```

More commonly you will not know the type of the attribute, in which case you can use the module level `create()` function which will return the correct attribute object based on the buffer.

```
from stun_protocol.attribute import create

# get a buffer from somewhere (perhaps received over a network)
buffer = ...

attr = create(buffer)
```

There are various base classes for attributes starting with `Attribute` which is an abstract base class (`ABC`).  The module defines types for all attributes in the RFC, but the base classes allow for creating custom attributes as needed.
