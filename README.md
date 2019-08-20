# Ero-Bluetooth-Mesh
Built in bearer is using a slightly modifier [Bleson](https://github.com/TheCellule/python-bleson) library for the advertising bearer layer. So far only tested on Linux. OSX untested and Windows 10 doesn't seem like it sets the advertising data correctly.

See better_mesh_ctl.py for a (broken) example. View the stack.py to see how the different layers are being connected

This is a learning experience for me so there may be some big inconsistences as I from terrible at python to slightly better.

### ALWAYS LOOK FOR HELP/CONTRIBUTERS ###

## Underworks:
 - Stack
 - Model/Foundation Layer

## Features Supported:
- Hardware Agnostic Bearer Layer 
- Network Layer
- Transport Layer
- Access Layer
- Provisioning others (Only PB-ADV/PB-GENERIC) for now
- Proxy (No GATT yet)
- Example TLS/SSL Mesh Proxy
- Expandable Serialization Abstractions

## Features Planned:
- Virtual devices
- PB-GATT
- Gatt Proxy
- Replay Cache
- Message Cache
- Model Layer
- Friends
- Low Power?
- Relay
- Being Provision

### Serialization:
Some Bluetooth Mesh information needs to be stored persistantly (Keys, Friendships, Replay Cache, Addresses, etc). This is achieved by those objects implemented `Serializable` which implements `to_dict` and `from_dict`. From there, you can store/transport to to whatever encoding you want (JSON, YAML, INI, CBOR, etc). The choice to use JSON in the examples is just for ease of use. 
