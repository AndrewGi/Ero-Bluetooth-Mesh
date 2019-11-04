# Ero-Bluetooth-Mesh

![Wireshark Example](/wireshark.PNG)

Ero Bluetooth Mesh is complete Bluetooth Mesh Stack (not just GATT-Proxy) with hardware agonistic support (besides for ble-drivers). The target for this Bluetooth Mesh driver is for edge routers and cloud processing of Mesh messages. This project started out just as a specialized Driver for personal use but it has expanded to a generic Mesh driver stack.

Done according to [Mesh Core v1.0](https://www.bluetooth.com/specifications/mesh-specifications/) I need update to 1.0.1 but I can't see changes because I'm not a registered company with SIG yet :)

Built in bearer is using a slightly modifier [Bleson](https://github.com/TheCellule/python-bleson) library for the advertising bearer layer. So far only tested on Linux. OSX untested and Windows 10 doesn't seem like it sets the advertising data correctly.

### ALWAYS LOOK FOR HELP/CONTRIBUTERS ###

The code is in a very partial working state. All of the logic is there, just need to fix the bugs and out-of-spec errors. 

# provision_cli.py

provision_cli.py is a provisioner command line interface for provisioning and generic mesh actions. Read provision_cli.py for a list of commands.

## Layers
- Foundation
- Access
- Upper Transport
- Lower Transport
- Net
- Adv Bearer, Proxy Bearer, Socket Bearer, Generic Bearer (GATT Planned) 


## Underworks:
 - Retransmissions
 - Testing

## Features Supported:
- Hardware Agnostic Bearer Layer 
- Network Layer
- Transport Layer
- Access Layer
- Provisioning others (Only PB-ADV/PB-GENERIC) for now
- Proxy (No GATT yet)
- Example TLS/SSL Mesh Proxy
- Replay Cache
- Model Layer
- Message Cache
- Expandable Serialization Abstractions

## Features Planned:
- Virtual devices
- PB-GATT
- Gatt Proxy
- Friends
- Low Power?
- Relay
- Being Provision
- Wireshark
### Serialization:
Some Bluetooth Mesh information needs to be stored persistantly (Keys, Friendships, Replay Cache, Addresses, etc). This is achieved by those objects implemented `Serializable` which implements `to_dict` and `from_dict`. From there, you can store/transport to to whatever encoding you want (JSON, YAML, INI, CBOR, etc). The choice to use JSON in the examples is just for ease of use. 
