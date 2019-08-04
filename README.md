# Ero-Bluetooth-Mesh
Bluetooth mesh stack for use in ero system. May be useful for others for reference
pure-python except for any hardware bearer layers 

Built in bearer is using a slightly modifier [Bleson](https://github.com/TheCellule/python-bleson) library for the advertising bearer layer. So far only tested on Linux. OSX untested and Windows 10 doesn't seem like it sets the advertising data correctly.

See better_mesh_ctl.py for an example.

## Features Supported:
- Hardware Agnostic Bearer Layer 
- Network Layer
- Transport Layer
- Access Layer
- Provisioning others (Only PB-ADV/PB-GENERIC) for now

## Features Planned:
- Virtual devices
- PB-GATT
- Gatt Proxy
- Custom Sockets Proxy
- Message Cache
- Model Layer
- Friends
- Low Power?
- Relay
- Being Provision
