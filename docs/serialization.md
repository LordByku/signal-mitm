# Serialization module(s)

The serialization module provides a way to serialize and deserialize data. We analyze two aspects:
- # Input interface: 
    - How data is provided to the CryptoMall module. Originally, the data coming from the client was firstly deserialized in ```implementation.py``` and handled by ```MitmUSer``` class that communicated directly with ```signal-protocol.py```. 

