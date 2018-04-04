# Nano Lib
Nano Currency functions for embedded targets. This library was constructed
with the ESP32 in mind, but can be ported over to other platforms without too
much headache.

# Todo
* More error handling (and test for it in unit tests)
* Be super careful about remembering to zero out anything that touches secrets
* State Block Signing
* Function to convert an nl_block_t into a "process" RPC command
* BIP39/44 Related Functions
* Block Hash Check
* Verify Signature

# Probably won't happen, but ideas
* On-board PoW (and make it a low priority background task)
