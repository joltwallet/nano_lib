# Nano Lib
Nano Currency functions for embedded targets. This library was constructed
with the ESP32 in mind, but can be ported over to other platforms without too
much headache.

# Todo
* [ongoing] More error handling (and test for it in unit tests)
* [ongoing] Be super careful about remembering to zero out anything that touches secrets
* [DONE]State Block Signing
* [Move to websocket library]Function to convert an nl_block_t into a "process" RPC command
* [Complete; discussing tweaks with Roosmaa]BIP39/44 Related Functions
* [Complete] Block Hash Check
* [Complete] Verify Signature

# Probably won't happen, but ideas
* On-board PoW (and make it a low priority background task)
