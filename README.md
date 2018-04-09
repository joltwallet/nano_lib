# Nano Lib
Nano Currency functions for embedded targets. This library was constructed
with the ESP32 in mind, but can be ported over to other platforms without too
much headache.

# Todo
* [ongoing] More error handling (and test for it in unit tests)
* [ongoing] Be super careful about remembering to zero out anything that touches secrets
* [Complete] State Block Signing
* [Move to websocket library] Function to convert an nl_block_t into a "process" RPC command
* [Complete; discussing tweaks with Roosmaa]BIP39/44 Related Functions
* [Complete] Block Hash Check
* [Complete] Verify Signature
* [Complete] Work endianess functions

# Probably won't happen, but ideas
* [Complete] On-board PoW (and make it a low priority background task);
    * Generally too slow unless lucky. Of 3 local PoW tests:
        1) 20 minutes
        2) 4 minutes
        3) >1hr (test incomplete)
