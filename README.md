# Nano Lib
Low level [Nano Currency](https://github.com/nanocurrency/raiblocks) functions for embedded targets. This library was constructed with the ESP32 in mind, but can be ported over to other platforms without too much headache. All hashing and signing heavily relies on libsodium. This currently works with the [commit](https://github.com/jedisct1/libsodium/tree/70170c28c844a4786e75efc626e1aeebc93caebc) (@70170c2) bundled with [ESP-IDF](https://github.com/espressif/esp-idf).

# Design
Nano heavily relies on uint256 numbers; in this library these are represented as a 32-long unsigned char array. To reduce confusion; information is always kept in their uint256 state as much as possible, i.e. storing public keys instead of nano addresses.

When applicable, all transactions are stored in `struct nl_block_t`. This structure supports all legacy and state blocks. While this library supports legacy blocks, it was really designed with State Blocks in mind.

# Unit Tests
Unit tests can be used by selecting this library with a target using the [ESP32 Unit Tester](https://github.com/BrianPugh/esp32_unit_tester).

```
make flash TEST_COMPONENTS='nano_lib' monitor
```

The unit tests (in the `test` folder) is a good source of examples on how to use this library.

# Related Projects
[`nano_parse`](https://github.com/joltwallet/nano_parse) - Library for crafting `rai_node` rpc calls and parsing their responses to be compatible with this library. [`nano_parse`](https://github.com/joltwallet/nano_lws) optionally builds with `nano_lws` which handles websockets for communicating with a `rai_node` over wifi.
