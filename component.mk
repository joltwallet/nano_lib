COMPONENT_ADD_INCLUDEDIRS := include
COMPONENT_PRIV_INCLUDEDIRS := src src/ed25519/src
COMPONENT_SRCDIRS := src src/ed25519/src

#$(call compile_only_if,$(CONFIG_NL_ENABLE), translation.c)
