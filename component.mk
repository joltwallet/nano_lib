COMPONENT_ADD_INCLUDEDIRS := include
COMPONENT_SRCDIRS := src

$(call compile_only_if,$(CONFIG_NL_ENABLE), translation.c)
