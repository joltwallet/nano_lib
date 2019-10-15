#
# This is a project Makefile. It is assumed the directory this Makefile resides in is a
# project subdirectory.
#

PROJECT_NAME := nano_lib

EXTRA_COMPONENT_DIRS := \
	.. \
	$(HOME)/esp/third-party/ \
	$(IDF_PATH)/tools/unit-test-app/components/

include $(IDF_PATH)/make/project.mk

tests:
	$(MAKE) \
	TEST_COMPONENTS='nano_lib' \
	flash monitor;


