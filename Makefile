# Minimal Makefile for bootstrapping without cmake

PKG_CONFIG ?= pkg-config
CXXFLAGS = -std=c++11

COMMON_SRCS = hash.cpp macho.cpp signature.cpp commands.cpp der.cpp bundle.cpp resources.cpp

SIGTOOL_SRCS = main.cpp $(COMMON_SRCS)
SIGTOOL_OBJS := $(SIGTOOL_SRCS:.cpp=.o)

CODESIGN_SRCS = codesign.cpp $(COMMON_SRCS)
CODESIGN_OBJS := $(CODESIGN_SRCS:.cpp=.o)

CPPFLAGS := -I vendor $(shell $(PKG_CONFIG) --cflags openssl libplist-2.0)
LIBS := $(shell $(PKG_CONFIG) --libs openssl libplist-2.0)

sigtool: $(SIGTOOL_OBJS)
	$(CXX) $(LDFLAGS) -o $@ $^ $(LIBS)

codesign: $(CODESIGN_OBJS)
	$(CXX) $(LDFLAGS) -o $@ $^ $(LIBS)

.PHONY: install clean
install: sigtool codesign
	mkdir -p $(DESTDIR)$(PREFIX)/bin
	cp codesign sigtool $(DESTDIR)$(PREFIX)/bin/

clean:
	rm -f sigtool codesign $(SIGTOOL_OBJS) $(CODESIGN_OBJS)
