
CXX := g++
FLAGS := -Wall -Wextra -O3

DIR_ROOT = $(abspath .)
DIR_OBJ := $(DIR_ROOT)/obj
DIR_SRC := $(DIR_ROOT)/src
TARGET := sni_viewer

all: build

build: $(DIR_SRC)/ssl.cpp  $(DIR_SRC)/main.cpp
	$(CXX) $(FLAGS) -o $(TARGET) $(DIR_SRC)/ssl.cpp $(DIR_SRC)/main.cpp -ltins

clean:
	rm -f $(TARGET)
	rm -f $(DIR_OBJ)/*