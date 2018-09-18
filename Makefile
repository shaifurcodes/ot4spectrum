LIBOTE_PATH = ../libOTe

INC_PATH = -I$(LIBOTE_PATH)/libOTe -I$(LIBOTE_PATH)/cryptoTools -I$(LIBOTE_PATH)/cryptoTools/thirdparty/linux/boost -I$(LIBOTE_PATH)/cryptoTools/thirdparty/linux/miracl/miracl


LIB_PATH = -L$(LIBOTE_PATH)/libOTe/lib -llibOTe -lcryptoTools -lSimplestOT -L$(LIBOTE_PATH)/cryptoTools/thirdparty/linux/boost/stage/lib -lboost_system -lboost_thread -L$(LIBOTE_PATH)/cryptoTools/thirdparty/linux/miracl/miracl/source -lmiracl

CC = g++
AUXCFLAGS = -g -ffunction-sections -maes -msse2 -msse4.1 -mpclmul -Wfatal-errors -pthread -Wno-strict-overflow  -fPIC -Wno-ignored-attributes
CFLAGS = -Wall -std=c++14 $(AUXCFLAGS)

all: nChooseOneExample
	
nChooseOneExample: nChooseOneExample
	$(CC) $(CFLAGS) $(INC_PATH) nChooseOneExample.cpp $(LIB_PATH) -o nChooseOneExample

clean:
	rm -f nChooseOneExample


