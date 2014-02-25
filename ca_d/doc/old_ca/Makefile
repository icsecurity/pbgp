UNAME:= $(shell uname)
ifeq (${UNAME},Linux)
	CFLAGS= -g -lpbc -lgmp -lnettle -lhogweed -lssl -lcrypto -lresolv -Wall -O0 
endif	

ifeq (${UNAME},OpenBSD)
	CFLAGS= -g -lpbc -lgmp -lnettle -lhogweed -Wall -O0
endif

CC=gcc
OPTIMIZE= -O3
LIBS=-L /usr/local/ssl/lib -L /usr/local/lib/ -L /usr/lib/ 
INCLUDES=-I . -I/usr/local/include/pbc/ -I/usr/local/include/ -I/usr/include/

all: setup_main actions_main ibe_test epoch_test test_openssl test_nettle microbench

microbench: misc setup ibe witness accumulator actions
	$(CC) microbench.c pbgp_actions.o pbgp_witness.o pbgp_common.o pbgp_setup.o pbgp_ibe.o pbgp_accumulator.o $(INCLUDES) $(LIBS) $(CFLAGS) \
            -o microbench

test_openssl: misc setup ibe witness accumulator actions
	$(CC) test_openssl.c pbgp_actions.o pbgp_witness.o pbgp_common.o pbgp_setup.o pbgp_ibe.o pbgp_accumulator.o $(INCLUDES) $(LIBS) $(CFLAGS) \
	 -o runtest_openssl -D MAKETEST 

test_nettle: misc setup ibe witness accumulator actions
	$(CC) test_nettle.c pbgp_actions.o pbgp_witness.o pbgp_common.o pbgp_setup.o pbgp_ibe.o pbgp_accumulator.o $(INCLUDES) $(LIBS) $(CFLAGS) \
	 -o runtest_nettle -D MAKETEST   

setup_main: misc actions ibe witness
	$(CC) pbgp_setup.c pbgp_common.o pbgp_actions.o pbgp_ibe.o pbgp_witness.o $(INCLUDES) $(LIBS) $(CFLAGS) -o setup -D SETUP_MAIN

actions_main: misc setup ibe witness
	$(CC) pbgp_actions.c pbgp_witness.o pbgp_common.o pbgp_setup.o pbgp_ibe.o $(INCLUDES) $(LIBS) $(CFLAGS) -o actions -D ACTIONS_MAIN

ibe_test: misc setup
	$(CC) pbgp_ibe.c pbgp_setup.o pbgp_common.o $(INCLUDES) $(LIBS) $(CFLAGS) -o ibe_test -D IBETEST_MAIN

epoch_test: misc setup ibe witness accumulator actions
	$(CC) pbgp_epoch.c pbgp_actions.o pbgp_witness.o pbgp_common.o pbgp_setup.o pbgp_ibe.o pbgp_accumulator.o $(INCLUDES) $(LIBS) $(CFLAGS) \
	-o epoch_test

setup: misc 
	$(CC) -c pbgp_setup.c pbgp_common.o $(INCLUDES) $(LIBS) $(CFLAGS)

actions:
	$(CC) -c pbgp_actions.c $(INCLUDES) $(LIBS) $(CFLAGS)

epoch:
	$(CC) -c pbgp_epoch.c $(INCLUDES) $(LIBS) $(CFLAGS)

accumulator:
	$(CC) -c pbgp_accumulator.c $(INCLUDES) $(LIBS) $(CFLAGS)

witness:
	$(CC) -c pbgp_witness.c $(INCLUDES) $(LIBS) $(CFLAGS)

ibe:
	$(CC) -c pbgp_ibe.c $(INCLUDES) $(LIBS) $(CFLAGS)

misc:
	$(CC) -c pbgp_common.c $(INCLUDES) $(LIBS) $(CFLAGS)	

clean:
	rm -rf *.o
	rm ibe_test setup actions epoch_test


