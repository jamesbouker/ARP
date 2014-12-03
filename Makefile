CC=gcc
FLAGS=-g -O2 -Wall -Werror
CFLAGS = ${FLAGS} -I/home/stufs1/cse533/Stevens/unpv13e/lib
LIBS =  /home/courses/cse533/Stevens/unpv13e/libunp.a
EXE = jbouker_arp jbouker_tour
EVERYTHINGELSE = api.h

all: $(EXE)

jbouker_arp: arp.o api.o
	gcc $(CFLAGS) -o $@ $^ ${LIBS}

jbouker_tour: tour.o api.o
	gcc $(CFLAGS) -o $@ $^ ${LIBS}

%.o: %.c %.h $(EVERYTHINGELSE)
	gcc $(CFLAGS) -c $^ ${LIBS}

clean:
	rm -f *.o *.out *.gch $(EXE)

#use these to easily deploy, remove, start, and kill the executables

deploy:
	~/cse533/deploy_app jbouker_arp
	~/cse533/deploy_app jbouker_tour

deployArp:
	~/cse533/deploy_app jbouker_arp

deployTour:
	~/cse533/deploy_app jbouker_tour

kill: 
	~/cse533/kill_apps

cleanup: 
	~/cse533/cleanup_vms
