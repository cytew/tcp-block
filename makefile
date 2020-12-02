LDLIBS=-lpcap

all: tcp-block

tcp-block: main.o arphdr.o ethhdr.o ip.o mac.o tcpblock.o
	g++ -o tcp-block main.o arphdr.o ethhdr.o ip.o mac.o tcpblock.o -lpcap

main.o: ethhdr.h arphdr.h tcpblockmain.cpp
	g++ -std=c++11 -c -o main.o tcpblockmain.cpp

arphdr.o: arphdr.cpp arphdr.h mac.h	ip.h
	g++ -std=c++11 -c arphdr.cpp

ethhdr.o: ethhdr.cpp ethhdr.h mac.h
	g++ -std=c++11 -c ethhdr.cpp

mac.o: mac.cpp mac.h
	g++ -std=c++11 -c mac.cpp

ip.o: ip.cpp ip.h
	g++ -std=c++11 -c ip.cpp

tcpblock.o: tcpblock.cpp tcpblock.h
	g++ -std=c++11 -c tcpblock.cpp

clean:
	rm -f tcp-block *.o
