all : send_arp

send_arp: send_arp.o
	g++ -g -o send_arp send_arp.o -lpcap
	rm -rf *.o

send_arp.o:
	g++ -g -c -o send_arp.o main.cpp

clean:
	rm -f send_arp
	rm -f *.o