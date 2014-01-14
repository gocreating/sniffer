all:sniffer.cpp
	g++ sniffer.cpp -o sniffer
clean:
	rm -f sniffer
