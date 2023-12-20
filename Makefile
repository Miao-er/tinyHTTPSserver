all: http-server

http-server: http_server.c
	gcc -Wall -g http_server.c -o http-server -lssl -lcrypto -lpthread

clean:
	@rm http-server
