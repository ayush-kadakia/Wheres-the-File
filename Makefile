all: WTF WTFserver

WTF: WTF.c
	gcc WTF.c -o WTF -lcrypto -g

WTFserver: WTFserver.c
	gcc WTFserver.c -lpthread -o WTFserver -lcrypto

test: WTFtest.c
	gcc WTFtest.c -o WTFtest

clean:
	rm -rf WTF WTFserver WTFtest client_folder server_folder
