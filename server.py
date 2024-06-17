import socket


def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(('localhost', 8080))
    server.listen(2)

    print("server hi!")
    while True:
        sock, addr = server.accept()
        print(f"connection from {addr}")

        data = sock.recv(1024)
        print(f"received: {data.decode()}")


if __name__ == '__main__':
    main()
