class Chunked:
    def __init__(self, data:bytes, chunk_size:int) -> None:
        self.data = data
        self.chunk_size = chunk_size

    def __iter__(self):
        for i in range(0, len(self.data), self.chunk_size):
            yield i // self.chunk_size, self.data[i:i+self.chunk_size]


if __name__ == "__main__":
    c = Chunked(b'1234567890'*3, 3)
    for i, chunk in c:
        print(i, chunk)