# Simple timer class
class Runtime:
    def __init__(self):
        self.start_time = time()
    def elapsed_time(self):
        print(f'runtime: {time() - self.start_time}\n')
