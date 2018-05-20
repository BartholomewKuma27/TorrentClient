import sys


class ArgumentParser:
    def __init__(self):
        self.t = 30
        self.v = False
        self.torrent_file_url = None
        self.save_dir = None

    def do_parsing(self):
        args_size = len(sys.argv)
        self.save_dir = sys.argv[args_size - 1]
        self.torrent_file_url = sys.argv[args_size - 2]
        if args_size == 4:
            cur = sys.argv[1]
            if cur[0:2] == "-t":
                self.t = cur
            else:
                self.v = cur
        if args_size == 5:
            self.t = sys.argv[1][2:]
            self.v = True
