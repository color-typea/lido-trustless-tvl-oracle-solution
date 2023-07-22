import time
from contextlib import contextmanager


class Printer:
    MAGENTA = '\033[95m'
    LIGHT_BLUE = '\033[94m'
    BLUE = '\033[44m'
    BRIGHT_CYAN = '\033[96m'
    BRIGHT_GREEN = '\033[92m'
    GREEN = '\033[42m'
    BRIGHT_YELLOW = '\033[93m'
    YELLOW = '\033[33m'
    BRIGHT_RED = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

    def print(self, message, color=None):
        if color is not None:
            msg = f"{color}{message}{self.ENDC}"
        else:
            msg = message
        print(msg)

    def info(self, message):
        self.print(message)

    def wait(self, message):
        msg = f"{self.YELLOW}{message}{self.ENDC}"
        input(msg)

    def detail(self, message, level=1):
        msgs = message.split("\n")
        indent = " " * 2 * level
        padded = [f"{indent}{msg}" for msg in msgs]
        self.print("\n".join(padded))

    def success(self, message):
        self.print(message, self.GREEN)

    def expected_fail(self, message):
        self.print(message, self.BRIGHT_CYAN)

    def attention(self, message):
        self.print(message, self.BRIGHT_YELLOW)

    def error(self, message):
        self.print(message, self.BRIGHT_RED)

    def header(self, message):
        msg = f"{self.BOLD}{message}{self.ENDC}"
        print(msg)

    def time(self, operation: str, time_spent: float):
        print(f"{self.BLUE}{operation} took {self.BOLD}{time_spent:.4f}s{self.ENDC}")


@contextmanager
def with_timing(printer: Printer, label: str):
    start_time = time.time()
    yield
    end_time = time.time()
    printer.time(label, end_time - start_time)