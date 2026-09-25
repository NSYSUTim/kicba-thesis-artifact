"""Minimal display-only compatibility layer for the upstream shift evaluator.

The frozen shift approach uses tqdm only to render progress.  This local shim
keeps the upstream numerical code unchanged on the offline analysis host,
where tqdm is not installed.
"""


class tqdm:
    def __init__(self, iterable, *args, **kwargs):
        self.iterable = iterable

    def __iter__(self):
        return iter(self.iterable)

    def __len__(self):
        return len(self.iterable)

    @staticmethod
    def write(message):
        print(message)
