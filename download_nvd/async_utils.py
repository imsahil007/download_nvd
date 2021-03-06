

# pylint: disable=too-many-arguments
""" Utility classes for the Async Download """
import asyncio
import glob
import gzip
import itertools
import os
import shutil
import sys
import tempfile
from functools import partial, wraps

# from cve_bin_tool.util import inpath


def async_wrap(func):
    @wraps(func)
    async def run(*args, loop=None, executor=None, **kwargs):
        if loop is None:
            loop = asyncio.get_event_loop()
        pfunc = partial(func, *args, **kwargs)
        return await loop.run_in_executor(executor, pfunc)

    return run


def get_event_loop():
    try:
        loop = asyncio.get_event_loop()
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
    if sys.platform.startswith("win"):
        if isinstance(loop, asyncio.SelectorEventLoop):
            loop = asyncio.ProactorEventLoop()
            asyncio.set_event_loop(loop)
    return loop


def run_coroutine(coro):
    loop = get_event_loop()
    aws = asyncio.ensure_future(coro)
    result = loop.run_until_complete(aws)
    return result




class FileIO:
    _open = async_wrap(open)
    _name_idx = 0
    _mode_idx = 1
    _mode = "r"

    def __init__(self, *args, **kwargs):
        # Do some trick to get exact filename and mode regardless of args or kwargs
        flatargs = list(itertools.chain(args, kwargs.values()))
        if (
            self.__class__._name_idx is not None
            and len(flatargs) > self.__class__._name_idx
        ):
            self.name = flatargs[self.__class__._name_idx]
        if (
            self.__class__._mode_idx is not None
            and len(flatargs) > self.__class__._mode_idx
        ):
            self._mode = flatargs[self.__class__._mode_idx]
        self._args = args
        self._kwargs = kwargs
        self._file = None

    async def __call__(self):
        """Convenience method to allow call like following:
        f = await FileIO("some file path", "r")()
        Note: We can't make async __init__
        """
        return await self.open()

    async def open(self):
        file = await self.__class__._open(*self._args, **self._kwargs)
        self._file = file
        self._setup()
        return self

    def _setup(self):
        if not self._file:
            raise RuntimeError("Invalid Use: Call open() before calling _setup()")
        common_async_attrs = {
            "close",
            "flush",
            "isatty",
            "read",
            "readline",
            "readlines",
            "seek",
            "tell",
            "truncate",
            "write",
            "writelines",
        }
        common_sync_attrs = {
            "detach",
            "fileno",
            "readable",
            "writable",
            "seekable",
            "closed",
            "mode",
            "name",
        }
        strings_sync_attrs = {
            "buffer",
            "encoding",
            "errors",
            "line_buffering",
            "newlines",
        }
        bytes_async_attrs = {"readinto", "readinto1", "read1"}
        bytes_sync_attrs = {"raw"}
        if "b" in self._mode:
            async_attrs = common_async_attrs | bytes_async_attrs
            sync_attrs = common_sync_attrs | bytes_sync_attrs
        else:
            async_attrs = common_async_attrs
            sync_attrs = common_sync_attrs | strings_sync_attrs
        [
            setattr(self, attr, async_wrap(getattr(self._file, attr)))
            for attr in async_attrs
            if hasattr(self._file, attr)
        ]
        [
            setattr(self, attr, getattr(self._file, attr))
            for attr in sync_attrs
            if hasattr(self._file, attr)
        ]

    async def __aenter__(self):
        return await self.open()

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        return await self.close()

    async def __anext__(self):
        line = await self.readline()
        if line:
            return line
        else:
            raise StopAsyncIteration

    def __aiter__(self):
        return self




class GzipFile(FileIO):
    _open = async_wrap(gzip.GzipFile)


aio_rmdir = async_wrap(shutil.rmtree)
aio_rmfile = async_wrap(os.remove)
aio_unpack_archive = async_wrap(shutil.unpack_archive)
aio_glob = async_wrap(glob.glob)
aio_mkdtemp = async_wrap(tempfile.mkdtemp)
aio_makedirs = async_wrap(os.makedirs)
# aio_inpath = async_wrap(inpath)
