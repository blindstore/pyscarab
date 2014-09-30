# pyscarab

[![Travis](https://travis-ci.org/blindstore/pyscarab.svg?branch=master)](https://travis-ci.org/blindstore/pyscarab)

Python wrapper and abstractions for [`libscarab`](https://hcrypt.com/) FHE library

## Installation

Requires libscarab [fork](https://github.com/blindstore/libScarab) installed.

Install with pip:

```
pip install git+git://github.com/blindstore/pyscarab.git@master
```

## Run the tests

```
nosetests scarab/tests
```


## Notes

`libscarab` uses insecure parameters by default, and is experimental software. This package should only be used for research purposes

`pyscarab` does not do any type checks before communicating with C, so it's very easy to segfault it. 
