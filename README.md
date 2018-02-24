# r2msdn[![analytics](http://www.google-analytics.com/collect?v=1&t=pageview&_s=1&dl=https%3A%2F%2Fgithub.com%2Fsecurisec%2Fr2msdn&tid=UA-113966566-3)]()
[![Twitter Follow](https://img.shields.io/twitter/follow/securisec.svg?style=social&label=Follow)]()
[![Analytics](https://ga-beacon.appspot.com/UA-113966566-3/r2msdn/readme)](https://github.com/securisec/r2msdn)

MSDN data annotation for radare2

This plugin helps by automatically annotating the description of a function and arguments that are passed to these functions. 

The data is from MSDN

It is not perfect, but works as expected. 

## Install
```commandline
r2pm update
r2pm -i r2msdn
```

## Options
```commandline
usage: $r2msdn [-h] [-v] [-i INFO]

optional arguments:
  -h, --help  show this help message and exit
  -v          Verbose mode
  --version   Show version
  -i INFO     Show info about a function
  -d          Describe the function
```

[![asciicast](https://asciinema.org/a/164908.png)](https://asciinema.org/a/164908)