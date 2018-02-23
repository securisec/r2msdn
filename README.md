# r2msdn[![analytics](http://www.google-analytics.com/collect?v=1&t=pageview&_s=1&dl=https%3A%2F%2Fgithub.com%2Fsecurisec%2Fr2msdn&tid=UA-113966566-3)]()

MSDN data annotation for radare2

This plugin helps by automatically commenting a description and arguments are passed to MSft functions. 

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
  -i INFO     Show info about a function
```

[![asciicast](https://asciinema.org/a/164908.png)](https://asciinema.org/a/164908)