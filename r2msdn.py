# -*- coding: utf-8 -*-
#!/usr/bin/env python
import json
import logging
import os
# ugly way of addressing UnicodeEncodeError
import sys
import textwrap
from argparse import ArgumentParser
from pydoc import pipepager

import r2pipe

reload(sys)
sys.setdefaultencoding('utf-8')

__author__ = 'securisec'
__version__ = '0.2'

script_path = os.path.dirname(os.path.realpath(__file__))

parse = ArgumentParser()
parse.add_argument('-v', dest='verbose',
                   help='Verbose mode', action='store_true')
parse.add_argument('--version', dest='version',
                   action='store_true', help='Show version')
parse.add_argument('-i', dest='info', help='Show info about a function')
parse.add_argument('-d', dest='describe',
                   help='Describe the function', action='store_true')
args = parse.parse_args()

if args.verbose:
    logging.basicConfig(level=logging.DEBUG)
if args.version:
    print __version__
    exit()


def str_format(s):
    """
    Textwrap to make the pager output nice
    """
    return textwrap.fill(s, replace_whitespace=False, width=80)


def find_args(func, func_name):
    """
    Returns a reversed list of all the arguments
    """
    for i, f in enumerate(func):
        try:
            if f['name'] == func_name:
                arguments = f['arguments']['argument']
                if isinstance(arguments, list):
                    reverse = [i['name'] for i in arguments][::-1]
                    func_desciption = f['description']
                    return reverse, func_desciption
                elif isinstance(arguments, dict):
                    return arguments['name'], f['description']
        except TypeError:
            continue

# def get_constants(a):
#     if isinstance(a, list):
#         for i in range(len(a)):
#             if a[i].has_key('constants'):
#                 for c in range(len(a[i]['constants']['constant'])):
#                     cons = a[i]['constants']['constant'][c]
#                     print cons['name'], cons['description']


def show_info(func, func_name):
    """
    Shows all available information about a 
    """
    logging.info('Does not show constants')
    result = ''
    for i, f in enumerate(func):
        try:
            if f['name'] == func_name:
                a = f['arguments']['argument']
                result += 'Name: %s\n' % f['name']
                result += '\nDll: %s\n' % f['dll']
                result += str_format('\nDescription: %s\n' % f['description'])
                result += '\n'
                result += str_format('\nReturns: %s\n' % f['returns'])
                result += '\n'
                if isinstance(a, list):
                    ag = ['\n%s: %s\n' %
                          (x['name'], x['description']) for x in a]
                    arguments = '\n'.join(ag)
                elif isinstance(a, dict):
                    arguments = '%s: %s' % (a['name'], a['description'])
                result += str_format('\nArguments: \n%s' % arguments)
                result += '\n\nMSFT URL: https://social.msdn.microsoft.com/search/en-US/windows?query=%s' % f['name']
        except TypeError:
            continue
    pipepager(result, cmd='less -R')


with open('%s/r2msdn.json' % script_path) as j:
    data = json.loads(j.read())
    functions = data['functions']['function']

if args.info:
    show_info(functions, args.info)
    exit()

r = r2pipe.open()
logging.warning('Not fully tested. There may be some misses')
raw_input('Without proper analysis, a lot of anotations will fail.\n\
ENTER to continue')
r.cmd('e scr.breaklines = 1')
if len(r.cmdj('aflj')) < 3:
    try:
        logging.warning(
            '\nCould not find enough functions. Try running r2msdn after more analysis.')
    except TypeError:
        logging.warning(
            '\nCould not find enough functions. Try running r2msdn after more analysis.')

# get all addresses for the imports
address_for_import = [hex(plt['plt']) for plt in r.cmdj('iij')]

for address in address_for_import:
    # axt for the import addresses
    xref = r.cmdj('axtj @ %s' % address)
    for is_call in xref:
        # Checks to see if a type call or data
        if is_call['type'] == 'call':
            # addess of usage
            from_addr = hex(is_call['from'])
            logging.info('\n' + '-' * 40)
            function_name = is_call['opcode'].split(
                ' ')[-1].split('_')[-1].strip(']')
            logging.info(' [%s] at %s' %
                         (function_name, from_addr))
            r.cmd('s %s' % from_addr)
            # gets a list of the arguments
            push_args = find_args(functions, function_name)
            if push_args is None:
                pass
            else:
                # sets description of function
                if args.describe:
                    r.cmd('CC %s' % push_args[1])
                # gets length of total args
                pdj = r.cmdj('pdj -%s' % str(len(push_args[0])))
                # if more than one arg
                if isinstance(push_args[0], list):
                    for o in range(len(pdj)):
                        addr_of_arg = hex(pdj[o]['offset'])
                        r.cmd('CC %s @ %s' % (push_args[0][o], addr_of_arg))
                        logging.info(' [+] Added %s at %s' %
                                     (push_args[0][o], addr_of_arg))
                # if single arg
                elif type(push_args[0]).__name__ == 'unicode':
                    addr_of_arg = hex(r.cmdj('pdj -1 @ %s' %
                                             from_addr)[0]['offset'])
                    r.cmd('CC %s @ %s' % (push_args[0], addr_of_arg))
                    logging.info(' [+] Added %s at %s' %
                                 (push_args[0], addr_of_arg))

