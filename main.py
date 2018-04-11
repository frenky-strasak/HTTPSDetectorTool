#!/usr/bin/env python3
# Author: Frantisek Strasak strasfra[ampersat]fel.cvut.cz

import argparse
from bro_source import bro_manager

__version__ = 1.0

def check_arg():

    # version
    # help
    # read one bro folder
    # read multi folders of bro
    # read suricata eye.json
    # read more suricata eye.jsons

    # Parse the parameters
    parser = argparse.ArgumentParser(description="Program HTTPS Detector tool version {}. Author: "
                                                 "Frantisek Strasak, strasfra@fel.cvut.cz".format(__version__),
                                     usage='%(prog)s -n <screen_name> [options]')
    parser.add_argument('-v', '--verbose', help='0-no verbosity, 1-middle verbosity, 2-high verbosity (default is 1)',
                        action='store', default=1, required=False, type=int)
    parser.add_argument('-V', '--version', help='{}'.format(__version__), action='version',
                        version='{}'.format(__version__))

    parser.add_argument('-b', '--brofolder', help='Path to Bro folder where all log files are.', action='store',
                        required=False)
    parser.add_argument('-B', '--brofolders', help='Multiple captures. Path to folder where Bro folders are.',
                        action='store', required=False)

    parser.add_argument('-s', '--suricatajson', help='Path to eye.json file.', action='store',
                        required=False)
    parser.add_argument('-S', '--suricatajsons', help='Multiple captures. Path to folder where eye.json files are.',
                        action='store', required=False)

    args = parser.parse_args()

    # Check arguments

    if not (args.brofolder or args.brofolders):
        parser.error('No action requested, see --help')

    return args


if __name__ == '__main__':
    args = check_arg()

    if args.brofolder:
        # print('Bro folder: {}'.format(args.brofolder))
        bro_manager.read_one_capture(args.brofolder, args.verbose)
    elif args.brofolders:
        print('Bro folders: {}'.format(args.brofolder))
    elif args.suricatajson:
        print('Suricata : {}'.format(args.brofolder))
    elif args.suricatajsons:
        print('Suricatas : {}'.format(args.brofolder))
    elif args.version:
        print('{}'.format(__version__))
