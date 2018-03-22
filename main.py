#!/usr/bin/env python3
# Author: Frantisek Strasak strasfra[ampersat]fel.cvut.cz

import argparse

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
                                                 "Frantisek Strasak, strasfra[ampersat]fel.cvut.cz".format(__version__),
                                     usage='%(prog)s -n <screen_name> [options]')
    parser.add_argument('-v', '--verbose', help='0-no verbosity, 1-middle verbosity, 2-high verbosity (default is 1)',
                        action='store', default=1, required=False, type=int)
    parser.add_argument('-b', '--brofolder', help='Path to Bro folder where all log files are.', action='store',
                        required=False)
    parser.add_argument('-B', '--brofolders', help='Multiple captures. Path to folder where Bro folders are.',
                        action='store', required=False)

    parser.add_argument('-s', '--suricatajson', help='Path to eye.json file.', action='store',
                        required=False)
    parser.add_argument('-S', '--suricatajson', help='Multiple captures. Path to folder where eye.json files are.',
                        action='store', required=False)

    args = parser.parse_args()

    if not (args.brofolder and args.brofolders):
        parser.error('No action requested, see --help')

    if args.brofolder:
        print('Folder: {}'.format(args.brofolder))

    return args


if __name__ == '__main__':
    args = check_arg()
    # Go to folder(s) and read data. Create ssl-units a detect them by model.

