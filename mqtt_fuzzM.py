"""mqtt_fuzzM.py

Performs MQTT sessions as a client with a fuzzed PDU once in a while.
"""

from __future__ import division
from twisted.internet.protocol import Protocol, ClientFactory
import itertools
import time
import binascii
import fuzzpool
import random
import uuid
import calendar
import argparse
import os
import socket

def run_tests(host, port, ratio, delay, radamsa, validcases):  # pylint: disable=R0913
    '''Main function to run'''
    hostname = host
    port = int(port)
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((hostname, port))
    client.send("MQTT")
    responce = client.recv(100)
    print responce


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='MQTT-fuzz, a simple MQTT protocol fuzzer.')
    parser.add_argument('host', metavar='target_host',
                        type=str,
                        default='localhost',
                        help='Host name of MQTT server / broker under test')
    parser.add_argument('port', metavar='target_port',
                        type=int,
                        default=1883,
                        help='Port number of MQTT server / broker under test')
    parser.add_argument('-ratio', metavar='fuzz_ratio',
                        type=int, required=False, choices=range(0, 11),
                        default=3, help='How many control packets should be fuzzed per 10 packets sent (0 = fuzz nothing, 10 = fuzz all packets, default is 3)')
    parser.add_argument('-delay', metavar='send_delay',
                        type=int, required=False,
                        default=50, help='How many milliseconds to wait between control packets sent, default is 50 ms')
    parser.add_argument('-validcases', metavar='validcase_path',
                        type=str, required=False,
                        default='valid-cases/', help='Path to the valid-case directories, default is "valid-cases/"')
    parser.add_argument('-fuzzer', metavar='fuzzer_path', type=str,
                        default='radamsa', required=False,
                        help='Path and name of the Radamsa binary, default "radamsa"')
    args = parser.parse_args()
    run_tests(args.host, args.port, args.ratio, args.delay, args.fuzzer, args.validcases)

