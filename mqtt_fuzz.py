#! /usr/bin/python
# pylint: disable=line-too-long,no-member

# Copyright 2015 F-Secure Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License"); you
# may not use this file except in compliance with the License.  You
# may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.  See the License for the specific language governing
# permissions and limitations under the License.

# Modified by Yuji Tabata(uztbt)

"""mqtt_fuzz.py

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
from twisted.spread import pb
import sys
from twisted.internet.protocol import ReconnectingClientFactory
from twisted.internet import defer

class MQTTFuzzProtocol(Protocol):
    '''Implementation of a pseudo-MQTT protocol that conducts predefined MQTT
    sessions by replaying a series of stored MQTT control packets.'''

    def dataReceived(self, data):
        """Callback. If we receive data from the remote peer, print it out

        :param data: Data received from remote peer

        """
        print "%s:%s:Server -> Fuzzer: %s" % (calendar.timegm(time.gmtime()), self.session_id, binascii.b2a_base64(data))

    def connectionMade(self):
        """Callback. We have connected to the MQTT server, so start banging away

        """
        print "%s:%s:Connected to server" % (calendar.timegm(time.gmtime()), self.session_id)
        self.send_next_pdu()

    def connectionLost(self, reason):
        self.callLaterHandle.cancel()

    def send_next_pdu(self):
        """Send a PDU and schedule the next PDU

        """
        from twisted.internet import reactor

        try:
            self.send_pdu(self.current_session.next())
            self.callLaterHandle=reactor.callLater(self.send_delay / 1000, self.send_next_pdu)
        except StopIteration:
            # We have sent all the PDUs of this session. Tear down
            # connection. It will trigger a reconnection in the factory.
            print "%s:%s:End of session, initiating disconnect." % (calendar.timegm(time.gmtime()), self.session_id)
            self.callLaterHandle=reactor.callLater(1000, self.send_next_pdu) #  makeshift
            self.transport.loseConnection()

    def send_pdu(self, pdutype):
        """Send either a valid case or a fuzz case

        :param pdutype: Message type (Directory from which the message will be sent)

        """
        from twisted.internet import reactor

        try:
            # 1 in 10, send a fuzz case, otherwise a valid case
            if random.randint(1, 10) < self.fuzz_ratio:
                print "%s:%s:Sending fuzzed %s" % (calendar.timegm(time.gmtime()), self.session_id, pdutype)
                data = self.fuzzdata.get_next_fuzzcase(os.path.join(self.validcases_path, pdutype))
            else:
                print "%s:%s:Sending valid %s" % (calendar.timegm(time.gmtime()), self.session_id, pdutype)
                data = self.fuzzdata.get_valid_case(os.path.join(self.validcases_path, pdutype))
            print "%s:%s:Fuzzer -> Server: %s" % (calendar.timegm(time.gmtime()), self.session_id, binascii.b2a_base64(data).rstrip())
            self.transport.write(data)
        except (IOError) as err:
            print "IO Error!!!!! Could not run the fuzzer. Check -validcases and -radamsa options. The error was: %s" % err
            reactor.stop()
        except (OSError) as err:
            print "OS Error!!!!! Could not run the fuzzer. Check -validcases and -radamsa options. The error was: %s" % err
            reactor.stop()

class MQTTClientFactory(ReconnectingClientFactory):
    '''Factory that creates pseudo-MQTT clients'''
    maxDelay = 0.05
    protocol = MQTTFuzzProtocol

    # These are the sessions that we will be running through.
    # If you want to extend the fuzzer with new control packets,
    # copy some raw valid control packets into a directory under valid-cases
    # and refer to that directory by name in one of these sessions here.
    # See readme.txt.
    control_packets_in_between = ['subscribe', 'publish', 'publish-ack', 'publish-release', 'publish-complete', 'publish-received']
    session_length = 6
    session_structures = [('connect',) + middle + ('disconnect',) for middle in itertools.permutations(control_packets_in_between, session_length-2)]

    def __init__(self, fuzz_ratio, send_delay, radamsa_path, validcases_path):
        # We cycle through the sessions again and again
        self.session = itertools.cycle(iter(self.session_structures))

        # Copy the data into this instance so we can use it later
        self.fuzzdata = fuzzpool.FuzzPool(radamsa_path)
        self.fuzz_ratio = fuzz_ratio
        self.send_delay = send_delay
        self.validcases_path = validcases_path

    def buildProtocol(self, address):
        # Create the fuzzer instance
        protocol_instance = ClientFactory.buildProtocol(self, address)

        # Tell the fuzzer instance which type of session it should run
        protocol_instance.current_session = iter(self.session.next())
        protocol_instance.fuzzdata = self.fuzzdata
        protocol_instance.session_id = str(uuid.uuid4())
        protocol_instance.fuzz_ratio = self.fuzz_ratio
        protocol_instance.send_delay = self.send_delay
        protocol_instance.validcases_path = self.validcases_path
        return protocol_instance

#     def clientConnectionFailed(self, connector, reason):
#         # Callback: The server under test has died
#         from twisted.internet import reactor
#         print "clientConnectionFailed"
#         print "%s:Failed to connect to MQTT server: %s" % (calendar.timegm(time.gmtime()), reason)
#         ReconnectingClientFactory.clientConnectionFailed(self,connector,reason)

#     def clientConnectionLost(self, connector, reason):
#         # Callback: The server under test closed connection or we decided to
#         # tear down the connection at the end of a session. We'll
#         # reconnect (which starts another session in the protocol
#         # instance)
#         print "%s:Connection to MQTT server lost: %s" % (calendar.timegm(time.gmtime()), reason)
#         print "%s:Reconnecting" % calendar.timegm(time.gmtime())
#         ReconnectingClientFactory.clientConnectionLost(self, connector, reason)
# #        defer.DeferredList([reconnection], consumeErrors=True).addCallbacks(self.ReconnectionDone,self.ReconnectionFailed)

    def reconennctionDone(self, results):
        print "Reconnection Done!!!!!!!!"

    def reconnectionFailed(self, results):
        print "Reconnection Failed!!!!!!!!!!"
class PBServer(pb.Root):
    def __init__(self,port):
        self.id = port
        self.remote_run_tests()

    def __str__(self): # String representation
        return "PBServer %s" % self.id

    def remote_initialize(self, initArg):
        return "%s initialized" % self
        
    def remote_run_tests(self, host="localhost", port=1883, ratio=3, delay=50, radamsa="radamsa", validcases="valid-cases/"):
        '''Main function to run'''
        hostname = host
        port = int(port)
        print "%s:Starting fuzz run to %s:%s" % (calendar.timegm(time.gmtime()), hostname, port)
        reactor.connectTCP(hostname, port, MQTTClientFactory(ratio, delay, radamsa, validcases))
        print "%s:Stopped fuzz run to %s:%s" % (calendar.timegm(time.gmtime()), hostname, port)

if __name__ == '__main__':
    from twisted.internet import reactor
    port = sys.argv[1]
    reactor.listenTCP(int(port), pb.PBServerFactory(PBServer(port)))
    reactor.run()
