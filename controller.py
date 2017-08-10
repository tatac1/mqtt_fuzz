"""
Controller.py
Starts and manages solvers in separate processses for parallel processing.
Provides an interface to the Flex UI.
"""
startPort=8900
FlexControlPanelPort=8050
import os, sys
from subprocess import Popen
from twisted.spread import pb
from twisted.internet import reactor, defer
from twisted.web import server, resource
from pyamf.remoting.gateway.twisted import TwistedGateway

class Controller(object):
    def __init__(self,mqttPort):
        self.mqttPort = mqttPort
        cores = detectCPUs()
        print "Cores:",cores
        # Solver connections will be indexed by (ip, port):
        self.fuzzers = dict.fromkeys([("localhost",i) for i in range(startPort, startPort+cores)])
        # Start a subprocess on a core for each solver
        self.pids = [Popen(["python","mqtt_fuzz.py",str(port)],bufsize=0).pid for ip,port in self.fuzzers]
        print "PIDs:",self.pids
        self.connected = False
        reactor.callLater(1, self.connect) # Give the solvers time to start

    def failed(self, results, failureMessage = "Call Failed"):
        for (success, returnValue),(address,port) in zip (results, self.solvers):
            if not success:
                raise Exception("address: %s port: %d %s" % (address,port,failureMessage))
    def connect(self):
        "Begin the connection process"
        connections = []
        for address, port in self.fuzzers:
            factory = pb.PBClientFactory()
            reactor.connectTCP(address, port, factory)
            connections.append(factory.getRootObject())
        defer.DeferredList(connections, consumeErrors=True).addCallbacks(self.storeConnections, self.failed, errbackArgs=("Failed to Connect"))

    def storeConnections(self, results):
        for (success, fuzzer), (address, port) in zip (results, self.fuzzers):
            self.fuzzers[address, port] = fuzzer
        print "Connected; self.fuzzers:",self.fuzzers
        self.connected = True
        self.start_fuzzing()

    def start_fuzzing(self):
        "Begin the fuzzing procces"
        if not self.connected:
            return reactor.callLator(0.5, self.start)
        print "Start fuzzing..."
        deferreds = [fuzzer.callRemote("run_tests",port=self.mqttPort) for fuzzer in self.fuzzers.values()]
        
def detectCPUs():
    """
    Detects the number of CPUs on a system. Cribbed from pp.
    """
    # Linux, Unix and MacOS:
    if hasattr(os, "sysconf"):
        if os.sysconf_names.has_key("SC_NPROCESSORS_ONLN"):
            # Linux & Unix:
            ncpus = os.sysconf("SC_NPROCESSORS_ONLN")
            if isinstance(ncpus,int) and ncpus > 0:
                return ncpus
            else: #OS X
                return int(os.popen2("sysctl -n hw.ncpu")[1].read())
        # Windows:
        if os.environ.has_key("NUMBER_OF_PROCESSORS"):
            ncpus = int(os.environ["NUMBER_OF_PROCESSORS"])
            if ncpus > 0:
                return ncpus
        return 1 # Default
                
if __name__ == "__main__":
    controller = Controller(sys.argv[1])
    reactor.run()
