#!/usr/bin/env python3
"""Drives wg-helper over its socket, the way the GUI does, for the smoke
test. Speaks the line protocol in src/common/ipc.rs.

Usage: helper-client.py <socket> <command> [args]
  up-down <conf>       bring up, wait for a handshake, print stats, take down
  up-and-vanish <conf> bring up, then close the socket without DOWN
  hold <conf> <secs>   bring up and keep the tunnel for <secs> seconds
  up-expect-error <conf>  UP must be refused (another client owns the tunnel)
Prints KEY=value lines for the shell script to check.
"""

import socket
import sys
import time

HANDSHAKE_TIMEOUT = 20


class Helper:
    def __init__(self, path):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(60)
        self.sock.connect(path)
        self.file = self.sock.makefile("rb")

    def line(self):
        data = self.file.readline()
        if not data:
            raise SystemExit("helper closed the connection")
        return data.decode().rstrip("\n")

    def up(self, text):
        data = text.encode()
        self.sock.sendall(b"UP %d\n" % len(data) + data)
        reply = self.line()
        if reply.startswith("ERR"):
            return None, reply
        kind, tun, mtu, dns, endpoint, count = reply.split(" ")
        assert kind == "STARTED", reply
        routes = [self.line() for _ in range(int(count))]
        return {"tun": tun, "mtu": mtu, "dns_changed": dns, "endpoint": endpoint, "routes": routes}, None

    def stats(self):
        self.sock.sendall(b"STATS\n")
        reply = self.line()
        assert reply.startswith("STATS "), reply
        rx, tx, rxp, txp, age = reply.split(" ")[1:]
        return {"rx": int(rx), "tx": int(tx), "rx_packets": int(rxp), "tx_packets": int(txp), "age": age}

    def down(self):
        self.sock.sendall(b"DOWN\n")
        reply = self.line()
        assert reply == "OK", reply


def bring_up(helper, conf):
    started, error = helper.up(open(conf).read())
    if error:
        raise SystemExit("UP failed: " + error)
    print("TUN=" + started["tun"])
    print("ENDPOINT=" + started["endpoint"])
    print("DNS_CHANGED=" + started["dns_changed"])
    for route in started["routes"]:
        print("# " + route)
    sys.stdout.flush()
    return started


def main():
    path, command = sys.argv[1], sys.argv[2]
    helper = Helper(path)
    if command == "up-down":
        bring_up(helper, sys.argv[3])
        deadline = time.time() + HANDSHAKE_TIMEOUT
        stats = helper.stats()
        while stats["age"] == "-" and time.time() < deadline:
            time.sleep(0.5)
            stats = helper.stats()
        print("HANDSHAKE=" + ("no" if stats["age"] == "-" else "yes"))
        time.sleep(2)
        stats = helper.stats()
        print("RX=%d TX=%d" % (stats["rx"], stats["tx"]))
        helper.down()
        print("DOWN=ok")
    elif command == "up-and-vanish":
        bring_up(helper, sys.argv[3])
        helper.sock.close()
    elif command == "hold":
        bring_up(helper, sys.argv[3])
        time.sleep(float(sys.argv[4]))
        helper.down()
    elif command == "up-expect-error":
        started, error = helper.up(open(sys.argv[3]).read())
        print("REFUSED=" + ("yes: " + error if error else "no"))
        if started:
            helper.down()
    else:
        raise SystemExit("unknown command " + command)


if __name__ == "__main__":
    main()
