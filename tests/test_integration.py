"""End-to-end: TN5250 plugged into hackterm-core ProxyDaemon."""
import pytest
import socket
import threading
import time
from hack5250 import TN5250
from hackterm_core import ProxyDaemon, Storage, MutateOpts


@pytest.fixture
def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _pump(daemon, n=50, delay=0.01):
    for _ in range(n):
        daemon.tick()
        time.sleep(delay)


def test_e2e_reveal_via_proxy(tmp_path, free_port, pkt_hidden_field):
    """Server sends hidden field, client receives it visible.

    This proves: TN5250 implements Protocol correctly, ProxyDaemon
    routes through mutate(), the NONDISP rewrite actually works
    end-to-end through real sockets.
    """
    proto = TN5250()
    storage = Storage(str(tmp_path / "test.db"), "127.0.0.1", 23, 3271, False)

    server_listener = socket.socket()
    server_listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_listener.bind(("127.0.0.1", 0))
    server_listener.listen(1)
    server_port = server_listener.getsockname()[1]

    daemon = ProxyDaemon(
        protocol=proto, storage=storage,
        listen_addr=("127.0.0.1", free_port),
        target_addr=("127.0.0.1", server_port),
    )

    holder = {}
    def client_thread():
        time.sleep(0.1)
        c = socket.socket()
        c.connect(("127.0.0.1", free_port))
        holder["sock"] = c
    t = threading.Thread(target=client_thread)
    t.start()
    daemon.wait_for_client()
    t.join()

    daemon.connect_to_server()
    server_conn, _ = server_listener.accept()

    try:
        # Complete handshake — send IAC DO NEW-ENVIRON so detect() fires
        server_conn.send(bytes([0xFF, 0xFD, 0x27]))
        _pump(daemon)
        holder["sock"].setblocking(False)
        try:
            holder["sock"].recv(1024)  # drain handshake
        except BlockingIOError:
            pass

        assert daemon.handshake_complete is True

        # Arm reveal_hidden, send a packet with a hidden field.
        # (was: unprotect on a visible-protected field, but selective
        # unprotect now skips those — see test_unprotect_selective.py)
        daemon.mutate_opts.reveal_hidden = True
        server_conn.send(pkt_hidden_field)
        _pump(daemon)

        received = holder["sock"].recv(4096)

        # Re-parse what the client received — field should be visible now
        s = proto.parse(received)
        assert len(s.fields) == 1
        assert s.fields[0].hidden is False

        # Storage should have the ORIGINAL (still hidden)
        rows = storage.all_logs()
        s2c_data = [r[5] for r in rows if r[2] == "S" and len(r[5]) > 10]
        assert pkt_hidden_field in s2c_data

    finally:
        daemon.close()
        holder["sock"].close()
        server_conn.close()
        server_listener.close()
        storage.close()
