import argparse
import asyncio
import logging
import time
import threading
import socket
import ipaddress
from typing import Optional
from enum import Enum, auto
from bleak import BleakClient, BleakScanner

SERVICE_UUID = "ab1ff2ae-f46c-ba92-c746-18629eb44091"
SCANNER_UUID    = "0b93af70-61ed-18bd-9b49-2f49f1fdf854"
RSSI_UUID = "d3107aa5f264-c3a1-b849-b7ff-c62f72f8"
CONTROL_UUID = "52764e3e958f-a5ad-284b-9531-4f42c9bc"
THR_UUID = "e804ecd5163f-f6ac-824d-fe04-b71ac767"
logger = logging.getLogger(__name__)

from dataclasses import dataclass
from typing import Callable, Dict, List 

CMD_CONNECT     = 0x01
CMD_DISCONNECT  = 0x02
CMD_SCAN_ONCE   = 0x03
CMD_SCAN_START  = 0x04
CMD_SCAN_STOP   = 0x05
CMD_TCP_START   = 0x06
CMD_UDP_START   = 0x07

RESP_WIFI_CONNECTED     = 0x01
RESP_WIFI_DISCONNECTED  = 0x02
RESP_WIFI_ACK           = 0x03
RESP_IP_RECEIVED        = 0x04
RESP_THROUGHPUT_DONE    = 0x05

CMD_TYPE_SCANNER  = 0x01
CMD_TYPE_RSSI     = 0x02
CMD_TYPE_CTRL     = 0x03
CMD_TYPE_THR  = 0x04
SCAN_COMMANDS = {CMD_SCAN_ONCE, CMD_SCAN_START, CMD_SCAN_STOP}

SCAN_COMMANDS = {
    "SCAN_ONCE": SCANNER_UUID,
    "SCAN_START": SCANNER_UUID,
    "SCAN_STOP": SCANNER_UUID,
    "RSSI_ONCE": RSSI_UUID,
    "RSSI_START": RSSI_UUID,
    "RSSI_STOP": RSSI_UUID,
}

CMD_TYPE_MAP = {
    "SCAN_ONCE": CMD_TYPE_SCANNER,
    "SCAN_START": CMD_TYPE_SCANNER,
    "SCAN_STOP": CMD_TYPE_SCANNER,
    "RSSI_ONCE": CMD_TYPE_RSSI,
    "RSSI_START": CMD_TYPE_RSSI,
    "RSSI_STOP": CMD_TYPE_RSSI,
}

class WifiState(Enum):
    DISCONNECTED = auto()
    CONNECTED = auto()
wifi_state = WifiState.DISCONNECTED
paired = False

class ThroughputMode(Enum):
    NONE = auto()
    TCP = auto()
    UDP = auto()

throughput_mode = ThroughputMode.NONE
throughput_lock = threading.Lock()

class DeviceNotFoundError(Exception):
    pass

class Args(argparse.Namespace):
    address: Optional[str]
    debug: bool

def start_throughput_server(proto: str, ip: str, port: int, duration: int):
    global throughput_mode

    with throughput_lock:
        if throughput_mode != ThroughputMode.NONE:
            raise RuntimeError("Throughput test already running")

        if proto == "TCP":
            throughput_mode = ThroughputMode.TCP
        elif proto == "UDP":
            throughput_mode = ThroughputMode.UDP
        else:
            raise ValueError("Unknown protocol")

    def server_thread():
        try:
            if proto == "TCP":
                run_tcp_server(ip, port, duration)
            else:
                run_udp_server(ip, port, duration)
        finally:
            global throughput_mode
            with throughput_lock:
                throughput_mode = ThroughputMode.NONE

    t = threading.Thread(target=server_thread, daemon=True)
    t.start()

def run_udp_server(ip: str, port: int, duration: int):
    peer = None 
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((ip, port))
    sock.settimeout(duration + 5)

    # first connection
    total_bytes = 0
    try:
        data, addr = sock.recvfrom(4096)
        peer = addr
        total_bytes += len(data)
    except:
        raise ValueError("UDP server failed to receive first packet")
    start = time.time()
    
    while time.time() - start < duration:
        try:
            data, addr = sock.recvfrom(4096)
        except socket.timeout:
            break
        total_bytes += len(data)

    elapsed = time.time() - start
    mbps = (total_bytes * 8) / (elapsed * 1e6)

    print(f"[UDP] Received {total_bytes} bytes in {elapsed:.2f}s")
    print(f"[UDP] Throughput: {mbps:.2f} Mbps")

    sock.close()

def run_tcp_server(ip: str, port: int, duration: int):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.settimeout(duration + 5)
    sock.bind((ip, port))
    sock.listen(1)

    print(f"[TCP] Listening on {ip}:{port}")

    try:
        conn, addr = sock.accept()
    except Exception as e:
        print(f"[TCP] accept failed: {e}")
        sock.close()
        return
        
    print(f"[TCP] Client connected from {addr}")

    total_bytes = 0
    start = time.time()

    while time.time() - start < duration:
        data = conn.recv(4096)
        if not data:
            break
        total_bytes += len(data)

    elapsed = time.time() - start
    mbps = (total_bytes * 8) / (elapsed * 1e6)

    print(f"[TCP] Received {total_bytes} bytes in {elapsed:.2f}s")
    print(f"[TCP] Throughput: {mbps:.2f} Mbps")

    conn.close()
    sock.close()

def build_command(cmd_type: int, cmd: int, ssid: Optional[str] = None, password: Optional[str] = None,
                  ip: Optional[str] = None, port: Optional[int] = None, duration: Optional[int] = None) -> bytes:
    """Build the BLE payload for a command."""
    if cmd == CMD_CONNECT:
        if ssid is None or password is None:
            raise ValueError("CONNECT command requires SSID and password")
        ssid_bytes = ssid.encode()
        pass_bytes = password.encode()
        if len(ssid_bytes) > 32 or len(pass_bytes) > 64:
            raise ValueError("SSID or password too long")
        payload = bytearray([cmd_type, CMD_CONNECT, len(ssid_bytes)]) + ssid_bytes + bytearray([len(pass_bytes)]) + pass_bytes
        return bytes(payload)
    
    elif cmd == CMD_TCP_START or cmd == CMD_UDP_START:
        if port is None or duration is None:
            raise ValueError("requires port and duration in seconds")
        if not (0 <= port <= 65535) or not (0 <= duration <= 255):
            raise ValueError("Port and duration must be 0-255")
        # convert to 2-byte big-endian
        ip_bytes = ipaddress.IPv4Address(ip).packed
        port_bytes = port.to_bytes(2, "big")
        duration_bytes = duration.to_bytes(1, "big")
        payload = bytearray([cmd_type, cmd]) + ip_bytes + port_bytes + duration_bytes
        return bytes(payload)

    else:
        return bytes([cmd_type, cmd])

def stdin_reader(loop, queue, shutdown_event): 
    while not shutdown_event.is_set(): 
        try: 
            cmd = input("> ") 
        except EOFError:
            asyncio.run_coroutine_threadsafe(shutdown_event.set(), loop)
            break
        asyncio.run_coroutine_threadsafe(queue.put(cmd), loop)

def parse_command(line: str):
    print(f"[CMD INPUT] {line}") 
    parts = line.strip().split()
    if not parts:
        raise ValueError("Empty command")

    cmd = parts[0].upper()
    args = parts[1:]
    cmd_code = 0x00;

    # ---- CONNECT / DISCONNECT ----
    if cmd == "CONNECT":
        if len(args) != 2:
            raise ValueError("CONNECT requires: <ssid> <password>")
        cmd_code = CMD_CONNECT
        ssid, password = args

        payload = build_command(CMD_TYPE_CTRL, cmd_code, ssid, password)
        return CONTROL_UUID, payload

    elif cmd == "DISCONNECT":
        if args:
            raise ValueError("DISCONNECT takes no arguments")
        cmd_code = CMD_DISCONNECT
        return CONTROL_UUID, build_command(CMD_TYPE_CTRL, cmd_code)

    # ---- THROUGHPUT commands ----
    elif cmd == "TCP_THROUGHPUT":
        if len(args) != 3:
            raise ValueError("TCP_THROUGHPUT requires <ip> <port> <duration>")
        ip = args[0]
        port = int(args[1])
        duration = int(args[2])
        payload = build_command(CMD_TYPE_THR, CMD_TCP_START, ip=ip, port=port, duration=duration)

        if wifi_state != WifiState.CONNECTED:
            raise ValueError("ESP is not connected to Wi-Fi")
        
        start_throughput_server("TCP", ip, port, duration)

        return THR_UUID, payload

    elif cmd == "UDP_THROUGHPUT":
        if len(args) != 3:
            raise ValueError("UDP_THROUGHPUT requires <ip> <port> <duration>")
        ip = args[0]
        port = int(args[1])
        duration = int(args[2])
        payload = build_command(CMD_TYPE_THR, CMD_UDP_START, ip=ip, port=port, duration=duration)
        if wifi_state != WifiState.CONNECTED:
            raise ValueError("ESP is not connected to Wi-Fi")
        
        start_throughput_server("UDP", ip, port, duration)

        return THR_UUID, payload

    # ---- SCAN commands ----
    elif cmd in SCAN_COMMANDS:
        write_uuid = SCAN_COMMANDS[cmd]
        cmd_type = CMD_TYPE_MAP[cmd]
        return write_uuid, build_command(cmd_type, {"SCAN_ONCE": CMD_SCAN_ONCE,
                                                    "SCAN_START": CMD_SCAN_START,
                                                    "SCAN_STOP": CMD_SCAN_STOP,
                                                    "RSSI_ONCE": CMD_SCAN_ONCE, 
                                                    "RSSI_START": CMD_SCAN_START,
                                                    "RSSI_STOP": CMD_SCAN_STOP}[cmd])
    raise ValueError(f"Unknown command: {cmd}")

async def command_sender(client, queue, shutdown_event):
    global paired
    while not shutdown_event.is_set():
        line = await queue.get()
        line = line.strip()

        if not line:
            continue

        if line.lower() == "exit":
            shutdown_event.set()
            break

        try:
            uuid, payload = parse_command(line)
        except ValueError as e:
            print(f"[CMD ERROR] {e}")
            continue

        if uuid == CONTROL_UUID and not paired:
            print("[BLE] Pairing...")
            await client.pair()
            paired = True
            print("[BLE] Paired")

        try:
            await asyncio.sleep(0.5)
            await client.write_gatt_char(uuid, payload, response=True)
        except Exception as e:
            print(f"[BLE ERROR] Failed to write to {uuid}: {e}")

async def run_ble_client(
    args: Args, scanner_queue: asyncio.Queue[tuple[float, Optional[bytearray]]],
    rssi_queue: asyncio.Queue[tuple[float, Optional[bytearray]]], 
    control_queue: asyncio.Queue[tuple[float, Optional[bytearray]]],
    thr_queue: asyncio.Queue[tuple[float, Optional[bytearray]]]
):
    global paired
    logger.info("starting the client...")
    if not args.address:
        raise ValueError("--address must be provided")

    device = await BleakScanner.find_device_by_address(args.address)
    if device is None:
        logger.error("could not find device with address '%s'", args.address)
        raise DeviceNotFoundError

    logger.info("connecting to the server...")

    command_queue = asyncio.Queue()
    shutdown_event = asyncio.Event()

    async def scanner_handler(sender: str, data: bytearray) -> None:
        print(f"[Scan Handler] Received data from {sender}")
        await scanner_queue.put((time.time(), data))

    async def rssi_handler(sender: str, data: bytearray) -> None:
        print(f"[RSSI Handler] Received data from {sender}")
        if not data:
            return
        rssi = int(data[0])
        await rssi_queue.put((time.time(), rssi))

    async def control_handler(sender: str, data: bytearray) -> None:
        print(f"[Control Handler] Received data from {sender}")
        global wifi_state

        if not data:
            return

        state_byte = data[0]
        if state_byte == RESP_WIFI_CONNECTED:
            wifi_state = WifiState.CONNECTED
            print("[BLE] Wi-Fi connected")
            return
        elif state_byte == RESP_WIFI_DISCONNECTED:
            wifi_state = WifiState.DISCONNECTED
            print("[BLE] Wi-Fi disconnected")
            return
        elif state_byte == RESP_WIFI_ACK:
            print("[BLE] Wi-Fi ack")
            return

        await control_queue.put((time.time(), state_byte))
        
    async def thr_handler(sender: str, data: bytearray) -> None:
        print(f"[Throughput Server] Received data from {sender}")
        if not data:
            return
        response = data[0]
        # TODO
        await thr_queue.put((time.time(), response))

    async with BleakClient(device) as client:
        logger.info("connected")

        # init
        await client.start_notify(SCANNER_UUID, scanner_handler)
        await client.start_notify(RSSI_UUID,    rssi_handler)
        await client.start_notify(CONTROL_UUID, control_handler)
        await client.start_notify(THR_UUID, thr_handler)
        
        # commands
        print("Connected. Type commands:")
        loop = asyncio.get_running_loop()
        threading.Thread(target=stdin_reader, args=(loop, command_queue, shutdown_event), daemon=True).start()
        await command_sender(client, command_queue, shutdown_event)
        await asyncio.sleep(2.0)

        # Graceful shutdown
        await client.stop_notify(SCANNER_UUID)
        await client.stop_notify(RSSI_UUID)
        await client.stop_notify(CONTROL_UUID)
        await client.stop_notify(THR_UUID)
        if paired:
            print("[BLE] Unpairing...")
            await client.unpair()
            print("[BLE] unpaired")


    await scanner_queue.put((time.time(), None))
    await rssi_queue.put((time.time(),    None))
    await control_queue.put((time.time(), None))
    await thr_queue.put((time.time(), None))

    logger.info("disconnected")

async def scanner_consumer(queue: asyncio.Queue[tuple[float, Optional[bytearray]]]):
    logger.info("Starting scanner consumer")

    while True:
        epoch, data = await queue.get()
        if data is None:
            logger.info("Got message from client about disconnection. Exiting scanner consumer loop...")
            break

        offset = 0
        networks = []

        # Unpack all records in this packet
        while offset < len(data):
            ssid_len = data[offset]
            offset += 1

            # Safety check
            if offset + ssid_len > len(data):
                logger.warning("Malformed packet: SSID length exceeds packet length")
                break

            ssid_bytes = data[offset:offset+ssid_len]
            try:
                ssid = ssid_bytes.decode('utf-8')
            except UnicodeDecodeError:
                ssid = ssid_bytes.hex()
            offset += ssid_len

            if offset >= len(data):
                logger.warning("Malformed packet: missing RSSI")
                break

            rssi = int(data[offset])
            offset += 1

            networks.append((ssid, rssi))

        # Print results
        for ssid, rssi in networks:
            s_rssi = rssi - 256 if rssi > 127 else rssi
            print(f"[{time.strftime('%H:%M:%S', time.localtime(epoch))}] SSID: '{ssid}', RSSI: {s_rssi} dBm")

async def rssi_consumer(queue: asyncio.Queue[tuple[float, Optional[int]]]):
    logger.info("Starting rssi consumer")

    while True:
        epoch, rssi = await queue.get()
        if rssi is None:
            logger.info("Got incorrect rssi response. Exiting control consumer loop...")
            break
        s_rssi = rssi - 256 if rssi > 127 else rssi
        print(f"[{time.strftime('%H:%M:%S', time.localtime(epoch))}] RSSI: {s_rssi} dBm")

async def control_consumer(queue: asyncio.Queue[tuple[float, Optional[bytearray]]]):
    logger.info("Starting control consumer")

    while True:
        epoch, data = await queue.get()
        print(f"[{time.strftime('%H:%M:%S', time.localtime(epoch))}] CONTROL CODE: {data}")
        if data is None:
            logger.info("Got message from client about disconnection. Exiting control consumer loop...")
            break

async def throughput_consumer(queue: asyncio.Queue[tuple[float, Optional[bytearray]]]):
    logger.info("Starting throughput consumer")
    while True:
        epoch, data = await queue.get()
        print(f"[{time.strftime('%H:%M:%S', time.localtime(epoch))}] THROUGHPUT CONTROL CODE: {data}")
        if data is None:
            logger.info("Got message from client about disconnection. Exiting throughput consumer loop...")
            break

async def main(args: Args) -> None:
    scanner_queue   = asyncio.Queue()
    rssi_queue      = asyncio.Queue()
    control_queue   = asyncio.Queue()
    thr_queue   = asyncio.Queue()

    tasks = [
        asyncio.create_task(run_ble_client(args, scanner_queue, rssi_queue, control_queue, thr_queue)),
        asyncio.create_task(scanner_consumer(scanner_queue)),
        asyncio.create_task(rssi_consumer(rssi_queue)),
        asyncio.create_task(control_consumer(control_queue)),
        asyncio.create_task(throughput_consumer(thr_queue))]

    try:
        await asyncio.gather(*tasks)
    except DeviceNotFoundError:
        pass
    finally:
        for t in tasks:
            t.cancel()

if __name__ == "__main__":
    parser = argparse.ArgumentParser()

    device_group = parser.add_mutually_exclusive_group(required=True)

    device_group.add_argument(
        "--address",
        metavar="<address>",
        help="the address of the bluetooth device to connect to",
    )

    parser.add_argument(
        "-d",
        "--debug",
        action="store_true",
        help="sets the logging level to debug",
    )

    args = parser.parse_args(namespace=Args())

    log_level = logging.DEBUG if args.debug else logging.INFO
    logging.basicConfig(
        level=log_level,
        format="%(asctime)-15s %(name)-8s %(levelname)s: %(message)s",
    )

    asyncio.run(main(args))
