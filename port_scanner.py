"""
Network Port Scanner
--------------------
A modular, multi-threaded TCP port scanner built using Python's standard `socket`
and `concurrent.futures` libraries.
Designed for network and security analysis to verify open services on a target host.
"""

from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
import socket
import sys
import threading

# Thread lock for synchronizing terminal output across concurrent threads
PRINT_LOCK = threading.Lock()


def resolve_target(target: str) -> str | None:
    """Resolve a hostname or validate an IP address into an IPv4 address.

    Args:
        target: A hostname (e.g., 'scanme.nmap.org') or an IP address.

    Returns:
        The resolved IPv4 address string, or None if resolution fails.
    """
    try:
        # socket.gethostbyname resolves domain names to IPv4 addresses.
        # If an IP address is passed, it returns the IP unmodified.
        ip_address = socket.gethostbyname(target.strip())
        return ip_address
    except socket.gaierror:
        # gaierror: Address-related error (e.g., name resolution failure / NXDOMAIN)
        print(f"\n[!] Error: Unable to resolve host '{target}'. Please check the domain or IP.")
        return None
    except Exception as exc:
        print(f"\n[!] Unexpected error resolving '{target}': {exc}")
        return None


def get_port_range() -> tuple[int, int] | None:
    """Prompt the user for valid starting and ending port numbers.

    Returns:
        A tuple of (start_port, end_port) or None if interrupted.
    """
    while True:
        try:
            start_str = input("Enter starting port (1-65535): ").strip()
            end_str = input("Enter ending port (1-65535): ").strip()

            start_port = int(start_str)
            end_port = int(end_str)

            # Validate valid TCP port boundary: 1 through 65535
            if not (1 <= start_port <= 65535) or not (1 <= end_port <= 65535):
                print("[!] Error: Port numbers must be within the range 1 - 65535. Try again.\n")
                continue

            if start_port > end_port:
                print("[!] Error: Starting port cannot be greater than ending port. Try again.\n")
                continue

            return start_port, end_port

        except ValueError:
            print("[!] Error: Please enter valid integer numbers for ports.\n")
        except KeyboardInterrupt:
            print("\n[!] Input cancelled by user.")
            return None


def get_thread_count(default: int = 100, max_threads: int = 500) -> int | None:
    """Prompt the user for the number of concurrent worker threads.

    Args:
        default: Default thread count if user presses Enter without input.
        max_threads: Upper safety threshold to prevent OS socket exhaustion.

    Returns:
        Integer thread count or None if interrupted.
    """
    while True:
        try:
            prompt = f"Enter number of worker threads (1-{max_threads}) [Default: {default}]: "
            thread_input = input(prompt).strip()

            # Fall back to default if user pressed Enter
            if not thread_input:
                return default

            threads = int(thread_input)
            if not (1 <= threads <= max_threads):
                print(f"[!] Error: Thread count must be between 1 and {max_threads}. Try again.\n")
                continue

            return threads

        except ValueError:
            print("[!] Error: Please enter a valid integer for thread count.\n")
        except KeyboardInterrupt:
            print("\n[!] Input cancelled by user.")
            return None


def scan_port(target_ip: str, port: int, timeout: float = 1.0) -> bool:
    """Attempt a TCP 3-way handshake with target_ip on the given port.

    Args:
        target_ip: The target IPv4 address.
        port: The destination TCP port number.
        timeout: Socket timeout in seconds.

    Returns:
        True if the port is open (connection succeeded), False otherwise.
    """
    # Create an IPv4 (AF_INET), TCP (SOCK_STREAM) socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Set timeout to prevent hanging on unresponsive or filtered ports
    sock.settimeout(timeout)

    try:
        # connect_ex returns 0 on success, or an errno code on failure
        result = sock.connect_ex((target_ip, port))
        return result == 0
    except socket.error as err:
        with PRINT_LOCK:
            print(f" [!] Socket error on port {port}: {err}")
        return False
    finally:
        # Always close the socket descriptor to free system resources
        sock.close()


def _scan_and_report(target_ip: str, port: int, timeout: float = 1.0) -> tuple[int, bool]:
    """Worker task: scan a single port and print the result with thread-safe output.

    Args:
        target_ip: The target IPv4 address.
        port: The destination TCP port number.
        timeout: Socket timeout in seconds.

    Returns:
        Tuple of (port, is_open).
    """
    is_open = scan_port(target_ip, port, timeout)

    # Use PRINT_LOCK to ensure atomic console output across concurrent threads
    with PRINT_LOCK:
        if is_open:
            print(f"[+] Port {port:5d} : OPEN")
        else:
            print(f"[-] Port {port:5d} : CLOSED / TIMED OUT")

    return port, is_open



def scan_ports(
    target_ip: str,
    start_port: int,
    end_port: int,
    max_threads: int = 100,
    timeout: float = 1.0,
) -> list[int]:
    """Scan a range of TCP ports concurrently using ThreadPoolExecutor.

    Args:
        target_ip: The destination IPv4 address.
        start_port: Lower port bound (inclusive).
        end_port: Upper port bound (inclusive).
        max_threads: Number of concurrent worker threads.
        timeout: Socket connection timeout per port in seconds.

    Returns:
        A sorted list of port numbers found to be open.
    """
    open_ports = []
    total_ports = end_port - start_port + 1
    # Cap worker threads to total ports if scanning fewer ports than max_threads
    workers = min(max_threads, total_ports)

    print(f"\n[*] Scanning {total_ports} port(s) from {start_port} to {end_port} using {workers} thread(s)...")
    print("-" * 50)

    try:
        with ThreadPoolExecutor(max_workers=workers) as executor:
            # Submit all port scanning tasks to the thread pool
            future_to_port = {
                executor.submit(_scan_and_report, target_ip, port, timeout): port
                for port in range(start_port, end_port + 1)
            }

            try:
                # Process results as tasks complete
                for future in as_completed(future_to_port):
                    port, is_open = future.result()
                    if is_open:
                        open_ports.append(port)

            except KeyboardInterrupt:
                with PRINT_LOCK:
                    print("\n\n[!] Scan interrupted by user (Ctrl+C). Cancelling pending tasks...")
                # Cancel pending futures in the queue
                executor.shutdown(wait=False, cancel_futures=True)

    except KeyboardInterrupt:
        with PRINT_LOCK:
            print("\n[!] Exiting thread pool...")

    # Sort discovered open ports numerically since threads complete out of order
    open_ports.sort()
    return open_ports


def main() -> None:
    """Entry point for the port scanner CLI application."""
    print("=" * 50)
    print("       MULTI-THREADED NETWORK PORT SCANNER        ")
    print("=" * 50)

    try:
        # Step 1: Prompt user for target host (IP or domain name)
        target_input = input("Enter target host (IP or domain, e.g. scanme.nmap.org): ").strip()
        if not target_input:
            print("[!] Hostname or IP cannot be empty. Exiting.")
            sys.exit(1)

        # Step 2: Resolve target to IPv4 address
        print(f"\n[*] Resolving target '{target_input}'...")
        target_ip = resolve_target(target_input)
        if not target_ip:
            sys.exit(1)

        print(f"[+] Target resolved: {target_input} -> {target_ip}")

        # Step 3: Get validated port range from user
        port_range = get_port_range()
        if port_range is None:
            sys.exit(0)

        start_port, end_port = port_range

        # Step 4: Get desired thread count
        thread_count = get_thread_count(default=100, max_threads=500)
        if thread_count is None:
            sys.exit(0)

        # Step 5: Record start time and initiate concurrent scan
        start_time = datetime.now()
        print(f"\n[*] Scan started at: {start_time.strftime('%Y-%m-%d %H:%M:%S')}")

        open_ports = scan_ports(
            target_ip=target_ip,
            start_port=start_port,
            end_port=end_port,
            max_threads=thread_count,
            timeout=1.0,
        )

        # Step 6: Display summary and duration
        end_time = datetime.now()
        duration = end_time - start_time

        print("-" * 50)
        print(f"[*] Scan finished at: {end_time.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"[*] Total duration   : {duration.total_seconds():.2f} seconds")
        print(f"[*] Open ports found : {len(open_ports)}")

        if open_ports:
            print(f"[+] Open Port List   : {', '.join(map(str, open_ports))}")
        else:
            print("[-] No open ports discovered in the specified range.")
        print("=" * 50)

    except KeyboardInterrupt:
        print("\n\n[!] Exiting program. Goodbye.")
        sys.exit(0)
    except Exception as exc:
        print(f"\n[!] Unexpected error: {exc}")
        sys.exit(1)


if __name__ == "__main__":
    main()

