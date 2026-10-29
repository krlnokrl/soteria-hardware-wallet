"""Capture unhashed RNGpin() bytes from the RNG test firmware (env:rngtest_*).

The on-board report covers the basics; for deeper analysis capture a file
and feed it to offline tools, e.g. `ent rng.bin` or NIST SP 800-90B
`ea_non_iid rng.bin 8` (use --raw for the pre-whitening pool bits).

    pip install pyserial
    python test/tools/rng_capture.py COM5 rng.bin 100000 [--raw]

Close the serial monitor first; only one program can hold the port.
"""
import argparse
import sys
import time

import serial


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("port", help="serial port of the board, e.g. COM5 or /dev/ttyACM0")
    ap.add_argument("out", help="output file (binary)")
    ap.add_argument("nbytes", type=int, help="number of bytes to capture")
    ap.add_argument("--raw", action="store_true",
                    help="raw pool bits before XOR whitening instead of RNGpin() output")
    a = ap.parse_args()

    with serial.Serial(a.port, 115200, timeout=10) as s, open(a.out, "wb") as f:
        s.write(b"x")            # stops a stream left running; else prints help
        time.sleep(1.0)
        s.reset_input_buffer()
        s.write(b"B" if a.raw else b"b")

        got, t0 = 0, time.time()
        while got < a.nbytes:
            chunk = s.read(min(4096, a.nbytes - got))
            if not chunk:
                sys.exit(f"timeout after {got} bytes - is the RNG test firmware flashed?")
            f.write(chunk)
            got += len(chunk)
            rate = got / max(time.time() - t0, 1e-9)
            print(f"\r{got}/{a.nbytes} bytes  {rate:.0f} B/s  "
                  f"ETA {(a.nbytes - got) / max(rate, 1e-9):.0f} s ", end="", flush=True)

        s.write(b"x")
        time.sleep(0.2)
        s.reset_input_buffer()
    print(f"\nwrote {got} bytes to {a.out}")


if __name__ == "__main__":
    main()
