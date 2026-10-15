
from time import perf_counter_ns
from statistics import median
import hmac

SECRET = bytes(range(64))

def vulnerable_compare(a, b):
    if len(a) != len(b):
        return False

    for x, y in zip(a, b):
        if x != y:
            return False

    return True

def measure(candidate, count=5000):
    results = []

    for _ in range(count):
        start = perf_counter_ns()
        vulnerable_compare(SECRET, candidate)
        results.append(perf_counter_ns() - start)

    return median(results)

def main():
    wrong_first = bytes([255]) + SECRET[1:]
    wrong_last = SECRET[:-1] + bytes([255])

    print("=== TIMING DEMO ===")
    print("Wrong first byte:", measure(wrong_first), "ns")
    print("Wrong last byte :", measure(wrong_last), "ns")

    print("Constant-time comparison:")
    print(hmac.compare_digest(SECRET, wrong_first))

if __name__ == "__main__":
    main()
