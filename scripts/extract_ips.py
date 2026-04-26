import csv
import sys
from pathlib import Path


def main(src: str, dst: str) -> None:
    with Path(src).open(newline="") as f, Path(dst).open("w") as out:
        reader = csv.DictReader(f)
        for row in reader:
            out.write(row["ipAddress"] + "\n")


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
