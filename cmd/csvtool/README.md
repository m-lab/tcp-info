# csvtool

The csvtool is intended to convert from ArchiveRecord files to CSV files.
It currently only handles raw or zstd compressed JSONL files as source.
It takes a single command line argument, which is the name of the file, or "-" to read uncompressed JSONL from stdin.

## Examples:

```bash
zstd -cd 2019/04/01/ndt-jdczh_1553815964_00000000000003E8.00184.jsonl.zst | ./csvtool - > connection.csv
```

```bash
./csvtool 2019/04/01/ndt-jdczh_1553815964_00000000000003E8.00184.jsonl.zst > connection.csv
```
