# csvtool

The csvtool is intended to convert the ArchiveRecord file format produced by
tcp-info to more easily usable CSV files. csvtool currently only handles
individual, raw or zstd compressed JSONL files as a source.  Named files should
be the only parameter. If reading uncompressed JSONL from STDIN, provide no
argument.

## Examples

Decompressing the JSONL file so that csvtool reads from stdin:

```bash
zstd -cd 2019/04/01/ndt-jdczh_1553815964_00000000000003E8.00184.jsonl.zst | ./csvtool > connection.csv
```

Directly read compressed format:

```bash
./csvtool 2019/04/01/ndt-jdczh_1553815964_00000000000003E8.00184.jsonl.zst > connection.csv
```
