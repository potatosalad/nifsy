# Nifsy

A nifty Elixir NIF for the FS.

## Benchmarking

You can use `mix run bench/<file>` to run a benchmark.

For read_line, `mix run bench/read_line_bench.exs`:

| name                | total      | usec/iter    | usec/line |
| ------------------- | ---------- | ------------ | --------- |
| 1 KB (16 B) - nifsy | 3061       | 61.22        | 1.36      |
| 1 KB (16 B) - file  | 7917       | 158.34       | 3.519     |
| 1 KB (1 KB) - nifsy | 996        | 19.92        | 0.443     |
| 1 KB (1 KB) - file  | 6626       | 132.52       | 2.945     |
| 1 KB (64KB) - nifsy | 854        | 17.08        | 0.38      |
| 1 KB (64KB) - file  | 6950       | 139.0        | 3.089     |
| 1 MB (1 KB) - nifsy | 87221      | 1744.42      | 1.205     |
| 1 MB (1 KB) - file  | 1730385    | 34607.7      | 23.9      |
| 1 MB (64KB) - nifsy | 33075      | 661.5        | 0.457     |
| 1 MB (64KB) - file  | 145792     | 2915.84      | 2.014     |
| 1 MB (1 MB) - nifsy | 70736      | 1414.72      | 0.977     |
| 1 MB (1 MB) - file  | 138290     | 2765.8       | 1.91      |
| 1 GB (1 KB) - nifsy | 11310163   | 1131016.3    | 24.406    |
| 1 GB (1 KB) - file  | 13666416   | 1366641.6    | 29.491    |
| 1 GB (64KB) - nifsy | 3488617    | 348861.7     | 7.528     |
| 1 GB (64KB) - file  | 8099967    | 809996.7     | 17.479    |
| 1 GB (1 MB) - nifsy | 3667947    | 366794.7     | 7.915     |
| 1 GB (1 MB) - file  | 4649991    | 464999.1     | 10.034    |
| 1 GB (1 GB) - nifsy | 35080356   | 3508035.6    | 75.7      |
| 1 GB (1 GB) - file  | 25042723   | 2504272.3    | 54.04     |
