# Registry Miner

## Description

This program scans a given registry file (primary) and extracts everything that looks like a timestamp.

`Usage: registry-miner.py <starting timestamp (YYYYMMDD)> <registry file> <output file (CSV)>`

The following timestamp formats are supported:
* FILETIME,
* UNIXTIME,
* SYSTEMTIME,
* ISOTIME (string),
* GUIDTIME (string).

The following timestamp types (locations) are supported:
* key names (timestamps stored as strings/substrings),
* value names (timestamps stored as strings/substrings),
* value data (timestamps stored as strings/substrings/lists/integers or raw bytes).

The following columns are written to the CSV file:
* Registry file: path to the registry file (primary),
* Key: path to the key,
* Value: name of the value (if the timestamp is stored in the value),
* Timestamp: timestamp (naive, no time zone),
* Timestamp format: one of the formats defined above (example: `FILETIME`),
* Timestamp type: timestamp type or location (example: `value_data_bin` for a timestamp found in value data of binary type),
* Confidence: `1` or `2` (`1` means "likely a false positive", `2` means "likely a valid timestamp"),
* Context: human-readable context, for binary timestamps only (example: `b'\x01\x00\x04\x80X\x00\x00\x00h\x00\x00\x00\x00\x00\x00\x00\x14\x00\x00\x00\x02' (ts_pos=1, ts_len=4, ctx_start=0)`, `ts_pos` and `ts_len` refer to the position and length of the timestamp found, `ctx_start` refers to the starting offset of context bytes).

## Dependencies

* yarp: https://github.com/msuhanov/yarp

## License

This program is made available under the terms of the GNU GPL, version 3.
See the 'License' file.

---
(c) Maxim Suhanov
