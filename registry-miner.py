#!/usr/bin/env python3
# coding: utf-8

from yarp import *
from struct import unpack
from datetime import datetime, timedelta
import re
import uuid
import sys
import os.path
import csv

PROGRAM_VERSION = '20180410'
TIMESTAMP_END_DELTA_IN_DAYS = 14 # Extract "future" timestamps within the following number of days from the most recent "last written" timestamp or the current timestamp.

def DecodeTimestampCmdLine(timestamp_str):
	match_obj = re.match('^(\\d{4})(\\d{2})(\\d{2})$', timestamp_str)
	if match_obj:
		year = int(match_obj.group(1))
		month = int(match_obj.group(2))
		day = int(match_obj.group(3))

		try:
			ts = datetime(year, month, day)
		except (ValueError, OverflowError):
			pass
		else:
			return ts

	sys.exit('An invalid starting timestamp was specified! The format is "YYYYMMDD".')

def BuildContext(value_data, ts_pos, ts_len):
	if ts_pos - 16 <= 0:
		ctx_start = 0
	else:
		ctx_start = ts_pos - 16

	ctx_end = ts_pos + ts_len + 16

	ctx_bytes_dump = str(value_data[ ctx_start : ctx_end ])
	ctx = '{} (ts_pos={}, ts_len={}, ctx_start={})'.format(ctx_bytes_dump, ts_pos, ts_len, ctx_start)

	return ctx

class TimestampDecoder(object):
	"""This class implements static methods to parse different timestamp types.
	The following timestamp formats are supported:
	 - FILETIME (8 bytes in the binary form),
	 - UNIXTIME (4 or 8 bytes in the binary form),
	 - SYSTEMTIME (16 bytes in the binary form),
	 - ISOTIME (a variable length string),
	 - GUIDTIME (within a GUID, a variable length string).
	"""

	@staticmethod
	def extract_int_from_str(s):
		match_obj = re.search('(\d{8,})', s)
		if match_obj:
			return int(match_obj.group(1))

	@staticmethod
	def is_guid_string(guid_string):
		try:
			guid = uuid.UUID(guid_string)
		except ValueError:
			return False

		return True

	@staticmethod
	def decode_guidtime_string(guid_string):
		try:
			guid = uuid.UUID(guid_string)
		except ValueError:
			return

		if guid.version != 1:
			return

		try:
			timestamp = datetime(1582, 10, 15) + timedelta(microseconds = guid.time / 10)
		except (ValueError, OverflowError):
			return

		return timestamp

	@staticmethod
	def decode_filetime_binary(timestamp_binary):
		if len(timestamp_binary) < 8:
			return

		timestamp_integer, = unpack('<Q', timestamp_binary[ : 8])
		timestamp = TimestampDecoder.decode_filetime_integer(timestamp_integer)

		return timestamp

	@staticmethod
	def decode_filetime_string(timestamp_string):
		try:
			timestamp_integer = int(timestamp_string)
		except ValueError:
			i = TimestampDecoder.extract_int_from_str(timestamp_string)
			if i:
				timestamp = TimestampDecoder.decode_filetime_integer(i)
				return timestamp

			return

		timestamp = TimestampDecoder.decode_filetime_integer(timestamp_integer)

		return timestamp

	@staticmethod
	def decode_filetime_integer(timestamp_integer):
		try:
			timestamp = datetime(1601, 1, 1) + timedelta(microseconds = timestamp_integer / 10)
		except (ValueError, OverflowError):
			return

		return timestamp

	@staticmethod
	def decode_unixtime32_binary(timestamp_binary):
		if len(timestamp_binary) < 4:
			return

		timestamp_integer, = unpack('<l', timestamp_binary[ : 4])
		timestamp = TimestampDecoder.decode_unixtime_integer(timestamp_integer)

		return timestamp

	@staticmethod
	def decode_unixtime64_binary(timestamp_binary):
		if len(timestamp_binary) < 8:
			return

		timestamp_integer, = unpack('<q', timestamp_binary[ : 8])
		timestamp = TimestampDecoder.decode_unixtime_integer(timestamp_integer)

		return timestamp

	@staticmethod
	def decode_unixtime_string(timestamp_string):
		try:
			timestamp_integer = int(timestamp_string)
		except ValueError:
			i = TimestampDecoder.extract_int_from_str(timestamp_string)
			if i:
				timestamp = TimestampDecoder.decode_unixtime_integer(i)
				return timestamp

			return

		timestamp = TimestampDecoder.decode_unixtime_integer(timestamp_integer)

		return timestamp

	@staticmethod
	def decode_unixtime_integer(timestamp_integer):
		try:
			timestamp = datetime(1970, 1, 1) + timedelta(seconds = timestamp_integer)
		except (ValueError, OverflowError):
			return

		return timestamp

	@staticmethod
	def decode_systemtime_binary(timestamp_binary):
		if len(timestamp_binary) < 16:
			return

		year, month, _, day, hour, minute, second, _ = unpack('<HHHHHHHH', timestamp_binary[ : 16])
		try:
			timestamp = datetime(year, month, day, hour, minute, second)
		except (ValueError, OverflowError):
			return

		return timestamp

	@staticmethod
	def decode_isotimestamp_string(timestamp_string):
		regexps_datetime = [ '(\\d{4})\\D(\\d{2})\\D(\\d{2})\\D(\\d{2})\\D(\\d{2})\\D(\\d{2})' ]
		regexps_date = [ '(\\d{4})(\\d{2})(\\d{2})', '(\\d{4})\\D(\\d{2})\\D(\\d{2})' ]

		for regexp in regexps_datetime:
			match_obj = re.search(regexp, timestamp_string)
			if match_obj:
				year = int(match_obj.group(1))
				month = int(match_obj.group(2))
				day = int(match_obj.group(3))
				hour = int(match_obj.group(4))
				minute = int(match_obj.group(5))
				second = int(match_obj.group(6))

				try:
					timestamp = datetime(year, month, day, hour, minute, second)
				except (ValueError, OverflowError):
					pass
				else:
					return timestamp

		for regexp in regexps_date:
			match_obj = re.search(regexp, timestamp_string)
			if match_obj:
				year = int(match_obj.group(1))
				month = int(match_obj.group(2))
				day = int(match_obj.group(3))

				try:
					timestamp = datetime(year, month, day)
				except (ValueError, OverflowError):
					pass
				else:
					return timestamp

	@staticmethod
	def process_key_or_value_name(key_or_value, timestamp_start, timestamp_end):
		"""This static method is used to extract a timestamp (within a given time period) from a key name or a value name.
		The following tuple is returned (or None, if no timestamp was found): (datetime_object, timestamp_format, timestamp_type, confidence).
		The 'datetime_object' is a datetime object (naive).
		The 'timestamp_format' is a string (for example: 'FILETIME', a list of supported formats is given in the docstring for this class).
		The 'timestamp_type' is a string: 'key_name_str' (for a key name) or 'value_name_str' (for a value name).
		The 'confidence' is an integer (1..2). The lowest value means "likely a false positive".
		"""

		name = key_or_value.name()
		if len(name) == 0:
			return

		confidence = 2 # The default confidence value.

		if type(key_or_value) is Registry.RegistryKey:
			timestamp_type = 'key_name_str'
		else:
			timestamp_type = 'value_name_str'

		timestamp = TimestampDecoder.decode_guidtime_string(name)
		if timestamp is not None and timestamp >= timestamp_start and timestamp <= timestamp_end:
			return (timestamp, 'GUIDTIME', timestamp_type, confidence)

		timestamp = TimestampDecoder.decode_filetime_string(name)
		if timestamp is not None and timestamp >= timestamp_start and timestamp <= timestamp_end:
			return (timestamp, 'FILETIME', timestamp_type, confidence)

		timestamp = TimestampDecoder.decode_unixtime_string(name)
		if timestamp is not None and timestamp >= timestamp_start and timestamp <= timestamp_end:
			if TimestampDecoder.is_guid_string(name): # This is likely a GUID.
				confidence = 1

			return (timestamp, 'UNIXTIME', timestamp_type, confidence)

		timestamp = TimestampDecoder.decode_isotimestamp_string(name)
		if timestamp is not None and timestamp >= timestamp_start and timestamp <= timestamp_end:
			return (timestamp, 'ISOTIME', timestamp_type, confidence)

	@staticmethod
	def process_value_data(value, timestamp_start, timestamp_end):
		"""This static method is used to extract a timestamp (within a given time period) from value data.
		The following tuple is returned (or None, if no timestamp was found): (datetime_object, timestamp_format, timestamp_type, confidence, context).
		The 'datetime_object' is a datetime object (naive).
		The 'timestamp_format' is a string (for example: 'FILETIME', a list of supported formats is given in the docstring for this class).
		The 'timestamp_type' is a string:
		 - 'value_data_int' for a timestamp stored as an integer,
		 - 'value_data_str' for a timestamp stored as a string (or a substring),
		 - 'value_data_str_list' for a timestamp stored as a string (or a substring) within a list of strings,
		 - 'value_data_bin' for a timestamp stored as binary data,
		 - 'value_data_str_bin' for a timestamp stored as an encoded string (substring) in binary data.
		The 'confidence' is an integer (1..2). The lowest value means "likely a false positive".
		The 'context' contains context bytes as a human-readable string or None.
		"""

		data = value.data()

		confidence = 2 # The default confidence value.
		context = None

		if type(data) is int:
			timestamp = TimestampDecoder.decode_filetime_integer(data)
			if timestamp is not None and timestamp >= timestamp_start and timestamp <= timestamp_end:
				return (timestamp, 'FILETIME', 'value_data_int', confidence, context)

			timestamp = TimestampDecoder.decode_unixtime_integer(data)
			if timestamp is not None and timestamp >= timestamp_start and timestamp <= timestamp_end:
				return (timestamp, 'UNIXTIME', 'value_data_int', confidence, context)

		elif type(data) is str:
			data = data.rstrip('\x00')

			timestamp = TimestampDecoder.decode_guidtime_string(data)
			if timestamp is not None and timestamp >= timestamp_start and timestamp <= timestamp_end:
				return (timestamp, 'GUIDTIME', 'value_data_str', confidence, context)

			timestamp = TimestampDecoder.decode_filetime_string(data)
			if timestamp is not None and timestamp >= timestamp_start and timestamp <= timestamp_end:
				return (timestamp, 'FILETIME', 'value_data_str', confidence, context)

			timestamp = TimestampDecoder.decode_unixtime_string(data)
			if timestamp is not None and timestamp >= timestamp_start and timestamp <= timestamp_end:
				if TimestampDecoder.is_guid_string(data): # This is likely a GUID.
					confidence = 1

				return (timestamp, 'UNIXTIME', 'value_data_str', confidence, context)

			timestamp = TimestampDecoder.decode_isotimestamp_string(data)
			if timestamp is not None and timestamp >= timestamp_start and timestamp <= timestamp_end:
				return (timestamp, 'ISOTIME', 'value_data_str', confidence, context)

		elif type(data) is list:
			for list_item in data:
				list_item = list_item.rstrip('\x00')

				timestamp = TimestampDecoder.decode_guidtime_string(list_item)
				if timestamp is not None and timestamp >= timestamp_start and timestamp <= timestamp_end:
					return (timestamp, 'GUIDTIME', 'value_data_str_list', confidence, context)

				timestamp = TimestampDecoder.decode_filetime_string(list_item)
				if timestamp is not None and timestamp >= timestamp_start and timestamp <= timestamp_end:
					return (timestamp, 'FILETIME', 'value_data_str_list', confidence, context)

				timestamp = TimestampDecoder.decode_unixtime_string(list_item)
				if timestamp is not None and timestamp >= timestamp_start and timestamp <= timestamp_end:
					if TimestampDecoder.is_guid_string(list_item): # This is likely a GUID.
						confidence = 1

					return (timestamp, 'UNIXTIME', 'value_data_str_list', confidence, context)

				timestamp = TimestampDecoder.decode_isotimestamp_string(list_item)
				if timestamp is not None and timestamp >= timestamp_start and timestamp <= timestamp_end:
					return (timestamp, 'ISOTIME', 'value_data_str_list', confidence, context)

		elif type(data) is bytes:
			pos = 0
			while pos < len(data):
				buf = data[ pos : ]

				timestamp = TimestampDecoder.decode_filetime_binary(buf)
				if timestamp is not None and timestamp >= timestamp_start and timestamp <= timestamp_end:
					if buf[ : 8].count(b'\x00') > 4: # Too many null bytes.
						confidence = 1

					context = BuildContext(data, pos, 8)
					return (timestamp, 'FILETIME', 'value_data_bin', confidence, context)

				timestamp = TimestampDecoder.decode_unixtime64_binary(buf)
				if timestamp is not None and timestamp >= timestamp_start and timestamp <= timestamp_end:
					if buf[ : 8].count(b'\x00') > 4: # Too many null bytes.
						confidence = 1

					context = BuildContext(data, pos, 8)
					return (timestamp, 'UNIXTIME', 'value_data_bin', confidence, context)

				timestamp = TimestampDecoder.decode_unixtime32_binary(buf)
				if timestamp is not None and timestamp >= timestamp_start and timestamp <= timestamp_end:
					if pos != 0 and pos + 4 != len(data): # This is an unusual offset, likely a false positive.
						confidence = 1

					context = BuildContext(data, pos, 4)
					return (timestamp, 'UNIXTIME', 'value_data_bin', confidence, context)

				timestamp = TimestampDecoder.decode_systemtime_binary(buf)
				if timestamp is not None and timestamp >= timestamp_start and timestamp <= timestamp_end:
					context = BuildContext(data, pos, 16)
					return (timestamp, 'SYSTEMTIME', 'value_data_bin', confidence, context)

				pos += 1

			try:
				buf_str = data.decode('utf-8', errors = 'replace').rstrip('\x00')
			except UnicodeDecodeError:
				pass
			else:
				timestamp = TimestampDecoder.decode_guidtime_string(buf_str)
				if timestamp is not None and timestamp >= timestamp_start and timestamp <= timestamp_end:
					return (timestamp, 'GUIDTIME', 'value_data_str_bin', confidence, context)

				timestamp = TimestampDecoder.decode_filetime_string(buf_str)
				if timestamp is not None and timestamp >= timestamp_start and timestamp <= timestamp_end:
					return (timestamp, 'FILETIME', 'value_data_str_bin', confidence, context)

				timestamp = TimestampDecoder.decode_unixtime_string(buf_str)
				if timestamp is not None and timestamp >= timestamp_start and timestamp <= timestamp_end:
					if TimestampDecoder.is_guid_string(buf_str): # This is likely a GUID.
						confidence = 1

					return (timestamp, 'UNIXTIME', 'value_data_str_bin', confidence, context)

				timestamp = TimestampDecoder.decode_isotimestamp_string(buf_str)
				if timestamp is not None and timestamp >= timestamp_start and timestamp <= timestamp_end:
					return (timestamp, 'ISOTIME', 'value_data_str_bin', confidence, context)

			try:
				buf_str = data.decode('utf-16le', errors = 'replace').rstrip('\x00')
			except UnicodeDecodeError:
				pass
			else:
				timestamp = TimestampDecoder.decode_guidtime_string(buf_str)
				if timestamp is not None and timestamp >= timestamp_start and timestamp <= timestamp_end:
					return (timestamp, 'GUIDTIME', 'value_data_str_bin', confidence, context)

				timestamp = TimestampDecoder.decode_filetime_string(buf_str)
				if timestamp is not None and timestamp >= timestamp_start and timestamp <= timestamp_end:
					return (timestamp, 'FILETIME', 'value_data_str_bin', confidence, context)

				timestamp = TimestampDecoder.decode_unixtime_string(buf_str)
				if timestamp is not None and timestamp >= timestamp_start and timestamp <= timestamp_end:
					if TimestampDecoder.is_guid_string(buf_str): # This is likely a GUID.
						confidence = 1

					return (timestamp, 'UNIXTIME', 'value_data_str_bin', confidence, context)

				timestamp = TimestampDecoder.decode_isotimestamp_string(buf_str)
				if timestamp is not None and timestamp >= timestamp_start and timestamp <= timestamp_end:
					return (timestamp, 'ISOTIME', 'value_data_str_bin', confidence, context)

class RegistryMiner(object):
	def __init__(self, primary_path):
		self.primary_file = open(primary_path, 'rb')

		transaction_logs = RegistryHelpers.DiscoverLogFiles(primary_path)

		if transaction_logs.log_path is not None:
			self.log_file = open(transaction_logs.log_path, 'rb')
		else:
			self.log_file = None

		if transaction_logs.log1_path is not None:
			self.log1_file = open(transaction_logs.log1_path, 'rb')
		else:
			self.log1_file = None

		if transaction_logs.log2_path is not None:
			self.log2_file = open(transaction_logs.log2_path, 'rb')
		else:
			self.log2_file = None

		self.hive = Registry.RegistryHive(self.primary_file)
		try:
			self.hive.recover_auto(self.log_file, self.log1_file, self.log2_file)
		except Registry.AutoRecoveryException:
			pass

		self.hive.walk_everywhere()

	def __enter__(self):
		return self

	def __exit__(self, *args):
		self.close()

	def close(self):
		self.hive = None

		self.primary_file.close()

		if self.log_file is not None:
			self.log_file.close()

		if self.log1_file is not None:
			self.log1_file.close()

		if self.log2_file is not None:
			self.log2_file.close()

	def scan(self):
		def process_key(key):
			yield (key, None)

			for value in key.values():
				yield (key, value)

			for subkey in key.subkeys():
				for r in process_key(subkey):
					yield r

		for r in process_key(self.hive.root_key()):
			yield r

	def latest_timestamp(self):
		latest_timestamp = self.hive.last_written_timestamp()

		def process_key(key):
			yield key

			for subkey in key.subkeys():
				for r in process_key(subkey):
					yield r

		for key in process_key(self.hive.root_key()):
			if key.last_written_timestamp() > latest_timestamp:
				latest_timestamp = key.last_written_timestamp()

		return latest_timestamp

if len(sys.argv) == 4:
	timestamp_start = DecodeTimestampCmdLine(sys.argv[1])
	file_path = sys.argv[2]
	file_out = sys.argv[3]
else:
	sys.exit('Registry Miner, version: {}'.format(PROGRAM_VERSION) + os.linesep + 'Usage: registry-miner.py <starting timestamp (YYYYMMDD)> <registry file> <output file (CSV)>')

if not os.path.isfile(file_path):
	sys.exit('Not a file: \'{}\''.format(file_path))

with RegistryMiner(file_path) as miner:
	latest_timestamp = miner.latest_timestamp()

	near_future = datetime.utcnow() + timedelta(days = 2)
	if latest_timestamp > near_future: # Something is wrong with timestamps in the hive, use the current timestamp as the latest one.
		latest_timestamp = datetime.utcnow()

	timestamp_end = latest_timestamp + timedelta(days = TIMESTAMP_END_DELTA_IN_DAYS)
	if timestamp_start > timestamp_end: # Something is wrong with the starting timestamp specified, trust the user and move the ending timestamp to the future.
		timestamp_end = timestamp_start + timedelta(days = TIMESTAMP_END_DELTA_IN_DAYS)

	f = open(file_out, 'w', newline = '')
	csv_file = csv.writer(f)
	csv_file.writerow(['Registry file', 'Key', 'Value', 'Timestamp', 'Timestamp format', 'Timestamp type', 'Confidence', 'Context'])

	for key, value in miner.scan():
		if value is None:
			timestamp = TimestampDecoder.process_key_or_value_name(key, timestamp_start, timestamp_end)
			if timestamp is not None:
				csv_file.writerow([file_path, key.path(), '', timestamp[0], timestamp[1], timestamp[2], timestamp[3], ''])
		else:
			value_name = value.name()
			if value_name == '':
				value_field = 'default value'
			else:
				value_field = 'value: {}'.format(value_name)

			timestamp = TimestampDecoder.process_key_or_value_name(value, timestamp_start, timestamp_end)
			if timestamp is not None:
				csv_file.writerow([file_path, key.path(), value_field, timestamp[0], timestamp[1], timestamp[2], timestamp[3], ''])

			timestamp = TimestampDecoder.process_value_data(value, timestamp_start, timestamp_end)
			if timestamp is not None:
				csv_file.writerow([file_path, key.path(), value_field, timestamp[0], timestamp[1], timestamp[2], timestamp[3], timestamp[4]])

	f.close()
