#!/usr/bin/env python3
# -*- coding: utf-8 -*-


import atexit
import logging
import optparse
import os
import re
import sys
import time


RED, GREEN, ORANGE, BLUE, PURPLE, LBLUE, GREY = \
  map("\33[%dm".__mod__, range(31, 38))
DNS_COLOR = GREY
ARP_COLOR = PURPLE
NO_COLOR = "\33[m"


class Packet(object):

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
  third layer of the OSI model.
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


class Context(object):

  def __init__(
    self, device, router_ip, hosts, options
  ):
    self.device = device
    self.router_ip = router_ip
    self.hosts = hosts
    self.options = options
    self.arp_table = {}
    self.dns_spoofer = None
    self.arp_poisoner = None
    self.check_mandatory()
    self.gather_informations()
    if not self.options.dns_ip:
      self.options.dns_ip = self.ip
    #self.chech_everything()
    self.check_options()

  def gather_informations(self):
    logger.info("Detecting our IP and MAC address...")
    self.ip = self.detect_self_ip()
    self.mac = self.detect_self_mac()
    if self.ip:
      if self.mac:
        logger.info("IP=%s ; MAC=%s" % (self.ip, self.mac))
      else:
        logger.critical("Could not detect our own IP.")
    else:
      logger.critical("Could not detect our own IP.")
    self.gather_router_mac()
    if self.know_router_mac():
      logger.info("Router MAC detected: %s." % self.get_router_mac())
    else:
      logger.info("Could not find router MAC. Trying later with ARP.")

  def know_router_mac(self):
    return self.router_ip in self.arp_table

  def get_router_mac(self):
    return self.arp_table.get(self.router_ip, [None])[0]

  def gather_router_mac(self):
    cmd = " | ".join((
      "arp -n %(router_ip)s 2> /dev/null",  # show arp table
      "grep -Po '\S+\s+\S+\s+%(device)s'",  # filter on device
      "cut -d' ' -f1"                       # get first part
    )) % {
      "router_ip": self.router_ip,
      "device": self.device,
    }
    mac = os.popen(cmd).read().strip()
    if mac:
      self.update_router_mac(mac)
    return self.get_router_mac()

  def update_router_mac(self, mac):
    self.arp_table[self.router_ip] = (mac, time.time())

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

  def get_possible_devices(self):
    return os.popen(" | ".join((
      "ip link show",               # show interfaces
      "grep -oP '\d+:\s+([^:]+)'",  # select 'number: intf'
      "cut -d' ' -f2"               # split and get just 'intf'
    ))).read().strip().split("\n")  # split on \n, ignoring trailing

  def chech_everything(self):
    self.check_mandatory()
    self.check_options()

  def check_mandatory(self):
    self.check_device()
    self.check_router_ip()
    self.check_hosts()

  def check_options(self):
    self.check_pid_path()
    self.check_arp_options()
    self.check_dns_options()

  def check_arp_options(self):
    if not self.options.no_arp:
      if self.options.arp_elapse_time <= 0:
        logger.critical("Bad elapsed time.")

  def check_dns_options(self):
    self.check_dns_ip()

  def check_device(self):
    if self.device not in self.get_possible_devices():
      logger.critical(
        "Bad device name: %s. Expencted one of those: %s" % (
          self.device, ", ".join(self.get_possible_devices())
        )
      )
    logger.debug("Device:    %-16s   [OK]" % self.device)
    if not self.detect_self_ip():
      logger.critical(
        "You're not connected to any network with this device"
      )
    if not self.detect_self_mac():
      logger.critical(
        "Could not get the mac adress associated to your device"
      )

  def check_router_ip(self):
    if not match_ipv4(self.router_ip):
      logger.critical("Bad router IP adress.")
    logger.debug("Router IP: %-16s   [OK]" % self.router_ip)

  def check_hosts(self):
    if not os.path.exists(self.hosts):
      logger.critical("%s does not exists." % self.hosts)
    elif not os.path.getsize(self.hosts):
      logger.critical("Empty host file")
    logger.debug("Hosts:     %-16s   [OK]" % self.hosts[-17:])

  def check_pid_path(self):
    pass

  def check_dns_ip(self):
    if not match_ipv4(self.options.dns_ip):
      logger.error("Bad router IP adress.")


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
    colors = GREY, GREEN, ORANGE, RED, BLUE
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

def parse_arguments():
  parser = optparse.OptionParser(
    usage="%prog [OPTIONS] device router_ip hosts" \
    "hosts\nInvokes a great and awful firewall like the one in " \
    "China (no). Redirect users on your lan, using the given host " \
    "file.\nUses ARP poisoning and DNS spoofing."
  )
  prog = os.path.basename(sys.argv[0])
  parser.add_option(
    "-p",
    dest="pidfile",
    default="/tmp/%s.pid" % prog,
    help="The file path where to store our PID (Default=/tmp/%s.pid)."%prog,
    metavar="PID_FILE"
  )
  arp_group = optparse.OptionGroup(parser, "ARP Options")
  arp_group.add_option(
    "-A", 
    dest="no_arp",
    action="store_true",
    default=False,
    help="Deactivates the ARP poisoner (harmless ARP Server mode).",
  )
  arp_group.add_option(
    "-r", 
    dest="respond_only",
    action="store_true",
    default=True,
    help="Only send ARP responses when asked to by other devices.",
  )
  arp_group.add_option(
    "-t", 
    dest="arp_elapse_time",
    default=1,
    type="int",
    help="Time ellapsed between two ARP responses. Ignored if -r is set.",
    metavar="MILISECONDS"
  )
  parser.add_option_group(arp_group)
  dns_group = optparse.OptionGroup(parser, "DNS Options")
  dns_group.add_option(
    "-d",
    dest="dns_ip",
    default=None,
    help="The IP adress of the DNS.",
    metavar="DNS_IP"
  )
  parser.add_option_group(dns_group)
  options, arguments = parser.parse_args()
  if len(arguments) != 3:
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
    exit()
  # we lower privelege everywhere.
  # we will upper privilege only when needed.
  lower_privilege()

  logging.basicConfig(format="[%(levelname)-8s] %(message)s", level=logging.DEBUG)
  logger = logging.getLogger(os.path.basename(__file__))
  color_logger(logger)
  logger.critical = attach_critical_callback(logger.critical)
  dns_logger = logging.getLogger("DNS")
  arp_logger = logging.getLogger("ARP")
  dns_logger.propagate = False
  arp_logger.propagate = False
  dns_sh = logging.StreamHandler()
  dns_sh.setFormatter(logging.Formatter(
    DNS_COLOR+"[DNS-%(levelname)-8s] %(message)s"+NO_COLOR
  ))
  dns_logger.addHandler(dns_sh)
  arp_sh = logging.StreamHandler()
  arp_sh.setFormatter(logging.Formatter(
    ARP_COLOR+"[ARP-%(levelname)-8s] %(message)s"+NO_COLOR
  ))
  arp_logger.addHandler(arp_sh)
  color_logger(dns_logger, overall_color=DNS_COLOR)
  color_logger(arp_logger, overall_color=ARP_COLOR)

  logger.info("PID=%d." %os.getpid())

  context = parse_arguments()

  create_pid_file(context)
  atexit.register(remove_pid_file, context.options.pidfile)

  exit()