#!/usr/bin/env python3
# -*- coding: utf-8 -*-


import logging
import os


RED, GREEN, ORANGE, BLUE, PURPLE, LBLUE, GREY = \
  map("\33[%dm".__mod__, range(31, 38))
DNS_COLOR = GREY
ARP_COLOR = PURPLE
NO_COLOR = "\33[m"


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

def color_logger(logger, overall_color=None):
  if overall_color is None:
    colors = GREY, GREEN, ORANGE, RED, BLUE
  else:
    colors = (overall_color, ) * 5
  for level, color in zip((
    "debug", "info", "warn", "error", "critical"), colors
  ):
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


if __name__ == "__main__":


  if os.getuid() != 0:
    print("You need to be root to run this program.")
    exit()
  # we lower privelege everywhere.
  # we will upper privilege only when needed.
  lower_privilege()

  logging.basicConfig(format="[%(levelname)-5s] %(message)s", level=logging.DEBUG)
  logger = logging.getLogger(os.path.basename(__file__))
  color_logger(logger)
  logger.critical = attach_critical_callback(logger.critical)
  dns_logger = logging.getLogger("DNS")
  arp_logger = logging.getLogger("ARP")
  dns_logger.propagate = False
  arp_logger.propagate = False
  dns_sh = logging.StreamHandler()
  dns_sh.setFormatter(logging.Formatter(
    DNS_COLOR+"[DNS-%(levelname)-5s] %(message)s"+NO_COLOR
  ))
  dns_logger.addHandler(dns_sh)
  arp_sh = logging.StreamHandler()
  arp_sh.setFormatter(logging.Formatter(
    ARP_COLOR+"[ARP-%(levelname)-5s] %(message)s"+NO_COLOR
  ))
  arp_logger.addHandler(arp_sh)
  color_logger(dns_logger, overall_color=DNS_COLOR)
  color_logger(arp_logger, overall_color=ARP_COLOR)


  logger.info("PID=%d." %os.getpid())