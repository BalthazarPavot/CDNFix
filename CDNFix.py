#!/usr/bin/env python3
# -*- coding: utf-8 -*-


import os


def elevate_privilege():
  os.seteuid(0)

def lower_privilege():
  os.seteuid(65534)


if __name__ == "__main__":


  if os.getuid() != 0:
    print("You need to be root to run this program.")
    exit()
  # we lower privelege everywhere.
  # we will upper privilege only when needed.
  lower_privilege()