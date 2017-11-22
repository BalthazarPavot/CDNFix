**CDNFix**.py
=========

What's that?
------------

An MITM tool. It launches two servers that intercept/craft ARP/DNS
requests. The `hosts` file describes which site points to which IP.


Why CDNFix?
-----------

Just because CDNs use their content to track your online activity.
Not to be tracked, you can use some web brower plugins like
[decentraleyes](https://github.com/Synzvato/decentraleyes).
But, if you want a network-scaled solution, plugins are not the
solution. This scipt may be the solution.

But no. This script is not a solution. And it's certainly not
efficient (slow and conspicuous).


So why this script?
-------------------

For educationnal purpose. That's all.
"Gneu gneu gneu... thats not educationnal, that's just dangerous!"
Yes it is, grumpy human. It is for me. I did this script for ME to
learn how ARP works, how DNS works, etc. So, anybody can code this
kind of script (and that's the reason why I did not use scapy to
craft packets and used raw sockets).

This answers the question of it's inefficiency: it was just a toy and
my LAN was my playground.


And after?
----------

I'll use this script for myself on my LAN. I'll ellaborate it, fux the
bugs, and that's all. I'll perhaps use my pydget library to build a
GUI, one day...


