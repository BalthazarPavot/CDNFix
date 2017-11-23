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

For educational purpose. That's all.

"Gneu gneu gneu... thats not educational, that's just dangerous!"

Yes it is, grumpy human. It is, for me.
I did this script for me to learn how ARP, DNS, packets, routers,...
worked on a LAN (and that's the reason why I did not use scapy to
craft packets and I used raw sockets). Anybody can code this kind
of script, so no, it's not dangerous to put it on the internet.

I think that also answers the question "why is it inefficienct?": It
was just a toy and my LAN (2 computers lol) was my playground.


And after?
----------

I'll use this script for myself on my LAN. I'll ellaborate it, fix the
bugs, and that's all. I'll perhaps use my
[pydget](https://github.com/BalthazarPavot/pydget) library to build a
GUI, one day...


