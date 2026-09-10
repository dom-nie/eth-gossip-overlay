# ethtool fixtures

`ethtool -k` and `ethtool -l` output for the two kinds of card the steering plan branches on:
one that can steer a flow itself, and one that cannot.

**These were hand-written from the documented output format, not captured from a host.** They
are the right shape and the right field names, and the parser they drive is real, but nobody
has yet run `ethtool` on a ConnectX-5 or a virtio interface and pasted the answer here. Replace
both pairs with real captures the first time this runs on a Linux host with either card:

```
ethtool -k <iface> > <model>-features.txt
ethtool -l <iface> > <model>-channels.txt
```

Keep the trailing sections. The parser skips what it does not recognise, and a fixture that
only holds the two lines it reads would stop proving that.
