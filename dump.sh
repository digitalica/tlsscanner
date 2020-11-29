sudo tcpdump -nXi eno1 "tcp port 443 and (tcp[((tcp[12] & 0xf0) >> 2)] = 0x16)" | php tcpdump2tsllog.php

