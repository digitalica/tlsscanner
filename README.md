### TLS scanner

Proof of Concept to show logging of TLS handshake (and version) is possible. 

We use tcpdump, and pipe the output to a PHP filter

All based on protocol info from: https://tls.ulfheim.net/
