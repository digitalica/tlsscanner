### TLS scanner

Proof of Concept to show logging of TLS handshake (and version) is possible. 

This we can log the *actual usage* of old TLS protocols

We use tcpdump, and pipe the output through a PHP (sorry, its just a POC) filter

All based on protocol info from: https://tls.ulfheim.net/
