
<?php

#
# https://tls.ulfheim.net/
#

$stdin = fopen('php://stdin', 'r');

$linenr = 0;


function getVersion($b1, $b2) {
	if ($b1 == '02') {
		return 'SSL';
	}
	if ($b1 == '03' and $b2 > '03') {
		return 'TLS1.3ormore';
	}
	if ($b1 == '03' and $b2 == '03') {
		return 'TLS1.2';
	}
	if ($b1 == '03' and $b2 == '02') {
		return 'TLS1.1';
	}
	if ($b1 == '03' and $b2 == '01') {
		return 'TLS1.0';
	}
	
	return $b1 . '-' . $b2;
	
}

function createFormattedTlsLogline($line0, $line1, $line2, $line3, $line4) {
  $sep = ' ';
  preg_match('/([^ ]*) IP ([^ ]*) > ([^ ]*): Flags/', $line0, $line0matches);
  preg_match('/0x0000:  (..)(..) (..)(..) (..)(..) (..)(..) (..)(..) (..)(..) (..)(..) (..)(..)/', $line1, $line1matches);
  preg_match('/0x0010:  (..)(..) (..)(..) (..)(..) (..)(..) (..)(..) (..)(..) (..)(..) (..)(..)/', $line2, $line2matches);
  preg_match('/0x0020:  (..)(..) (..)(..) (..)(..) (..)(..) (..)(..) (..)(..) (..)(..) (..)(..)/', $line3, $line3matches);
  preg_match('/0x0030:  (..)(..) (..)(..) (..)(..) (..)(..) (..)(..) (..)(..) (..)(..) (..)(..)/', $line4, $line4matches);
  $time = $line0matches[1];
  $fromipport = explode('.', $line0matches[2]);
  $toipport = explode('.', $line0matches[3]);
  $fromip = implode('.', array_slice($fromipport, 0,4));
  $fromport = $fromipport[4];
  $toip = implode('.', array_slice($toipport, 0,4));
  $toport = $toipport[4];
  $bytes = array_merge(array_slice($line1matches,1 ), array_slice($line2matches, 1), array_slice($line3matches, 1), array_slice($line4matches, 1));
  
  $offset = ($bytes[0] & 0xf) * 4;
  
  $bytes = array_slice($bytes, $offset);
  
  if ($bytes[0] != '16') {
	# print $time . $sep . "NOTTLS" . "-" . $offset . "-" . $bytes[0] . "\n";
	return; // not a TLS handschake packet
  }
  $show = true;
  $type = 'Unknown';
  $version = 'Unknown';
  switch ($bytes[5]) { // first byte of handshake header
	case '01':
	  $type = 'ClientHello';
	  $version = getVersion($bytes[1], $bytes[2]);
	  break;
	case '02': 
	  $type = 'ServerHello';
	  $version = getVersion($bytes[1], $bytes[2]);
	  break;
	case '0b': 
	  $type = 'ServerCertificate';
	  $version = getVersion($bytes[1], $bytes[2]);
	  break;
	case '0c': 
	case '0C': 
	  $type = 'ServerKeyExchange';
	  $version = getVersion($bytes[1], $bytes[2]);
	  break;
	case '0e': 
	case '0E': 
	  $type = 'ServerHelloDone';
	  $version = getVersion($bytes[1], $bytes[2]);
	  break;
	case '10': 
	  $type = 'ClientKeyExchange';
	  $version = getVersion($bytes[1], $bytes[2]);
	  break;
	case '10': 
	  $type = 'ClientKeyExchange';
	  $version = getVersion($bytes[1], $bytes[2]);
	  break;
	default:
	  $show = false; // unknown type, so most probably just matching encrypted packet
	  break;
  }  
  if ($show) {
    $logline = $time . $sep . $fromip . $sep . $fromport . $sep . $toip. $sep . $toport . $sep . $type . $sep . $version . "\n";
    print $logline;
  }
}


while (true) {
  $line = fgets($stdin);
  if (preg_match('/^\d\d:\d\d:\d\d\.\d\d/', $line)) {
	$linenr = 0;
	$line0 = $line;
  } else {
	$linenr++;
	switch ($linenr) {
	  case 1:
	    $line1 = $line;
	    break;
	  case 2:
	    $line2 = $line;
	    break;
	  case 3:
	    $line3 = $line;
	    break;
	  case 4:
	    $line4 = $line;
	    createFormattedTlsLogline($line0, $line1, $line2, $line3, $line4);
	    break;
	}
  }
#  if ($linenr<3) {
#	print ($line);
#  }
}

?>
