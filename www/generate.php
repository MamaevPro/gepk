<?
$cmd=$_POST['cmd'];
$par=$_POST['par'];

$rez="profileid:".$_POST['profile_id']."\n";
$rez.="profilename:".$_POST['profile_name']."\n";
$rez.="host:".$_POST['host']."\n";
for($i=0;$i<count($cmd);$i++){
	switch($cmd[$i]):
		case "1": $rez.="tcp:".$par[$i]."\n"; break;
		case "2": $rez.="upd:".$par[$i]."\n"; break;
		case "3": $rez.="ping:".$par[$i]."\n"; break;
		case "4": $rez.="sleep:".$par[$i]."\n"; break;
		case "5": $rez.="mstsc:".$par[$i]."\n"; break;
	endswitch;	
}

$cipher = "aes-256-cbc";
$ivlen = openssl_cipher_iv_length($cipher);
$iv = openssl_random_pseudo_bytes(16);
#$key = openssl_random_pseudo_bytes(32);
$key="b85Axk4PYXoYcAwkpTBI6mr7mYDIKG6Q";

$ciphertext_raw = openssl_encrypt($rez, $cipher, $key, $options=OPENSSL_RAW_DATA, $iv);
$hmac = hash_hmac('sha256', $ciphertext_raw, $key, $as_binary=true);
$ciphertext = base64_encode( $iv.$hmac.$ciphertext_raw);


echo wordwrap($ciphertext,64,"\n",true);
?>