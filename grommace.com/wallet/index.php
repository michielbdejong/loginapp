<?php
//create table wallets (email varchar(255), app varchar(255), md5_pass varchar(255), wallet text);
$dbHost = 'localhost';
$dbUser = 'root';
$dbPass = '';
$dbName = 'grommace';
$dbSock = null;

class Wallet {
	private $mysql = null;
	function connect() {
		if($this->mysql === null) {
			$this->mysql = mysqli_connect($GLOBALS['dbHost'], $GLOBALS['dbUser'], $GLOBALS['dbPass'], $GLOBALS['dbName']);
		}
	}
	function set($email, $app, $password, $wallet) {
		$this->connect();
		$queryStr = 'INSERT INTO `wallets` (`email`, `app`, `md5_pass`, `wallet`) VALUES ("'
			.$this->mysql->real_escape_string($email)
			.'", "'
			.$this->mysql->real_escape_string($app)
			.'", PASSWORD("'
			.$this->mysql->real_escape_string($password)
			.'"), "'
			.$this->mysql->real_escape_string($wallet)
			.'")';
		file_put_contents('/tmp/mich.log', "\nGrommace does:\n$queryStr\n", FILE_APPEND);
		$queryResult = $this->mysql->query($queryStr);
		if($queryResult==false) {
			return $this->mysql->error;
		}
		return 'OK';
	}
	function get($email, $app, $password) {
		$this->connect();
		$queryStr = 'SELECT wallet FROM `wallets` WHERE `email`="'
			.$this->mysql->real_escape_string($email)
			.'" AND `app` = "'
			.$this->mysql->real_escape_string($app)
			.'" AND `md5_pass` = PASSWORD("'
			.$this->mysql->real_escape_string($password)
			.'")';
		file_put_contents('/tmp/mich.log', "\nGrommace does:\n$queryStr\n", FILE_APPEND);
		$queryResult = $this->mysql->query($queryStr);
		if($queryResult==false) {
			return $this->mysql->error;
		}
		$row = $queryResult->fetch_row();
		return str_replace("\\\"", "\"", $row[0]);
	}
}
//MAIN:
header('Content-Type: text/html');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, POST, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type');
header('Access-Control-Max-Age: 86400');
if(isset($_POST['protocol']) && $_POST['protocol'] == 'KeyWallet/0.1' && isset($_POST['action'])) {
	$refererParts = explode('/', $_SERVER['HTTP_REFERER']);
	$app = $refererParts[2];
	switch($_POST['action']) {
	case 'GET':
		if(!isset($_POST['email'])) {
			die('please set an email in the post');
		}
		if(!isset($_POST['password'])) {
			die('please set a password in the post');
		}
		$wallet = new Wallet();
		die($wallet->get($_POST['email'], $app, $_POST['password']));
//		die(json_encode(array(
//			'user'=>'blonde',
//			'storageNode'=>'hotmail.com.mlsn.org',
//			'publicKeyProduct'=>'adsfafaewewafafv',
//			'privateKeyComplement'=>'ergesEfafswefz',
//			'subPass'=>'tW34LOEA5YTA5EAS',
//			'pubPass'=>'eraeefetblxfpere',
//			'sessionKey'=>'trgaefaewfeqwrgget',
//		)));
	case 'SET':
		if(!isset($_POST['email'])) {
			die('please set an email in the post');
		}
		if(!isset($_POST['password'])) {
			die('please set a password in the post');
		}
		if(!isset($_POST['wallet'])) {
			die('please set a wallet in the post');
		}
		$wallet = new Wallet();
		die($wallet->set($_POST['email'], $app, $_POST['password'], $_POST['wallet']));
	default:
		die('please set action as SET or GET');
	}
} else {
	die("error:please POST with KeyWallet/0.1 protocol".var_export($_POST, true));
}
