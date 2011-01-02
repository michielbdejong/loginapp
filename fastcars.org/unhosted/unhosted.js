/*
    UnstorageNodeed JS library. Handles comms with unhosted storage storageNode for unhosted web apps.
    Copyright (C) 2010 Michiel de Jong michiel@unhosted.org

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as
    published by the Free Software Foundation, either version 3 of the
    License, or (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/


/*GLOBAL SINGLETON:*/
unhosted = new function() {
	//private:
	var that = this;
	var keys={};//each one should contain fields r,c,n[,s[,d]] (r,c in ASCII; n,s,d in HEX)
	var rng = new SecureRandom();//for padding

	var sendPost = function(post, storageNode, prefix, postfix) {//this function implements synchronous AJAX to a storageNode
		if(typeof storageNode == 'undefined') {
			return 'error, attempted to connect to an undefined storageNode.';
		}
		if(typeof prefix == 'undefined') {
			prefix = "http://unhosted.";
		}
		if(typeof postfix == 'undefined') {
			postfix = "/UJ/0.2/";
		}
		xmlhttp=new XMLHttpRequest();
		//xmlhttp.open("POST","http://example.unhosted.org/",false);
		xmlhttp.open("POST",prefix+storageNode+postfix,false);//TODO: make this https
		xmlhttp.setRequestHeader("Content-type","application/x-www-form-urlencoded");
		xmlhttp.send(post);
		return xmlhttp.responseText;
	}
	var checkNick=function(nick) {
		if(typeof keys[nick] == 'undefined') {
			parts=nick.split('@', 2);
			if(parts.length != 2) {
				alert('attempt to use undefined key nick: '+nick+'. Did you forget to log in?');
			}
			that.importSubN({"user":parts[0],"storageNode":parts[1]},nick,".n");
		}
	}
	var checkFields = function(arr, fieldNames) {
		for(field in fieldNames) {
			if(typeof arr[fieldNames[field]] == 'undefined') {
				alert('field '+fieldNames[field]+' missing from key: '+JSON.stringify(arr));
				return;
			}
		}
	}
	// Generate a new random private key B bits long, using public expt E
	var RSAGenerate = function() {
		var qs = 512>>1;
		this.e = parseInt("10001",16);
		var ee = new BigInteger("10001",16);
		for(;;) {
			for(;;) {
				p = new BigInteger(512-qs,1,rng);
				if(p.subtract(BigInteger.ONE).gcd(ee).compareTo(BigInteger.ONE) == 0 && p.isProbablePrime(10)) break;
			}
			for(;;) {
				q = new BigInteger(qs,1,rng);
				if(q.subtract(BigInteger.ONE).gcd(ee).compareTo(BigInteger.ONE) == 0 && q.isProbablePrime(10)) break;
			}
			if(p.compareTo(q) <= 0) {
				var t = p;
				p = q;
				q = t;
			}
			var p1 = p.subtract(BigInteger.ONE);
			var q1 = q.subtract(BigInteger.ONE);
			var phi = p1.multiply(q1);
			if(phi.gcd(ee).compareTo(BigInteger.ONE) == 0) {
				//generate some interesting numbers from p and q:
				var qs = 512>>1;		var e = parseInt("10001", 16);  var ee = new BigInteger("10001", 16);
				var p1 = p.subtract(BigInteger.ONE);	var q1 = q.subtract(BigInteger.ONE);
				var phi = p1.multiply(q1);	var n = p.multiply(q);	var d = ee.modInverse(phi);

				return {"publicKeyProduct":n.toString(16), "privateKeyComplement":d.toString(16)};
			}
		}
	}
	var createPub = function(emailUser, emailDomain, storageNode) {
		var bnSeskey, bnWriteKey, bnReadKey;
		key = RSAGenerate();
		key.storageNode = storageNode;
		key.emailUser = emailUser;
		key.emailDomain = emailDomain;
		bnSeskey = new BigInteger(128,1,rng);//rijndael function we use uses a 128-bit key
		key.session_key = bnSeskey.toString(16);
		bnWriteKey = new BigInteger(128,1,rng);//rijndael function we use uses a 128-bit key
		key.pubPass = bnWriteKey.toString(16);
		bnReadKey = new BigInteger(128,1,rng);//rijndael function we use uses a 128-bit key
		key.subPass = bnReadKey.toString(16);
		return key;
	}
	//public:
	this.importPub = function(writeCaps, nick) {//import a (pub) key to the keys[] variable
		checkFields(writeCaps, ['emailUser', 'emailDomain', 'storageNode', 'publicKeyProduct', 'privateKeyComplement']);
		keys[nick]=writeCaps;//this should contain r,c,n,d.
	}
	this.rawGet = function(nick, keyPath) {//used for starskey and by wappbook login bootstrap to retrieve key.n and key.s
		checkNick(nick);
		var ret = sendPost("protocol=UJ/0.2&action=KV.GET&emailUser="+keys[nick].emailUser+"&emailDomain="+keys[nick].emailDomain+"&keyPath="+keyPath+"&subPass="+keys[nick].subPass, keys[nick].storageNode);
		if(ret == "") {
			return null;
		}
		try {
			return JSON.parse(ret);
		} catch(e) {
			alert('Non-JSON response to GET command:'+ret);
			return null;
		}
	}
	this.get = function(nick, keyPath) {//execute a UJ/0.1 GET command
		checkNick(nick);
		var ret = that.rawGet(nick, keyPath);
		if(ret==null || ret.value == null) {
			return null;
		}
		return JSON.parse(byteArrayToString(rijndaelDecrypt(hexToByteArray(ret.value), hexToByteArray(keys[nick].session_key), 'ECB')));
	}
	this.importWallet = function(email, walletHost, walletPass) {//execute a getwallet command
		var ret = sendPost("protocol=KeyWallet/0.1&action=GET&email="+email+"&password="+walletPass,
					walletHost, "http://", "/wallet/");
		var wallet = JSON.parse(ret);
		this.importPub(wallet, email);
		var ret = sendPost("protocol=UJ/0.2&action=ACCT.GETSTATE&emailUser="+keys[email].emailUser+"&emailDomain="+keys[email].emailDomain
					+"&pubPass="+keys[email].pubPass, keys[email].storageNode);
		switch(ret) {
		case '0':
			alert('your account is still pending setup');
			break;
		case '1':
			//alert('your account is live and you logged in successfully! enjoy your session.');
			break;
		case '2':
			alert('your account is gone! if you did not delete it on purpose then contact your unhosted storage provider');
			break;
		case '3':
			alert('your account is emigrating to ...@...');
			break;
		case '4':
			alert('your account is immigrating from ...@...');
			break;
		case 'HTTP/1.1 402 Forbidden':
			alert('oops! looks like your Wallet at Grommace does not successfully link to a valid account.');
			break;
		default:
			alert('unknown account state');
		}
		return email;
	}
	this.exportWallet = function(email, guid, walletHost, walletPass) {//execute a getwallet command
		var ret = sendPost("protocol=KeyWallet/0.1&action=SET&email="+email+"&password="+walletPass+"&wallet="+JSON.stringify(keys[guid]), 
					walletHost, "http://", "/wallet/");
	}
	this.set = function(nick, keyPath, value) {//execute a UJ/0.1 SET command
		checkNick(nick);
		var encr = byteArrayToHex(rijndaelEncrypt(JSON.stringify(value), hexToByteArray(keys[nick].session_key), 'ECB'));
		var PubSign = '';//makePubSign(nick, cmd);
		var ret = sendPost("protocol=UJ/0.2&action=KV.SET&emailUser="+keys[nick].emailUser+"&emailDomain="+keys[nick].emailDomain+"&keyPath="+keyPath+"&value="+encr+"&PubSign="+PubSign+'&pubPass='+keys[nick].pubPass, keys[nick].storageNode);
		if(ret != '"OK"') {
			alert(ret);
		}
		return ret;
	}
	this.nodeExists = function(storageNode) {
		return (storageNode == 'balimich.org');
	}
	this.registerAccount = function(email, storageNode) {
		var parts, key, ret;
		parts = email.split('@', 2);
		if(parts.length != 2) {
			alert("email "+email+" not valid - use user@domain.tld");
		} else {
			key = createPub(parts[0], parts[1], storageNode);
			//storage storageNode needs to know read and write passwords:
			ret = sendPost("protocol=UJ/0.2&action=ACCT.REGISTER&emailUser="+parts[0]+"&emailDomain="+parts[1]
				+"&subPass="+key.subPass+"&pubPass="+key.pubPass, key.storageNode);
			this.importPub(key, email);
		}
		return ret;
	}
	this.confirmAccount = function(email, registrationToken) {
		var parts, key, ret;
		parts = email.split('@', 2);
		if(parts.length != 2) {
			alert("email "+email+" not valid - use user@domain.tld");
		} else {
			key = keys[email];
			//storage storageNode needs to know read and write passwords:
			ret = sendPost("protocol=UJ/0.2&action=ACCT.CONFIRM&emailUser="+parts[0]+"&emailDomain="+parts[1]
				+"&pubPass="+key.pubPass+"&registrationToken="+registrationToken, key.storageNode);
		}
		return ret;
	}
}
