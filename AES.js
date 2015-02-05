// AES using MCRYPT

var base64 = require('/Crypt/Base64');
var Mcrypt = require('/Crypt/Mcrypt');
var mcrypt = new Mcrypt();

exports.Crypt = function(encrypt, text, iv, key, cipher, mode) {
	mcrypt.Crypt(null,null,null, key, cipher, mode);
};

exports.Encrypt = function(encrypt, text, iv, key, cipher, mode) {
	var block = mcrypt.get_block_size(cipher,mode);
	console.log('Block Size : ' + block);
	var pad = block - ((text.length) % block);
	console.log('Pad : ' + pad);
	var plainText = text + require('/Crypt/Helper').str_repeat(require('/Crypt/Helper').chr(pad), pad);
	console.log('PlainText : ' + plainText);
    	return mcrypt.Encrypt(plainText, key);
};

exports.Decrypt = function(decrypt, encrypted, iv, key, cipher, mode) {
	var decrypted = mcrypt.Decrypt(base64.decode(encrypted), key);
	var block = mcrypt.get_block_size(cipher,mode);
	console.log('Block Size : ' + block);
	var pad = require('/Crypt/Helper').ord(decrypted[(decrypted.length) - 1]);
    	var len = decrypted.length;
    	var pad = require('/Crypt/Helper').ord(decrypted[len-1]);
    	console.log('Dec Pad : ' + pad);
    	return decrypted.substr(0,len-pad);
};
