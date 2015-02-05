/*
 *  jsmcrypt version 0.1  -  Copyright 2012 F. Doering
 *
 *  This program is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU General Public License as
 *  published by the Free Software Foundation; either version 2 of the
 *  License, or (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA
 *  02111-1307 USA
 */
 
 
 //this creates a static class mcrypt that is already initialized
 
function Mcrypt(){
	
	var Rijndael = require('/Crypt/Rijndael');
	var rijndael = new Rijndael();
	
	this.ciphers= {		//	block size,	key size
	  "rijndael-128"	:[16,32],
	  "rijndael-192"	:[24,32],
	  "rijndael-256"	:[32,32],
	  "serpent"			:[16,32],
	 };
	
	this.blockCipherCalls = {};
	
	this.blockCipherCalls['rijndael-128'] = function(cipher,block,key,encrypt){
	 	if(key.length<16)
	    key+=Array(17-key.length).join(String.fromCharCode(0));
		else if(key.length<24 && key.length>16)
		    key+=Array(25-key.length).join(String.fromCharCode(0));
		else if(key.length<32 && key.length>24)
		    key+=Array(33-key.length).join(String.fromCharCode(0));
	 	
		if(encrypt)
			rijndael.Encrypt(block,key);
		else
			rijndael.Decrypt(block,key);
		return block;
	 };
	 this.blockCipherCalls['rijndael-192']=this.blockCipherCalls['rijndael-128'];
	 this.blockCipherCalls['rijndael-256']=this.blockCipherCalls['rijndael-128'];
	 this.blockCipherCalls.serpent=function(cipher,block,key,encrypt){
		if(encrypt)
			Serpent.Encrypt(block);
		else
			Serpent.Decrypt(block);
		return block;
	 };
	 this.blockCipherCalls.serpent.init=function(cipher,key,encrypt){
		var keyA=[];
		for(var i=0;i<key.length;i++)
			keyA[i]=key.charCodeAt(i);
		Serpent.Init(keyA);
	 };
	 this.blockCipherCalls.serpent.deinit=function(cipher,key,encrypt){
		Serpent.Close();
	 };
	 
	 this.cMode = 'ecb';
	 this.cCipher = 'rijndael-128';
	 this.cKey = '';
	 
	 // Common Crypt
	 
	 this.Crypt=function(encrypt,text,IV,key, cipher, mode){
		if(key) this.cKey=key; else key=this.cKey;
		if(cipher) this.cCipher=cipher; else cipher=this.cCipher;
		if(mode) this.cMode=mode; else mode=this.cMode;
		if(!text)
			return true;
		if(this.blockCipherCalls[cipher].init)
			this.blockCipherCalls[cipher].init(cipher,key,encrypt);
		var blockS=this.ciphers[cipher][0];
		var chunkS=blockS;
		var iv=new Array(blockS);
		switch(mode){
			case 'cfb':
				chunkS=1;//8-bit
			case 'cbc':
			case 'ncfb':
			case 'nofb':
			case 'ctr':
				if(!IV)
					throw "mcrypt.Crypt: IV Required for mode "+mode;
				if(IV.length!=blockS)
					throw "mcrypt.Crypt: IV must be "+blockS+" characters long for "+cipher;
				for(var i = blockS-1; i>=0; i--)
					iv[i] = IV.charCodeAt(i);
				break;
			case 'ecb':
				break;
			default:
				throw "mcrypt.Crypt: Unsupported mode of opperation"+this.cMode;
		}
		var chunks=Math.ceil(text.length/chunkS);
		var orig=text.length;
		text+=Array(chunks*chunkS-orig+1).join(String.fromCharCode(0));//zero pad the end
		var out='';
		switch(mode){
			case 'ecb':
				for(var i = 0; i < chunks; i++){
					for(var j = 0; j < chunkS; j++)
						iv[j]=text.charCodeAt((i*chunkS)+j);
					this.blockCipherCalls[cipher](cipher,iv, this.cKey,encrypt);
					for(var j = 0; j < chunkS; j++)
						out+=String.fromCharCode(iv[j]);
				}
				
				console.log('iv = '+iv.join());
				break;
			case 'cbc':
				if(encrypt){
					for(var i = 0; i < chunks; i++){
						for(var j = 0; j < chunkS; j++)
							iv[j]=text.charCodeAt((i*chunkS)+j)^iv[j];
						this.blockCipherCalls[cipher](cipher,iv, this.cKey,true);
						for(var j = 0; j < chunkS; j++)
							out+=String.fromCharCode(iv[j]);
					}
				}
				else{
					for(var i = 0; i < chunks; i++){
						var temp=iv;
							iv=new Array(chunkS);
						for(var j = 0; j < chunkS; j++)
							iv[j]=text.charCodeAt((i*chunkS)+j);
						var decr=iv.slice(0);
						this.blockCipherCalls[cipher](cipher,decr, this.cKey,false);
						for(var j = 0; j < chunkS; j++)
							out+=String.fromCharCode(temp[j]^decr[j]);
					}
				}
				break;
			case 'cfb':
				for(var i = 0; i < chunks; i++){
					var temp=iv.slice(0);
					this.blockCipherCalls[cipher](cipher,temp, this.cKey,true);
					temp=temp[0]^text.charCodeAt(i);
					iv.push(encrypt?temp:text.charCodeAt(i));
					iv.shift();
					out+=String.fromCharCode(temp);
				}
				out=out.substr(0,orig);
				break;
			case 'ncfb':
				for(var i = 0; i < chunks; i++){
					this.blockCipherCalls[cipher](cipher,iv, this.cKey,true);
					for(var j = 0; j < chunkS; j++){
						var temp=text.charCodeAt((i*chunkS)+j);
						iv[j]=temp^iv[j];
						out+=String.fromCharCode(iv[j]);
						if(!encrypt)
							iv[j]=temp;
					}
				}
				out=out.substr(0,orig);
				break;
			case 'nofb':
				for(var i = 0; i < chunks; i++){
					this.blockCipherCalls[cipher](cipher,iv, this.cKey,true);
					for(var j = 0; j < chunkS; j++)
						out+=String.fromCharCode(text.charCodeAt((i*chunkS)+j)^iv[j]);
				}
				out=out.substr(0,orig);
				break;
			case 'ctr':
				for(var i = 0; i < chunks; i++){
					temp=iv.slice(0);
					this.blockCipherCalls[cipher](cipher,temp, this.cKey,true);
					for(var j = 0; j < chunkS; j++)
						out+=String.fromCharCode(text.charCodeAt((i*chunkS)+j)^temp[j]);
					var carry=1;
					var index=chunkS;
					do{
						index--;
						iv[index]+=1;
						carry=iv[index]>>8;
						iv[index]&=255;
					}while(carry);
				}
				out=out.substr(0,orig);
				break;
		}
		if(this.blockCipherCalls[cipher].deinit)
			this.blockCipherCalls[cipher].deinit(cipher,key,encrypt);
		return out;
	};
	 
}
 

 /* Encrypt */
 Mcrypt.prototype.Encrypt = function(message,IV,key, cipher, mode){
	return this.Crypt(true, message, IV, key, cipher, mode);
};

/* Decrypt */  
 Mcrypt.prototype.Decrypt=function(ctext,IV,key, cipher, mode){
	return this.Crypt(false, ctext, IV, key, cipher, mode);
 };

/* Crypt
 * This function can encrypt or decrypt text
 */
 
Mcrypt.prototype.Crypt=function(encrypt,text,IV,key, cipher, mode){
	this.Crypt(encrypt,text,IV,key, cipher, mode);
};

//Gets the block size of the specified cipher
Mcrypt.prototype.get_block_size=function(cipher,mode){
	if(!cipher) cipher=this.cCipher;
	if(!this.ciphers[cipher])
		return false;
	return this.ciphers[cipher][0];
};

//Gets the name of the specified cipher
Mcrypt.prototype.get_cipher_name=function(cipher){
	if(!cipher) cipher=this.cCipher;
	if(!this.ciphers[cipher])
		return false;
	return cipher;
};

//Returns the size of the IV belonging to a specific cipher/mode combination
Mcrypt.prototype.get_iv_size=function(cipher,mode){
	if(!cipher) cipher=this.cCipher;
	if(!this.ciphers[cipher])
		return false;
	return this.ciphers[cipher][0];
};

//Gets the key size of the specified cipher
Mcrypt.prototype.get_key_size=function(cipher,mode){
	if(!cipher) cipher=this.cCipher;
	if(!this.ciphers[cipher])
		return false;
	return this.ciphers[cipher][1];
};

//Gets an array of all supported ciphers
Mcrypt.prototype.list_algorithms=function(){
	var ret=[];
	for(var i in this.ciphers)
		ret.push(i);
	return ret;
};

Mcrypt.prototype.list_modes=function(){
	return ['ecb','cbc','cfb','ncfb','nofb','ctr'];
};

module.exports = Mcrypt;
