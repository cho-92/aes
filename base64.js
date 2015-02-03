var b64array = "ABCDEFGHIJKLMNOP" +
	           "QRSTUVWXYZabcdef" +
	           "ghijklmnopqrstuv" +
	           "wxyz0123456789+/" +
	           "=";

exports.encode = function(input){
    var base64 = "";
    var hex = "";
    var chr1, chr2, chr3 = "";
    var enc1, enc2, enc3, enc4 = "";
    var i = 0;

    do {
        chr1 = input.charCodeAt(i++);
        chr2 = input.charCodeAt(i++);
        chr3 = input.charCodeAt(i++);
    
        enc1 = chr1 >> 2;
        enc2 = ((chr1 & 3) << 4) | (chr2 >> 4);
        enc3 = ((chr2 & 15) << 2) | (chr3 >> 6);
        enc4 = chr3 & 63;
    
        if (isNaN(chr2)) {
            enc3 = enc4 = 64;
        } else if (isNaN(chr3)) {
            enc4 = 64;
        }

        base64  = base64  +
            b64array.charAt(enc1) +
            b64array.charAt(enc2) +
            b64array.charAt(enc3) +
            b64array.charAt(enc4);
        chr1 = chr2 = chr3 = "";
        enc1 = enc2 = enc3 = enc4 = "";
    } while (i < input.length);

    return base64;
};
	
exports.decode = function(input) {
    var input = input;
    var output = "";
    var hex = "";
    var chr1, chr2, chr3 = "";
    var enc1, enc2, enc3, enc4 = "";
    var i = 0;

    var base64test = /[^A-Za-z0-9\+\/\=]/g;
    if (base64test.exec(input)) {
        Ti.API.info("There were invalid base64 characters in the input text.\n" +
              "Valid base64 characters are A-Z, a-z, 0-9, '+', '/',and '='\n" +
              "Expect errors in decoding.");
    } else {
        Ti.API.info("");
    }
    input = input.replace(/[^A-Za-z0-9\+\/\=]/g, "");

    do {
        enc1 = b64array.indexOf(input.charAt(i++));
        enc2 = b64array.indexOf(input.charAt(i++));
        enc3 = b64array.indexOf(input.charAt(i++));
        enc4 = b64array.indexOf(input.charAt(i++));
        
        chr1 = (enc1 << 2) | (enc2 >> 4);
        chr2 = ((enc2 & 15) << 4) | (enc3 >> 2);
        chr3 = ((enc3 & 3) << 6) | enc4;
        
        output = output + String.fromCharCode(chr1);
        
        if (enc3 != 64) {
            output = output + String.fromCharCode(chr2);
        }
        if (enc4 != 64) {
            output = output + String.fromCharCode(chr3);
        }
    
        chr1 = chr2 = chr3 = "";
        enc1 = enc2 = enc3 = enc4 = "";
    
    } while (i < input.length);

    return unescape(output);
};
	
exports.UTF8Encode = function(s) {
	for(var c, i = -1, l = (s = s.split("")).length, o = String.fromCharCode; ++i < l;
		s[i] = (c = s[i].charCodeAt(0)) >= 127 ? o(0xc0 | (c >>> 6)) + o(0x80 | (c & 0x3f)) : s[i]
	);
	return s.join("");
};
	
exports.UTF8Decode = function(s) {	
	for(var a, b, i = -1, l = (s = s.split("")).length, o = String.fromCharCode, c = "charCodeAt"; ++i < l;
		((a = s[i][c](0)) & 0x80) &&
		(s[i] = (a & 0xfc) == 0xc0 && ((b = s[i + 1][c](0)) & 0xc0) == 0x80 ?
		o(((a & 0x03) << 6) + (b & 0x3f)) : o(128), s[++i] = "")
	);
	return s.join("");
};
