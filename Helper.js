
// str_repeat
exports.str_repeat = function(input, multiplier) {
	var y = '';
	while (true) {
		if (multiplier & 1) {
			y += input;
		}
		multiplier >>= 1;
		if (multiplier) {
			input += input;
		} else {
			break;
		}
	}
	return y;
};

// chr
exports.chr = function(codePt) {
	if (codePt > 0xFFFF) {
		codePt -= 0x10000;
		return String.fromCharCode(0xD800 + (codePt >> 10), 0xDC00 + (codePt & 0x3FF));
	}
	return String.fromCharCode(codePt);
};

// ord
exports.ord = function(string) {

	var str = string + '', code = str.charCodeAt(0);
	if (0xD800 <= code && code <= 0xDBFF) {
		var hi = code;
		if (str.length === 1) {
			return code;
		}
		var low = str.charCodeAt(1);
		return ((hi - 0xD800) * 0x400) + (low - 0xDC00) + 0x10000;
	}
	if (0xDC00 <= code && code <= 0xDFFF) {// Low surrogate
		return code;
	}
	return code;
}; 
