Shamir39 = function() {

    var VERSION = "shamir39b";
    var VALID_LENGTHS = [0, 12, 15, 18, 21, 24];

    // Splits a BIP39 mnemonic and optional passphrase into Shamir39b mnemonics.
    // Validation on the bip39 words is minimal (expected count, in wordlist)
    this.split = function(bip39MnemonicWords, passphrase, wordlist, m, n) {
        // validate inputs
        if (m < 2) {
            return {
                error: "Must require at least 2 shares"
            };
        }
        if (m > 4095) {
            return {
                error: "Must require at most 4095 shares"
            };
        }
        if (n < 2) {
            return {
                error: "Must split to at least 2 shares"
            };
        }
        if (n > 4095) {
            return {
                error: "Must split to at most 4095 shares"
            };
        }
        // TODO make wordlist length more general
        if (wordlist.length != 2048) {
            return {
                error: "Wordlist must have 2048 words"
            };
        }
        if (bip39MnemonicWords.length == 0 && passphrase.length == 0) {
            return {
                error: "No bip39 mnemonic words or passphrase provided"
            };
        }
        if (VALID_LENGTHS.indexOf(bip39MnemonicWords.length) < 0) {
            return {
                error: "Mnemonic must consist of " + VALID_LENGTHS.slice(0, VALID_LENGTHS.length - 1).join(", ") + " or "
                        + VALID_LENGTHS[VALID_LENGTHS.length - 1] + " words"
            };            
        }
        if (passphrase.length > 256) { // totally arbitrary
            return {
                error: "Passphrases longer than 256 characters not supported"
            }
        }
        // convert bip39 mnemonic into bits
        var binStr = "";
        for (var i=0; i<bip39MnemonicWords.length; i++) {
            var w = bip39MnemonicWords[i];
            var index = wordlist.indexOf(w);
            if (index == -1) {
                var errorMsg = "Invalid word found in list: " + w;
                return {
                    error: errorMsg
                };
            }
            var bits = index.toString(2); // convert to base 2
            bits = lpad(bits, 11);
            binStr = binStr + bits;
        }
        // calculate 3-bit code representing mnemonic word count
        var prefix = 0;
        if (bip39MnemonicWords.length > 0) {
            prefix = (bip39MnemonicWords.length - 9) / 3;
        }
        // append passphrase
        binStr += encodeStr(passphrase);
        // apply padding for use as hex
        var lenForHex = Math.ceil((binStr.length + 5) / 4) * 4; // +5 to account for prefix to be added
        var padding = lenForHex - (binStr.length + 5);
        // RKTODO: For debugging/testing, assert padding is <  4.  Should always be.
        binStr = "0".repeat(padding) + binStr;
        // prefix with padding count and mnemonic word count code
        binStr = lpad(prefix.toString(2), 3) + binStr;
        binStr = lpad(padding.toString(2), 2) + binStr;
        // convert to hex string
        var totalHexChars = binStr.length / 4;
        var hexStr = "";
        for (var i=0; i<totalHexChars; i++) {
            var nibbleStr = binStr.substring(i*4, (i+1)*4);
            var hexValue = parseInt(nibbleStr, 2);
            var hexChar = hexValue.toString(16);
            hexStr = hexStr + hexChar;
        }
        // create shamir parts
        var partsHex = share(hexStr, n, m, 0, true);
        // convert parts into shamir39 mnemonics
        var mnemonics = [];
        for (var o=0; o<partsHex.length; o++) {
            // set mnemonic version
            var mnemonic = [VERSION];
            // set mnemonic parameters
            var parametersBin = paramsToBinaryStr(m, o);
            var paramsWords = binToMnemonic(parametersBin, wordlist);
            mnemonic = mnemonic.concat(paramsWords);
            // set mnemonic shamir part
            var partHex = partsHex[o];
            var partBin = hex2bin(partHex);
            var partWords = binToMnemonic(partBin, wordlist);
            mnemonic = mnemonic.concat(partWords);
            // add mnemonic part to mnemonics
            mnemonics.push(mnemonic);
        }
        return {
            mnemonics: mnemonics
        };
    }

    // Combines Shamir39 mnemonics into a BIP39 mnemonic
    this.combine = function(parts, wordlist) {
        // convert parts to hex
        var hexParts = [];
        var requiredParts = -1;
        for (var i=0; i<parts.length; i++) {
            var words = parts[i];
            // validate version
            if (words[0] != VERSION) {
                return {
                    error: "Version doesn't match"
                };
            }
            // get params
            var mBinStr = "";
            var oBinStr = "";
            var endParamsIndex = 1;
            for (var j=1; j<words.length; j++) {
                var word = words[j];
                var wordIndex = wordlist.indexOf(word);
                if (wordIndex == -1) {
                    return {
                        error: "Word not in wordlist: " + word
                    }
                }
                var wordBin = lpad(wordIndex.toString(2), 11);
                mBinStr = mBinStr + wordBin.substring(1,6);
                oBinStr = oBinStr + wordBin.substring(6,11);
                var isEndOfParams = wordBin[0] == "0";
                if (isEndOfParams) {
                    endParamsIndex = j;
                    break;
                }
            }
            // parse parameters
            var m = parseInt(mBinStr, 2);
            var o = parseInt(oBinStr, 2);
            // validate parameters
            if (requiredParts == -1) {
                requiredParts = m;
            }
            if (m != requiredParts) {
                return {
                    error: "Inconsisent M parameters"
                }
            }
            // get shamir part
            var partBin = "";
            for (var j=endParamsIndex+1; j<words.length; j++) {
                var word = words[j];
                var wordIndex = wordlist.indexOf(word);
                if (wordIndex == -1) {
                    return {
                        error: "Word not in wordlist: " + word
                    }
                }
                var wordBin = lpad(wordIndex.toString(2), 11);
                partBin = partBin + wordBin;
            }
            var hexChars = Math.floor(partBin.length / 4) * 4;
            var diff = partBin.length - hexChars;
            partBin = partBin.substring(diff);
            var partHex = bin2hex(partBin);
            // insert in correct order and remove duplicates
            hexParts[o] = partHex;
        }
        // remove missing parts
        var partsClean = [];
        for (var i=0; i<hexParts.length; i++) {
            if (hexParts[i]) {
                partClean = {
                    id: i+1,
                    part: hexParts[i],
                };
                partsClean.push(partClean);
            }
        }
        hexParts = partsClean;
        // validate the parameters to ensure the secret can be created
        if (hexParts.length < requiredParts) {
            return {
                error: "Not enough parts, requires " + requiredParts
            }
        }
        // combine parts into secret
        var secretHex = combine(hexParts);
        // convert secret into binary
        var secretBin = hex2bin(secretHex);
        var orgSecretBin = secretBin; // for debugging; since we'll overwrite the latter below in order to avoid extra diff lines in this code fork
        // read padding length
        var padLenBin = secretBin.substring(0, 2);
        var padLen = parseInt(padLenBin, 2); // RKTODO: Improve validation to ensure we have enough bits
        // read 3-bit prefix containing word count
        var prefix = secretBin.substring(padLenBin.length, padLenBin.length + 3);
        var wcount = parseInt(prefix, 2);
        var totalWords = 0;
        if (wcount > 0) {
            totalWords = 3 * wcount + 9;
        }
        if (VALID_LENGTHS.indexOf(totalWords) < 0) {
            return {
                error: "Unsupported mnemonic word count of " + totalWords
            }
        }
        // discard prefix and padding
        secretBin = secretBin.substring(prefix.length + padLenBin.length + padLen);
        // extract and truncate passphrase if it exists
        var passphraseBin = secretBin.substring(totalWords * 11);
        secretBin = secretBin.substring(0, totalWords * 11);
        // decode passphrase
        var passphrase = decodeStr(passphraseBin);
        // convert secret into mnemonic
        var totalWords = Math.floor(secretBin.length / 11);
        var totalBits = totalWords * 11;
        var diff = secretBin.length - totalBits;
        secretBin = secretBin.substring(diff);
        var mnemonic = [];
        for (var i = 0; i<totalWords; i++) {
            var wordIndexBin = secretBin.substring(i*11, (i+1)*11);
            var wordIndex = parseInt(wordIndexBin, 2);
            var word = wordlist[wordIndex];
            mnemonic.push(word);
        }
        return {
            mnemonic: mnemonic,
            passphrase: passphrase
        };
    }

    // encodes the paramaters into a binary string
    function paramsToBinaryStr(m, o) {
        // get m as binary, padded to multiple of 5 bits
        var mBin = m.toString(2);
        // get o as binary, padded to multiple of 5 bits
        var oBin = o.toString(2);
        // calculate the overall binary length of each parameter, which must
        // be identical
        var mBinFinalLength = Math.ceil(mBin.length / 5) * 5;
        var oBinFinalLength = Math.ceil(oBin.length / 5) * 5;
        var binFinalLength = Math.max(mBinFinalLength, oBinFinalLength)
        // pad each parameter
        mBin = lpad(mBin, binFinalLength);
        oBin = lpad(oBin, binFinalLength);
        // encode parameters in binary
        var totalWords = oBin.length / 5;
        var binStr = "";
        for (var i=0; i<totalWords; i++) {
            var isLastWord = i == totalWords - 1
            var leadingBit = "1";
            if (isLastWord) {
                leadingBit = "0";
            }
            var mBits = mBin.substring(i*5, (i+1)*5);
            var oBits = oBin.substring(i*5, (i+1)*5);
            binStr = binStr + leadingBit + mBits + oBits;
        }
        return binStr;
    }

    function binToMnemonic(binStr, wordlist) {
        var mnemonic = [];
        // pad binary to suit words of 11 bits
        var totalWords = Math.ceil(binStr.length / 11);
        var totalBits = totalWords * 11;
        binStr = lpad(binStr, totalBits);
        // convert bits to words
        for (var i=0; i<totalWords; i++) {
            var bits = binStr.substring(i*11, (i+1)*11);
            var wordIndex = parseInt(bits, 2);
            var word = wordlist[wordIndex];
            mnemonic.push(word);
        }
        return mnemonic;
    }

    // left-pad a number with zeros
    function lpad(s, n) {
        s = s.toString();
        while (s.length < n) {
            s = "0" + s;
        }
        return s;
    }

    // Shamir functions modified from
    // https://github.com/amper5and/secrets.js/
    // by Alexander Stetsyuk - released under MIT License
    var defaults = {
        bits: 8, // default number of bits
        radix: 16, // work with HEX by default
        minBits: 3,
        maxBits: 20, // this permits 1,048,575 shares, though going this high is NOT recommended in JS!

        bytesPerChar: 2,
        maxBytesPerChar: 6, // Math.pow(256,7) > Math.pow(2,53)

        // Primitive polynomials (in decimal form) for Galois Fields GF(2^n), for 2 <= n <= 30
        // The index of each term in the array corresponds to the n for that polynomial
        // i.e. to get the polynomial for n=16, use primitivePolynomials[16]
        primitivePolynomials: [null,null,1,3,3,5,3,3,29,17,9,5,83,27,43,3,45,9,39,39,9,5,3,33,27,9,71,39,9,5,83],

        // warning for insecure PRNG
        warning: 'WARNING:\nA secure random number generator was not found.\nUsing Math.random(), which is NOT cryptographically strong!'
    };

    // Protected settings object
    var config = {};

    function getConfig(){
        return {
            'bits': config.bits,
            'unsafePRNG': config.unsafePRNG
        };
    };

    function init(bits){
        if(bits && (typeof bits !== 'number' || bits%1 !== 0 || bits<defaults.minBits || bits>defaults.maxBits)){
            throw new Error('Number of bits must be an integer between ' + defaults.minBits + ' and ' + defaults.maxBits + ', inclusive.')
        }

        config.radix = defaults.radix;
        config.bits = bits || defaults.bits;
        config.size = Math.pow(2, config.bits);
        config.max = config.size - 1;

        // Construct the exp and log tables for multiplication.
        var logs = [], exps = [], x = 1, primitive = defaults.primitivePolynomials[config.bits];
        for(var i=0; i<config.size; i++){
            exps[i] = x;
            logs[x] = i;
            x <<= 1;
            if(x >= config.size){
                x ^= primitive;
                x &= config.max;
            }
        }

        config.logs = logs;
        config.exps = exps;
    };

    function isInited(){
        if(!config.bits || !config.size || !config.max  || !config.logs || !config.exps || config.logs.length !== config.size || config.exps.length !== config.size){
            return false;
        }
        return true;
    };

    // Returns a pseudo-random number generator of the form function(bits){}
    // which should output a random string of 1's and 0's of length `bits`
    function getRNG(){
        var randomBits, crypto;

        function construct(bits, arr, radix, size){
            var str = '',
                i = 0,
                len = arr.length-1;
            while( i<len || (str.length < bits) ){
                str += padLeft(parseInt(arr[i], radix).toString(2), size);
                i++;
            }
            str = str.substr(-bits);
            if( (str.match(/0/g)||[]).length === str.length){ // all zeros?
                return null;
            }else{
                return str;
            }
        }

        // node.js crypto.randomBytes()
        if(typeof require === 'function' && (crypto=require('crypto')) && (randomBits=crypto['randomBytes'])){
            return function(bits){
                var bytes = Math.ceil(bits/8),
                    str = null;

                while( str === null ){
                    str = construct(bits, randomBits(bytes).toString('hex'), 16, 4);
                }
                return str;
            }
        }

        // browsers with window.crypto.getRandomValues()
        if(window['crypto'] && typeof window['crypto']['getRandomValues'] === 'function' && typeof window['Uint32Array'] === 'function'){
            crypto = window['crypto'];
            return function(bits){
                var elems = Math.ceil(bits/32),
                    str = null,
                    arr = new window['Uint32Array'](elems);

                while( str === null ){
                    crypto['getRandomValues'](arr);
                    str = construct(bits, arr, 10, 32);
                }

                return str;
            }
        }

        // A totally insecure RNG!!! (except in Safari)
        // Will produce a warning every time it is called.
        config.unsafePRNG = true;
        warn();

        var bitsPerNum = 32;
        var max = Math.pow(2,bitsPerNum)-1;
        return function(bits){
            var elems = Math.ceil(bits/bitsPerNum);
            var arr = [], str=null;
            while(str===null){
                for(var i=0; i<elems; i++){
                    arr[i] = Math.floor(Math.random() * max + 1);
                }
                str = construct(bits, arr, 10, bitsPerNum);
            }
            return str;
        };
    };

    // Warn about using insecure rng.
    // Called when Math.random() is being used.
    function warn(){
        window['console']['warn'](defaults.warning);
        if(typeof window['alert'] === 'function' && config.alert){
            window['alert'](defaults.warning);
        }
    }

    // Set the PRNG to use. If no RNG function is supplied, pick a default using getRNG()
    function setRNG(rng, alert){
        if(!isInited()){
            init();
        }
        config.unsafePRNG=false;
        rng = rng || getRNG();

        // test the RNG (5 times)
        if(typeof rng !== 'function' || typeof rng(config.bits) !== 'string' || !parseInt(rng(config.bits),2) || rng(config.bits).length > config.bits || rng(config.bits).length < config.bits){
            throw new Error("Random number generator is invalid. Supply an RNG of the form function(bits){} that returns a string containing 'bits' number of random 1's and 0's.")
        }else{
            config.rng = rng;
        }
        config.alert = !!alert;

        return !!config.unsafePRNG;
    };

    function isSetRNG(){
        return typeof config.rng === 'function';
    };

    // Generates a random bits-length number string using the PRNG
    function random(bits){
        if(!isSetRNG()){
            setRNG();
        }

        if(typeof bits !== 'number' || bits%1 !== 0 || bits < 2){
            throw new Error('Number of bits must be an integer greater than 1.')
        }

        if(config.unsafePRNG){
            warn();
        }
        return bin2hex(config.rng(bits));
    }

    // Divides a `secret` number String str expressed in radix `inputRadix` (optional, default 16)
    // into `numShares` shares, each expressed in radix `outputRadix` (optional, default to `inputRadix`),
    // requiring `threshold` number of shares to reconstruct the secret.
    // Optionally, zero-pads the secret to a length that is a multiple of padLength before sharing.
    function share(secret, numShares, threshold, padLength, withoutPrefix){
        if(!isInited()){
            init();
        }
        if(!isSetRNG()){
            setRNG();
        }

        padLength =  padLength || 0;

        if(typeof secret !== 'string'){
            throw new Error('Secret must be a string.');
        }
        if(typeof numShares !== 'number' || numShares%1 !== 0 || numShares < 2){
            throw new Error('Number of shares must be an integer between 2 and 2^bits-1 (' + config.max + '), inclusive.')
        }
        if(numShares > config.max){
            var neededBits = Math.ceil(Math.log(numShares +1)/Math.LN2);
            throw new Error('Number of shares must be an integer between 2 and 2^bits-1 (' + config.max + '), inclusive. To create ' + numShares + ' shares, use at least ' + neededBits + ' bits.')
        }
        if(typeof threshold !== 'number' || threshold%1 !== 0 || threshold < 2){
            throw new Error('Threshold number of shares must be an integer between 2 and 2^bits-1 (' + config.max + '), inclusive.');
        }
        if(threshold > config.max){
            var neededBits = Math.ceil(Math.log(threshold +1)/Math.LN2);
            throw new Error('Threshold number of shares must be an integer between 2 and 2^bits-1 (' + config.max + '), inclusive.  To use a threshold of ' + threshold + ', use at least ' + neededBits + ' bits.');
        }
        if(typeof padLength !== 'number' || padLength%1 !== 0 ){
            throw new Error('Zero-pad length must be an integer greater than 1.');
        }

        if(config.unsafePRNG){
            warn();
        }

        secret = '1' + hex2bin(secret); // append a 1 so that we can preserve the correct number of leading zeros in our secret
        secret = split(secret, padLength);
        var x = new Array(numShares), y = new Array(numShares);
        for(var i=0, len = secret.length; i<len; i++){
            var subShares = _getShares(secret[i], numShares, threshold);
            for(var j=0; j<numShares; j++){
                x[j] = x[j] || subShares[j].x.toString(config.radix);
                y[j] = padLeft(subShares[j].y.toString(2)) + (y[j] ? y[j] : '');
            }
        }
        var padding = config.max.toString(config.radix).length;
        if(withoutPrefix){
            for(var i=0; i<numShares; i++){
                x[i] = bin2hex(y[i]);
            }
        }else{
            for(var i=0; i<numShares; i++){
                x[i] = config.bits.toString(36).toUpperCase() + padLeft(x[i],padding) + bin2hex(y[i]);
            }
        }

        return x;
    };

    // This is the basic polynomial generation and evaluation function
    // for a `config.bits`-length secret (NOT an arbitrary length)
    // Note: no error-checking at this stage! If `secrets` is NOT
    // a NUMBER less than 2^bits-1, the output will be incorrect!
    function _getShares(secret, numShares, threshold){
        var shares = [];
        var coeffs = [secret];

        for(var i=1; i<threshold; i++){
            coeffs[i] = parseInt(config.rng(config.bits),2);
        }
        for(var i=1, len = numShares+1; i<len; i++){
            shares[i-1] = {
                x: i,
                y: horner(i, coeffs)
            }
        }
        return shares;
    };

    // Polynomial evaluation at `x` using Horner's Method
    // TODO: this can possibly be sped up using other methods
    // NOTE: fx=fx * x + coeff[i] ->  exp(log(fx) + log(x)) + coeff[i],
    //       so if fx===0, just set fx to coeff[i] because
    //       using the exp/log form will result in incorrect value
    function horner(x, coeffs){
        var logx = config.logs[x];
        var fx = 0;
        for(var i=coeffs.length-1; i>=0; i--){
            if(fx === 0){
                fx = coeffs[i];
                continue;
            }
            fx = config.exps[ (logx + config.logs[fx]) % config.max ] ^ coeffs[i];
        }
        return fx;
    };

    function inArray(arr,val){
        for(var i = 0,len=arr.length; i < len; i++) {
            if(arr[i] === val){
             return true;
            }
        }
        return false;
    };

    function processShare(share){

        var bits = config.bits;
        if(bits && (typeof bits !== 'number' || bits%1 !== 0 || bits<defaults.minBits || bits>defaults.maxBits)){
            throw new Error('Number of bits must be an integer between ' + defaults.minBits + ' and ' + defaults.maxBits + ', inclusive.')
        }

        var max = Math.pow(2, bits) - 1;
        var idLength = max.toString(config.radix).length;

        var id = share.id;
        if(typeof id !== 'number' || id%1 !== 0 || id<1 || id>max){
            throw new Error('Share id must be an integer between 1 and ' + config.max + ', inclusive.');
        }
        part = share.part;
        if(!part.length){
            throw new Error('Invalid share: zero-length share.')
        }
        return {
            'bits': bits,
            'id': id,
            'value': part
        };
    };

    // Protected method that evaluates the Lagrange interpolation
    // polynomial at x=`at` for individual config.bits-length
    // segments of each share in the `shares` Array.
    // Each share is expressed in base `inputRadix`. The output
    // is expressed in base `outputRadix'
    function _combine(at, shares){
        var setBits, share, x = [], y = [], result = '', idx;

        for(var i=0, len = shares.length; i<len; i++){
            share = processShare(shares[i]);
            if(typeof setBits === 'undefined'){
                setBits = share['bits'];
            }else if(share['bits'] !== setBits){
                throw new Error('Mismatched shares: Different bit settings.')
            }

            if(config.bits !== setBits){
                init(setBits);
            }

            if(inArray(x, share['id'])){ // repeated x value?
                continue;
            }

            idx = x.push(share['id']) - 1;
            share = split(hex2bin(share['value']));
            for(var j=0, len2 = share.length; j<len2; j++){
                y[j] = y[j] || [];
                y[j][idx] = share[j];
            }
        }

        for(var i=0, len=y.length; i<len; i++){
            result = padLeft(lagrange(at, x, y[i]).toString(2)) + result;
        }

        if(at===0){// reconstructing the secret
            var idx = result.indexOf('1'); //find the first 1
            return bin2hex(result.slice(idx+1));
        }else{// generating a new share
            return bin2hex(result);
        }
    };

    // Combine `shares` Array into the original secret
    function combine(shares){
        return _combine(0, shares);
    };

    // Evaluate the Lagrange interpolation polynomial at x = `at`
    // using x and y Arrays that are of the same length, with
    // corresponding elements constituting points on the polynomial.
    function lagrange(at, x, y){
        var sum = 0,
            product,
            i, j;

        for(var i=0, len = x.length; i<len; i++){
            if(!y[i]){
                continue;
            }

            product = config.logs[y[i]];
            for(var j=0; j<len; j++){
                if(i === j){ continue; }
                if(at === x[j]){ // happens when computing a share that is in the list of shares used to compute it
                    product = -1; // fix for a zero product term, after which the sum should be sum^0 = sum, not sum^1
                    break;
                }
                product = ( product + config.logs[at ^ x[j]] - config.logs[x[i] ^ x[j]] + config.max/* to make sure it's not negative */ ) % config.max;
            }

            sum = product === -1 ? sum : sum ^ config.exps[product]; // though exps[-1]= undefined and undefined ^ anything = anything in chrome, this behavior may not hold everywhere, so do the check
        }
        return sum;
    };

    // Splits a number string `bits`-length segments, after first
    // optionally zero-padding it to a length that is a multiple of `padLength.
    // Returns array of integers (each less than 2^bits-1), with each element
    // representing a `bits`-length segment of the input string from right to left,
    // i.e. parts[0] represents the right-most `bits`-length segment of the input string.
    function split(str, padLength){
        if(padLength){
            str = padLeft(str, padLength)
        }
        var parts = [];
        for(var i=str.length; i>config.bits; i-=config.bits){
            parts.push(parseInt(str.slice(i-config.bits, i), 2));
        }
        parts.push(parseInt(str.slice(0, i), 2));
        return parts;
    };

    // Pads a string `str` with zeros on the left so that its length is a multiple of `bits`
    function padLeft(str, bits){
        bits = bits || config.bits
        var missing = str.length % bits;
        return (missing ? new Array(bits - missing + 1).join('0') : '') + str;
    };

    function hex2bin(str){
        var bin = '', num;
        for(var i=str.length - 1; i>=0; i--){
            num = parseInt(str[i], 16)
            if(isNaN(num)){
                throw new Error('Invalid hex character.')
            }
            bin = padLeft(num.toString(2), 4) + bin;
        }
        return bin;
    }

    function bin2hex(str){
        var hex = '', num;
        str = padLeft(str, 4);
        for(var i=str.length; i>=4; i-=4){
            num = parseInt(str.slice(i-4, i), 2);
            if(isNaN(num)){
                throw new Error('Invalid binary character.')
            }
            hex = num.toString(16) + hex;
        }
        return hex;
    }

    // Converts a given UTF16 character string to the HEX representation.
    // Each character of the input string is represented by
    // `bytesPerChar` bytes in the output string.
    function str2hex(str, bytesPerChar){
        if(typeof str !== 'string'){
            throw new Error('Input must be a character string.');
        }
        bytesPerChar = bytesPerChar || defaults.bytesPerChar;

        if(typeof bytesPerChar !== 'number' || bytesPerChar%1 !== 0 || bytesPerChar<1 || bytesPerChar > defaults.maxBytesPerChar){
            throw new Error('Bytes per character must be an integer between 1 and ' + defaults.maxBytesPerChar + ', inclusive.')
        }

        var hexChars = 2*bytesPerChar;
        var max = Math.pow(16, hexChars) - 1;
        var out = '', num;
        for(var i=0, len=str.length; i<len; i++){
            num = str[i].charCodeAt();
            if(isNaN(num)){
                throw new Error('Invalid character: ' + str[i]);
            }else if(num > max){
                var neededBytes = Math.ceil(Math.log(num+1)/Math.log(256));
                throw new Error('Invalid character code (' + num +'). Maximum allowable is 256^bytes-1 (' + max + '). To convert this character, use at least ' + neededBytes + ' bytes.')
            }else{
                out = padLeft(num.toString(16), hexChars) + out;
            }
        }
        return out;
    };

    // Converts a given HEX number string to a UTF16 character string.
    function hex2str(str, bytesPerChar){
        if(typeof str !== 'string'){
            throw new Error('Input must be a hexadecimal string.');
        }
        bytesPerChar = bytesPerChar || defaults.bytesPerChar;

        if(typeof bytesPerChar !== 'number' || bytesPerChar%1 !== 0 || bytesPerChar<1 || bytesPerChar > defaults.maxBytesPerChar){
            throw new Error('Bytes per character must be an integer between 1 and ' + defaults.maxBytesPerChar + ', inclusive.')
        }

        var hexChars = 2*bytesPerChar;
        var out = '';
        str = padLeft(str, hexChars);
        for(var i=0, len = str.length; i<len; i+=hexChars){
            out = String.fromCharCode(parseInt(str.slice(i, i+hexChars),16)) + out;
        }
        return out;
    };

    // RKTODO: Move below out to separate string encoding js
    // RKTODO: Get a code review of ASCII 7-bit stuff, do some unit testing on different-endianned machine, verify dependencies like
    //         parseInt, toString(, 2), etc. don't do any tricks under the hood that haven't been accounted for.
    // RKTODO: Maybe all this BOM stuff was overkill.  Could just use an FF marker (ASCII7 "{DEL}") to denote UTF16 and save
    //         foreign users some bits.  Or be dynamic; measure maximum character and use first 4 bits to tell you how many bits to
    //         use per character.  Could offset ASCII table so simple english passphrases (made up of only letters, numbers and the
    //         2 most popular symbols) would only take up 6 bits per letter.

    // UTF-16 Byte Order Marker and corresponding bit representations (both big / little endian)
    const BOM          = [0xFF, 0xFE];
    const BOM_BITS     = BOM[0].toString(2) + BOM[1].toString(2); // 1111111111111110
    const BOM_REV_BITS = BOM[1].toString(2) + BOM[0].toString(2); // 1111111011111111
    const MAX_BITS_PER_CHAR = 32; // generic str2bin and bin2str accomodate up to UTF-32

    function encodeStr(str){
        var out;
        var ascii = isCompatibleASCII(str);
        var bitsPerChar = ascii ? 7 : 16;
        out = str2bin(str, bitsPerChar);
        if (!ascii) {
            out = BOM_BITS + out;
        }
        return out;
    }

    function decodeStr(bin){
        var bitsPerChar;
        if(detectUTF16(bin)){ // throws an error if invalid or can't detect
            bitsPerChar = 16;
            bin = bin.substring(BOM_BITS.length); // drop the UTF-16 indicator
        }else{
            bitsPerChar = 7;
        }
        if (bin.length % bitsPerChar != 0){
            throw new Error('Binary string is not the expected length')
        }
        return bin2str(bin, bitsPerChar);
    }

    // Returns true if the blob begins with a big-endian BOM and looks like UTF-16.
    // Returns false if it looks like 7-bit ASCII.
    // Throws an error if it doesn't look like either.
    function detectUTF16(bin){
        // Detect Unicode
        if (bin.length >= BOM_BITS.length) {
            if (bin.startsWith(BOM_BITS)) {
                // Treat as UTF-16
                if ((bin.length - BOM_BITS.length) % 16 != 0) {
                    throw new Error('Corrupt UTF-16 content detected');
                } else {
                    return true;
                }
            } else if (bin.startsWith(BOM_REV_BITS)) {
                throw new Error('Reversed UTF-16 byte order marker detected');
            }
        }
        // Treat as 7-bit ASCII
        if (bin.length % 7 != 0) {
            throw new Error('Unable to decode corrupted text');
        }
        return false;
    }

    // Checks if given string consists solely of ASCII characters (excluding extended; i.e. just 0 through 127)
    function isASCII(str){
        for(var i=0; i<str.length; i++){
            if(str.charCodeAt(i) > 127){
                return false;
            }
        }
        return true;
    }

    // Verifies the given string can be encoded into 7-bit ASCII characters without resulting in a binary
    // sequence that's ambiguous to decode.
    function isCompatibleASCII(str){
        // Here's how various byte order markers would look if read from a binary blob and interpreted as 7-bit ASCII:
        // ORIGINAL ENCODING        BYTES    BITS (SEPTETS)                DECODED TO ASCII 7-BIT
        // UTF-16 (big endian)      FEFF     1111111 0111111 11            "{DEL}{?}" + exta 2 bits
        // UTF-16 (little endian)   FFFE     1111111 1111111 10            "{DEL}{DEL}" + extra 2 bits
        // UTF-8                    EFBBBF   1110111 1101110 1110111 111   "wnw" + extra 3 bits
        // Generate the ASCII characters BOM would decode to
        var bom1 = parseInt(BOM_BITS.substring(0, 7), 2);
        var bom2 = parseInt(BOM_BITS.substring(7, 14), 2);
        var bom_asc = String.fromCharCode(bom1) + String.fromCharCode(bom2);
        var bom_rev_asc = String.fromCharCode(bom2) + String.fromCharCode(bom1);
        if (!isASCII(str)) return false;
        if (str.startsWith(bom_asc) || str.startsWith(bom_rev_asc)) return false;
        return true;
    }

    // Converts a given UTF16 character string to its binary representation.
    // Each character of the input string is represented by `bitsPerChar` bits in the output string.
    function str2bin(str, bitsPerChar){
        validateStr(str, "Input", undefined, undefined, 'a text string');
        validateInt(bitsPerChar, 'Bits per character', 1, MAX_BITS_PER_CHAR);
        var max = Math.pow(2, bitsPerChar) - 1; // e.g. evaluates to 127 for 7-bit ASCII
        var out = '', num;
        for(var i=0; i<str.length; i++){
            num = str.charCodeAt(i);
            if(isNaN(num)){
                throw new Error('Invalid character: ' + str[i]);
            }else if(num > max){
                var neededBits = Math.ceil(Math.log(num+1)/Math.log(2));
                throw new Error('Invalid character code (' + num + '). Maximum allowable is 2^bits-1 (' + max + '). ' +
                                'To convert this character, use at least ' + neededBits + ' bits.')
            }else{
                out += lpad(num.toString(2), bitsPerChar);
            }
        }
        return out;
    }

    // Converts a given binary character string to a UTF16 character string.
    function bin2str(bin, bitsPerChar){
        validateStr(bin, "Input", undefined, undefined, 'a binary string');
        validateInt(bitsPerChar, 'Bits per character', 1, MAX_BITS_PER_CHAR);
        var out = '';
        bin = padLeft(bin, bitsPerChar);
        for(var i=0; i<bin.length; i+=bitsPerChar){
            out += String.fromCharCode(parseInt(bin.slice(i, i+bitsPerChar), 2));
        }
        return out;
    }

    //function reverseStr(str){
    //    return str.split('').reverse().join('');
    //}

    // Validates given value is an integer, with optional min / max limits.
    // Throws an error if num is invalid, otherwise permits execution to continue.
    // param should be the parameter name or a short, human-readable description of what represents.
    function validateInt(num, param, min, max){
        if (typeof min === 'undefined') min = undefined;
        if (typeof max === 'undefined') max = undefined;
        var msg = param + ' must be an integer';
        if      (min !== undefined && max !== undefined) msg += ' between ' + min + ' and ' + max + ', inclusive';
        else if (min !== undefined && max === undefined) msg += ' greater than or equal to ' + min;
        else if (min === undefined && max !== undefined) msg += ' less than or equal to ' + max;
        if(typeof num !== 'number' || num%1 !== 0 || min !== undefined && num<min || max !== undefined && num>max){
            throw new Error(msg)
        }
    }

    // Validates given value is a string, with optional min / max length.
    // Throws an error if str is invalid, otherwise permits execution to continue.
    // param should be the parameter name or a short, human-readable description of what represents.
    // desc can optionally be a short, human-readable description of the intended content.
    function validateStr(str, param, min, max, desc){
        if (typeof min === 'undefined') min = undefined;
        if (typeof max === 'undefined') max = undefined;
        if (typeof desc === 'undefined') desc = undefined;
        var msg = param + ' must be ' + (desc === undefined ? 'a string' : desc);
        var len = str.length;
        if      (min !== undefined && max !== undefined && min == max)
                                                         msg += ' exactly ' + min + ' characters long';
        if      (min !== undefined && max !== undefined) msg += ' between ' + min + ' and ' + max + ' characters long, inclusive';
        else if (min !== undefined && max === undefined) msg += ' of at least ' + min + ' characters';
        else if (min === undefined && max !== undefined) msg += ' of no more than ' + max + ' characters';
        if(typeof str !== 'string' || min !== undefined && len<min || max !== undefined && len>max){
            throw new Error(msg)
        }
    }

    // Polyfill for older browsers (https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/String/startsWith#Polyfill)
    if(!String.prototype.startsWith){
        String.prototype.startsWith = function(searchString, position){
            return this.substr(position || 0, searchString.length) === searchString;
        };
    }

    init(12); // 12 bits = 4096-1 shares maximum

}
