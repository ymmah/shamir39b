# Shamir Mnemonics Specification (shamir39b)

# DRAFT

## Motivation

BIP39 mnemonics provide a simple, human-readable backup of an entire wallet. But a challenge to securely storing the backup is that anyone with a copy of the mnemonic gains access to the funds.

[Shamir's Secret Sharing Scheme](https://en.wikipedia.org/wiki/Shamir%27s_Secret_Sharing) (SSSS) alleviates this risk by securely dividing sensitive data into pieces which can be distributed among trusted parties such that several must be combined to reconstruct the original message. But with existing tooling, the benefit of using human readable words is lost as the output is typically encoded into sequences of hexadecimal "gibberish".

This proposal is a way to split a BIP39 mnemonic into pieces via SSSS while maintaining the benefits of the original mnemonic encoding. This is achieved by encoding the SSSS shares themselves as mnemonics, which can then be distributed to others with reduced risk of private keys being exposed or lost if one or a few shares are compromised or misplaced.

## Version

This specification, referred to as "shamir39b", is a modification to the original [shamir39](https://github.com/iancoleman/shamir39/blob/master/specification.md) specification proposed by Ian Coleman.  It adds the ability to include freeform text alongside the original wallet seed mnemonic, which can be used for storing a passphrase ("25th" seed word), safe code, or other small amount of secret information which will be revealed when the pieces are combined.

## Operation

The original BIP39 mnemonic you type in is converted to its binary representation.

A 5 bit prefix is constructed as follows:

- First 2 bits: Indicates number of padding bits.
- Next 3 bits: Indicates number of mnemonic words present, as follows: 000 = 0 words, 001 = 12 words, 010 = 15 words, 011 = 18 words, 100 = 21 words, 101 = 24 words.  i.e. 0 for none, otherwise # words = value * 3 + 9.  For now, values of 110 and 111 are reserved).

Next come the padding bits (between zero and 3 of them).  These are required to ensure the secret ends on a 4-bit boundary suitable for conversion to hexadecimal format.

Then the bits corresponding to the mnemonic you are splitting (exactly 11 bits per word).

Finally, the remaining bits are the passphrase (if there is one).  If you only used ASCII characters (0 to 127) they are encoded as 7 bits per character.  If you used any characters outside of this range, then the passphrase instead begins with a standard UTF-16 Byte Order Marker (0xFF 0xFE) followed by 16 bits per character in your passphrase.

All of the bits above make up your secret, which is converted to hex and fed into an SSSS algorithm to create shares.

The generated shares are then wrapped with some additional indicators to aid in reconstruction (below) and finally converted to BIP39 mnemonics.

No additional checkdigits are implemented at present, but it's being discussed.

The structure used in Shamir39b was hacked together in a hurry and will likely change.

## Share Components

Each share produced consists of 3 components: Version, Parameters, and the Shamir Share.

The encoded components are concatenated together to form a Shamir Mnemonic.

### First Component is Version

The first component is the single word shamir39b.

This prevents mixing incompatible mnemonics and allows upgrading the implementation in the future.

### Second Component is Parameters

The second component specifies the parameters of Shares Required (M) and Share Ordering (O).

It may be encoded to multiple words.

The first bit of the 11 bits of the word indicates if this is the final word used to encode the parameters. A first bit value of 0 indicates this is final word, 1 means continue parsing words.

The next five bits of each word give M

The last five bits of each word give the Order of this share

If the parameters span multiple words, concatenate the bits together to form M and O

#### Example decoding parameters in a single word

'amused' is index 65 in the English wordlist. This translates to binary 00001000001 left-padded to 11 bits.

00001000001 is parsed into parameters as

```
0      00010  00001
Final  M      O
```

The leading zero indicates this is the final word encoding the parameters.

The next five bits give M; M = 00010 = 2, ie 2 shares are required to reconstruct the secret.

The next five bits give O; O = 00001 = 1; ie this should be ordered after share with O=0 but before share with O=2.

#### Example encoding parameters across multiple words

```
Consider
M = 35 = 100011
O = 10 = 1010

Left pad both to multiple of 5 bits

M = 0000100011
O = 0000001010

Split into groups of 5 bits

M = 00001 00011
O = 00000 01010

Convert this into mnemonic words:

The first word is not the final word so it:
- starts with 1
- then has the first five bits of M
- then has the first five bits of O

1 00001 00000 = 10000100000 = 1056 = "lottery"

The second word is the final word so it:
- starts with 0
- then has the second five bits of M
- then has the second five bits of O

0 00011 01010 = 00001101010 = 106 = "ask"

So the parameters M = 35 and O = 10 are encoded as "lottery ask"
```

### Third Component is The Shamir Share

The third component is the data for the shamir share and is a binary blob which must be encoded to mnemonic words.

The binary shamir share is encoded to mnemonic words by:

- left pad the binary share to multiple of 11 bits
- 3 of the extra 4 bits record how many triplets of words are in the secret mnemonic (0 = 3, 1 = 6, ...., 7 = 24)
- convert each group of 11 bits to the corresponding word in the wordlist

The mnemonic words are decoded to the binary shamir share by:

- convert each word to the 11 bit binary representation and concatenate together
- truncate from the left to the required multiple for the specific shamir implementation (in the case of the prototype it's 4 bits)

## Alternatives

The [original Shamir39](https://github.com/iancoleman/shamir39) scheme is probably more actively developed / supported.

A scheme such as BIP45 (HD multisig wallets) targets separation of secrets at the transaction layer, whereas this proposal targets the key storage layer. Multisig wallets have the benefit of not requiring the secrets to be merged, ie a transaction can be signed progressively in isolation by each party until enough signatures have been accumulated to broadcast the transaction. In contrast, SSSS requires parties to combine their secrets into a single secret, which must then be handled by a 'leader' of the group to finally sign any transactions using the combined secret.

## Testing

### Initial Data

Original mnemonic:

```
what secret hair silly plate web thank purchase oxygen smart pass town
```

Original passphrase:

```
Thundertown
```

Split into 3-of-5.  Resulting parts (presented in correct order):

```
shamir39b army assume veteran east report thrive amount fade arrow obey energy wagon title cushion deer clever lava woman abandon push settle scheme

shamir39b around barrel angle mirror artwork limb also february undo hidden energy team pupil lend puppy song combine protect seminar auction oil pitch

shamir39b arrange busy toddler cradle junk anger side photo blush cash purchase repeat logic truck illegal equal essence twin vapor damage crane body

shamir39b arrest accident intact together coach belt spy tunnel gown banana ship feel sausage issue lawsuit morning veteran flash orbit window later elder

shamir39b arrive arrive owner garlic flee outside become buddy mule foam captain devote mushroom there patrol art near cabbage poverty secret strategy when
```

### Tests

* Splitting:
    * The original mnemonic and passphrase can be split into multiple shares
    * None of the shares are identical to the original mnemonic
    * Each share starts with the version 'shamir39b'
* Combining: Shares 1, 2 and 3 combine to the original mnemonic and passphrase
* Ordering: Shares 5, 4 and 3 combine to the original mnemonic and passphrase
* Not enough shares: The original cannot be recovered with only 2 shares
* Unicode / foreign-language characters supported
* Empty mnemonic supported (for just splitting a passphrase or whatever arbitrary text)

### Further Tests TBD

* Large number of shares (ie greater than 32)
* Encoding of parameters across multiple words
* Upper limit of shares (in the prototype implementation it's 4095)
* More...

### Advantages

- Put all the secret codes your heirs need to recover your wallet in a single place.  Eliminates confusion that might occur if you were to apply Shamir Sharing separately to the seed and passphrase and make them figure out which ones need to be combined in which groupings.

## Disadvantages

- It's possible to infer rough information about the size of your secret (i.e. lots of words in the shares indicates existence of a passphrase).  In other words, you need to have some basic trust in the people to whom you distribute the shares.  Also compromises deniability.
- You are keeping the wallet seed and passphrase tied together (i.e. if one is compromised the other probably will be as well) which may not be good depending on your security stance.

## Example Implementation

Web app - https://rkagerer.github.io/shamir39b/standalone.html

Library and source code - refer to Ian's original https://github.com/iancoleman/shamir39/ from which this project is forked - see src/js/shamirMnemonic.js

## References

[Shamir's Secret Sharing](https://en.wikipedia.org/wiki/Shamir%27s_Secret_Sharing)
[BIP39 Mnemonic](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki)
