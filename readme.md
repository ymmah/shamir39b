# Shamir39b Tool

An EXPERIMENTAL tool for converting BIP39 mnemonic phrases to shamir secret sharing scheme parts whilst retaining the benefit of mnemonics.
Please don't use this tool for real.  It's under development and THINGS WILL BREAK.

## Online Version

https://rkagerer.github.io/shamir39b/standalone.html

## Standalone offline version

Download `standalone.html`

Open the file in a browser by double clicking it.

This can be compiled from source using the command `python compile.py`

## Original Version (under active development)

https://iancoleman.github.io/shamir39/

## Usage

TODO

## Donations

Since this project is the efforts of many people, most of which don't appear in
the obvious places like code or issues, donating to the project itself causes
significant operational difficulties.

As a result, if you would like to support this project financially you are
encouraged to donate to one of the many groups that makes the internet a place
amenable to projects such as this one.

[Donation-accepting organizations and projects](https://en.bitcoin.it/wiki/Donation-accepting_organizations_and_projects)

If the list is too difficult to choose from, the EFF is a good choice.

[Electronic Frontier Foundation](https://supporters.eff.org/donate)

or for a direct bitcoin address, consider donating to the
[Free Software Foundation](https://www.fsf.org/about/ways-to-donate/)
at 1PC9aZC4hNX2rmmrt7uHTfYAS3hRbph4UN

![alt text](https://static.fsf.org/nosvn/images/bitcoin_qrcodes/fsf.png "FSF Bitcoin Address")

## Making changes

Please do not make modifications to `standalone.html`, since they will
be overwritten by `compile.py`.

Make changes in `src/*` and apply them using the command `python compile.py`

# Tests

TODO

# License

This Shamir39b tool is released under the terms of the MIT license. See LICENSE for
more information or see https://opensource.org/licenses/MIT.
