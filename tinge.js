"use strict";

/*;
	@module-license:
		The MIT License (MIT)
		@mit-license

		Copyright (@c) 2017 Richeve Siodina Bebedor
		@email: richeve.bebedor@gmail.com

		Permission is hereby granted, free of charge, to any person obtaining a copy
		of this software and associated documentation files (the "Software"), to deal
		in the Software without restriction, including without limitation the rights
		to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
		copies of the Software, and to permit persons to whom the Software is
		furnished to do so, subject to the following conditions:

		The above copyright notice and this permission notice shall be included in all
		copies or substantial portions of the Software.

		THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
		IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
		FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
		AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
		LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
		OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
		SOFTWARE.
	@end-module-license

	@module-configuration:
		{
			"package": "tinge",
			"path": "tinge/tinge.js",
			"file": "tinge.js",
			"module": "tinge",
			"author": "Richeve S. Bebedor",
			"contributors": [
				"John Lenon Maghanoy <johnlenonmaghanoy@gmail.com>"
			],
			"eMail": "richeve.bebedor@gmail.com",
			"repository": "https://github.com/volkovasystems/tinge.git",
			"test": "tinge-test.js",
			"global": true
		}
	@end-module-configuration

	@module-documentation:
		Support both encoding and decoding.
	@end-module-documentation

	@include:
		{
			"_": "lodash",
			"crypto": "crypto",
			"doubt": "doubt",
			"falze": "falze",
			"harden": "harden",
			"hashid": "hashids",
			"lzString": "lz-string",
			"numric": "numric",
			"secret": "secrets.js",
			"snapd": "snapd",
			"truu": "truu",
			"U200b": "u200b",
			"uuid": "node-uuid"
		}
	@end-include
*/

const _ = require( "lodash" );
const crypto = require( "crypto" );
const doubt = require( "doubt" );
const falze = require( "falze" );
const harden = require( "harden" );
const hashid = require( "hashids" );
const lzString = require( "lz-string" );
const numric = require( "numric" );
const protype = require( "protype" );
const secret = require( "secrets.js" );
const snapd = require( "snapd" );
const truu = require( "truu" );
const U200b = require( "u200b" );
const uuid = require( "node-uuid" );

/*;
	@option:
		{
			"code:required": "string",
			"setting:required": "string"
		},
		{
			"factor:required": "[string]",
			"length": "number",
			"salt": "string",
			"dictionary": "string"
		}
	@end-option
*/
const tinge = function tinge( option ){
	/*;
		@meta-configuration:
			{
				"option:required": "object"
			}
		@end-meta-configuration
	*/

	let code = option.code;
	let setting = option.setting;

	if( truu( code ) && truu( setting ) ){
		if( !protype( code, STRING ) ){
			throw new Error( "invalid code" );
		}

		if( !protype( setting, STRING ) ){
			throw new Error( "invalid setting" );
		}

		tinge.clear( code );

		let trace = U200b( code ).separate( );
		code = trace[ 0 ] || code;

		setting = lzString.decompress( setting );
		setting = U200b( setting ).separate( );

		let copy = setting[ 0 ];
		let salt = setting[ 3 ];
		let dictionary = setting[ 4 ];

		if( falze( copy ) || falze( salt ) || falze( dictionary ) ){
			throw new Error( "invalid setting" );
		}

		let index = setting[ 1 ];
		if( truu( index ) && numric( index ) ){
			index = parseInt( index );

		}else{
			throw new Error( "invalid index" );
		}

		let last = setting[ 2 ];
		if( truu( last ) && numric( last ) ){
			last = parseInt( last );

		}else{
			throw new Error( "invalid last index" );
		}

		copy = copy.substring( index, last );

		if( copy == code ){
			let generator = new hashid( salt, 0, dictionary );
			let raw = generator.decodeHex( setting[ 0 ] );

			let sample = U200b( raw ).separate( );

			let hash = secret.combine( sample );

			if( option.hash ){
				throw new Error( "hash already exists" );
			}

			harden( "hash", hash, option );

		}else{
			throw new Error( "invalid code" );
		}

	}else{
		let factor = option.factor;

		if( falze( factor ) ){
			throw new Error( "factor not given" );
		}

		if( !doubt( factor ).ARRAY ){
			throw new Error( "invalid factor" );
		}

		let length = option.length || 12;

		let salt = option.salt || tinge.SALT;

		if( !protype( salt, STRING ) ){
			throw new Error( "invalid salt" );
		}

		let dictionary = option.dictionary || tinge.DICTIONARY;

		if( !protype( dictionary, STRING ) ){
			throw new Error( "invalid dictionary" );
		}

		let indexed = option.indexed;

		if( indexed && !protype( indexed, BOOLEAN ) ){
			throw new Error( "invalid indexed flag" );
		}

		if( indexed && length < 12 ){
			throw new Error( "invalid length on indexed mode" );
		}

		let hash = crypto.createHash( "sha512" );
		hash.update( JSON.stringify( _.compact( factor ) ) );
		hash = hash.digest( "hex" );
		harden( "hash", hash, option );

		let share = secret.share( hash, factor.length, 2 );
		let sample = _.sampleSize( share, 2 );

		let raw = U200b( sample[ 0 ].toString( ), sample[ 1 ].toString( ) )
			.base( U200B_BASE16 ).toString( );
		let generator = new hashid( salt, 0, dictionary );
		let code = generator.encodeHex( raw );

		if( indexed ){
			length = length - 6;
		}

		let index = Math.floor( ( code.length - length ) * Math.random( ) );
		let last = index + length;

		let setting = U200b( [ code, index, last, salt, dictionary ] ).toString( );

		setting = lzString.compress( setting );

		let trace = code.substring( index, last );

		if( indexed ){
			index = _.padStart( index, 3, 0 );
			last = _.padStart( last, 3, 0 );

			trace = U200b( trace, index, last ).toString( );
		}

		if( trace in tinge.cache ){
			return tinge( {
				"factor": option.factor,
				"length": option.length,
				"dictionary": option.dictionary,
				"salt": option.salt
			} );
		}

		tinge.clear( trace );

		option.code = trace;
		option.setting = setting;
	}

	return option;
};

harden.bind( tinge )( "clear", function clear( trace ){
	if( trace in tinge.cache ){
		return tinge;
	}

	tinge.cache[ trace ] = true;

	if( tinge.timeout.length >= 60 ){
		return tinge;
	}

	tinge.timeout.push( snapd( function onClear( ){
		for( let code in tinge.cache ){
			delete tinge.cache[ code ];
		}

		while( tinge.timeout.length ){
			clearTimeout( tinge.timeout.pop( ) );
		}
	}, 1000 * 60 * ( tinge.timeout.length || 1 ) ).timeout );

	return tinge;
} );

harden.bind( tinge )( "timeout", [ ] );

harden.bind( tinge )( "cache", { } );

harden.bind( tinge )( "SALT", uuid.v4( ) );

harden.bind( tinge )( "DICTIONARY", [
	"ABCDEFGHIJKLMNOPQRSTUVWXYZ",
	"abcdefghijklmnopqrstuvwxyz",
	"0123456789"
].join( "" ) );

module.exports = tinge;
