"use strict";

/*;
	@module-license:
		The MIT License (MIT)
		@mit-license

		Copyright (@c) 2016 Richeve Siodina Bebedor
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
			"harden": "harden",
			"hashid": "hashids",
			"lzString": "lz-string",
			"secret": "secrets.js",
			"U200b": "u200b",
			"uuid": "node-uuid"
		}
	@end-include
*/

var _ = require( "lodash" );
var crypto = require( "crypto" );
var doubt = require( "doubt" );
var harden = require( "harden" );
var hashid = require( "hashids" );
var lzString = require( "lz-string" );
var secret = require( "secrets.js" );
var U200b = require( "u200b" );
var uuid = require( "node-uuid" );

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
var tinge = function tinge( option ){
	/*;
		@meta-configuration:
			{
				"option:required": "object"
			}
		@end-meta-configuration
	*/

	var code = option.code;
	var setting = option.setting;

	if( code && setting ){
		if( typeof code != "string" ){
			throw new Error( "invalid code" );
		}

		if( typeof setting != "string" ){
			throw new Error( "invalid setting" );
		}

		tinge.clear( code );

		var trace = U200b( code ).separate( );
		code = trace[ 0 ] || code;

		setting = lzString.decompress( setting );
		setting = U200b( setting ).separate( );

		var copy = setting[ 0 ];
		var index = parseInt( setting[ 1 ] );
		var last = parseInt( setting[ 2 ] );
		var salt = setting[ 3 ];
		var dictionary = setting[ 4 ];

		if( !copy ||
			isNaN( index ) ||
			isNaN( last ) ||
			!salt ||
			!dictionary )
		{
			throw new Error( "invalid setting" );
		}

		copy = copy.substring( index, last );

		if( copy == code ){
			var generator = new hashid( salt, 0, dictionary );
			var raw = generator.decodeHex( setting[ 0 ] );

			var sample = U200b( raw ).separate( );

			var hash = secret.combine( sample );

			if( option.hash ){
				throw new Error( "hash already exists" );
			}

			harden( "hash", hash, option );

		}else{
			throw new Error( "invalid code" );
		}

	}else{
		var factor = option.factor;

		if( !factor ){
			throw new Error( "factor not given" );
		}

		if( !doubt( factor ).ARRAY ){
			throw new Error( "invalid factor" );
		}

		var length = option.length || 12;

		var salt = option.salt || tinge.SALT;

		if( typeof salt != "string" ){
			throw new Error( "invalid salt" );
		}

		var dictionary = option.dictionary || tinge.DICTIONARY;

		if( typeof dictionary != "string" ){
			throw new Error( "invalid dictionary" );
		}

		var indexed = option.indexed;

		if( indexed && length < 12 ){
			throw new Error( "invalid length on indexed mode" );
		}

		var hash = crypto.createHash( "sha512" );
		hash.update( JSON.stringify( _.compact( factor ) ) );
		hash = hash.digest( "hex" );
		harden( "hash", hash, option );

		var share = secret.share( hash, factor.length, 2 );
		var sample = _.sampleSize( share, 2 );

		var raw = U200b( sample[ 0 ].toString( ), sample[ 1 ].toString( ) )
			.base( U200B_BASE16 ).toString( );
		var generator = new hashid( salt, 0, dictionary );
		var code = generator.encodeHex( raw );

		if( indexed ){
			length = length - 6;
		}

		var index = Math.floor( ( code.length - length ) * Math.random( ) );
		var last = index + length;

		var setting = U200b( [ code, index, last, salt, dictionary ] ).toString( );

		setting = lzString.compress( setting );

		var trace = code.substring( index, last );

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

	tinge.timeout.push( setTimeout( function onTimeout( ){
		for( var code in tinge.cache ){
			delete tinge.cache[ code ];
		}

		while( tinge.timeout.length ){
			clearTimeout( tinge.timeout.pop( ) );
		}
	} ), 1000 * ( tinge.timeout.length || 1 ) );

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
