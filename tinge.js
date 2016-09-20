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
	@end-module-documentation

	@include:
		{
			"_": "lodash",
			"crypto": "crypto",
			"hashid": "hashids",
			"lzString": "lz-string",
			"secret": "secrets.js",
			"U200b": "u200b"
		}
	@end-include
*/

var _ = require( "lodash" );
var crypto = require( "crypto" );
var hashid = require( "hashids" );
var lzString = require( "lz-string" );
var secret = require( "secrets.js" );
var U200b = require( "u200b" );

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
		setting = lzString.decompress( setting );
		setting = U200b( setting ).separate( );

		var copy = setting[ 0 ];
		var index = parseInt( setting[ 1 ] );
		var last = parseInt( setting[ 2 ] );
		var salt = setting[ 3 ];
		var dictionary = setting[ 4 ];

		copy = copy.substring( index, last );

		if( copy == code ){
			var generator = new hashid( salt, 0, dictionary );
			var raw = generator.decodeHex( code );

			var sample = U200b( raw ).separate( );

			var hash = secret.combine( sample );

			option.hash = hash;

		}else{
			throw new Error( "invalid code" );
		}

	}else{
		var factor = option.factor;
		var length = option.length;
		var indexed = option.indexed;
		var salt = option.salt;

		var hash = crypto.createHash( "sha512" );
		hash.update( JSON.stringify( _.compact( factor ) ) );
		hash = hash.digest( "hex" );

		var share = secret.share( hash, factor.length, 2 );
		var sample = _.sampleSize( share, 2 );

		var raw = U200b( sample[ 0 ].toString( ), sample[ 1 ].toString( ) ).toString( );
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

			trace = [ trace, index, last ].join( "" );
		}

		option.code = trace;
		option.setting = setting;
	}

	return option;
};

module.exports = tinge;
