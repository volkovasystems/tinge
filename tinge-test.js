"use strict";

const tinge = require( "./tinge.js" );

for( let index=0; index < 3; index++ ) {

	let data1 = {
		"factor": [
			"ballpen-item",
			"Ballpen Item"
		],
		"indexed": true
	};

	let encoded = tinge( data1 );

	console.log( "encoded", encoded );

	if( !encoded ) {

		console.log( "not encoded" );
	}else{

		let data2 = {
			"code": encoded.code,
			"setting":encoded.setting
		};

		let decoded = tinge( data2 );

		console.log( "decoded", decoded );

	}

}
