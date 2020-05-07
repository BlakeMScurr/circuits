include "../node_modules/circomlib/circuits/babyjub.circom";
include "../node_modules/circomlib/circuits/comparators.circom";
include "../node_modules/circomlib/circuits/poseidon.circom";
include "../node_modules/circomlib/circuits/bitify.circom";
include "./utils.circom";

// For now SubjectPos is set to Index
// template BuildClaimSubjectOtherIden() {
// 	signal input claimType
// 	signal input id;
// 
// 	signal output hi;
// 	signal output hv;
// 
// 	component e0 = Bits2Num(256);
// 	var claimType[64];
// 	claimType = bigEndian(_claimType, 64);
// 	for (var i=0; i<64; i++) {
// 		e0.in[i] <== claimType[i];
// 	}
// 	for (var i=64; i<256; i++) {
// 		e0.in[i] <== 0;
// 	}
// 
// 	// Hi
// 	component hashHi = Poseidon(2, 6, 8, 57);
// 	hashHi.inputs[0] <== e0.out;
// 	hashHi.inputs[1] <== id;
// 	hi <== hashHi.out;
// 
// 	// Hv
// 	component hashHv = Poseidon(1, 6, 8, 57);
// 	hashHv.inputs[0] <== 0;
// 	hv <== hashHv.out;
// }

// template Test() {
// 	signal input claim[2][4];
// }
// 
// template getClaimNonce() {
// 	signal input claim[2][4];
// 	signal output nonce;
// }
// 
// template getClaimType() {
// 	signal input claim[2][4];
// 	signal output claimType;
// }

// index: bool.  0 if SubjectPos is Index, 1 if SubjectPos is Value
template getClaimSubjectOtherIden(index) {
	signal input claim[8];
	signal input claimFlags[32]; // claimFlags must be parsed from the claim

	signal output id;

	// Assert that claim subject is OtherIden
	// flags[0:2] == [0, 1]: Subject == OtherIden
	claimFlags[0] === 0;
	claimFlags[1] === 1;
	// flags[2] == 0 / 1: SubjectPos == Index / Value
	claimFlags[2] == index;

	if (index == 0) {
		id <== claim[0*4 + 1];
	} else {
		id <== claim[1*4 + 1];
	}
}

template getClaimHeader() {
	signal input claim[8];

	signal output claimType;
	signal output claimFlags[32]

 	component i0Bits = Num2Bits(256);
	i0Bits.in <== claim[0*4 + 1]

	component claimTypeNum = Bits2Num(64);

	for (var i=0; i<64; i++) {
		claimTypeNum.in[i] <== i0Bits.out[i];
	}
	claimType <== claimTypeNum.out;

	for (var i=0; i<32; i++) {
		claimFlags[i] <== i0Bits.out[64 + i];
	}
}

template getClaimRevNonce() {
	signal input claim[8];

	signal output revNonce;

	component claimRevNonce = Bits2Num(32);

 	component v0Bits = Num2Bits(256);
	v0Bits.in <== claim[1*4 + 1]
	for (var i=0; i<32; i++) {
		claimRevNonce.in[i] <== v0Bits.out[i];
	}
	revNonce <== claimRevNonce.out;
}

template getClaimHiHv() {
	signal input claim[8];

	signal output hi;
	signal output hv;

	component hashHi = Poseidon(6, 6, 8, 57);
	for (var i=0; i<4; i++) {
		hashHi.inputs[0] <== claim[0*4 + i];
	}
	hashHi.inputs[4] <== 0;
	hashHi.inputs[5] <== 0;
	hi <== hashHi.out;

	component hashHv = Poseidon(6, 6, 8, 57);
	for (var i=0; i<4; i++) {
		hashHv.inputs[0] <== claim[1*4 + i];
	}
	hashHv.inputs[4] <== 0;
	hashHv.inputs[5] <== 0;
	hv <== hashHv.out;
}

template test() {
	signal input claim[8];

	component header = getClaimHeader();
	for (var i=0; i<8; i++) { header.claim[i] <== claim[i]; }
	// header.claimType
	// header.claimFlags[32]

	component subjectOtherIden = getClaimSubjectOtherIden(0);
	for (var i=0; i<8; i++) { subjectOtherIden.claim[i] <== claim[i]; }
	for (var i=0; i<32; i++) { subjectOtherIden.claimFlags[i] <== header.claimFlags[i]; }
	// subjectOtherIden.id

	component claimRevNonce = getClaimRevNonce();
	for (var i=0; i<8; i++) { claimRevNonce.claim[i] <== claim[i]; }
	// claimRevNonce.revNonce

	component claimHiHv = getClaimHiHv();
	for (var i=0; i<8; i++) { claimHiHv.claim[i] <== claim[i]; }
	// claimHiHv.hi
	// claimHiHv.hv
}

// component main = getClaimSubjectOtherIden(0);
component main = test();
