import {describe} from "mocha";

const path = require("path");
const wasm_tester = require("circom_tester").wasm;
const chai = require("chai");
const assert = chai.assert;

export {};

describe("Test claim query NOTIN operation", function () {

    this.timeout(600000);

    let circuit;

    before(async () => {
        circuit = await wasm_tester(
            path.join(__dirname, "../circuits/query", "credentialAtomicQueryMTPTest.circom"),
            {
                output: path.join(__dirname, "circuits", "build"),
                recompile: true,
                reduceConstraints: false,
            },
        );

    });

    after(async () => {
        circuit.release()
    })


    it("credentialAtomicQueryMTPTest", async () => {

        // inputs MUST be generated by GO-CIRCUITS library https://github.com/iden3/go-circuits (using corresponding test)
        const inputs = {
            "userAuthClaim": ["269270088098491255471307608775043319525", "0", "17640206035128972995519606214765283372613874593503528180869261482403155458945", "20634138280259599560273310290025659992320584624461316485434108770067472477956", "15930428023331155902", "0", "0", "0"],
            "userAuthClaimMtp": ["0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0"],
            "userAuthClaimNonRevMtp": ["0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0"],
            "userAuthClaimNonRevMtpAuxHi": "0",
            "userAuthClaimNonRevMtpAuxHv": "0",
            "userAuthClaimNonRevMtpNoAux": "1",
            "challenge": "1",
            "challengeSignatureR8x": "8553678144208642175027223770335048072652078621216414881653012537434846327449",
            "challengeSignatureR8y": "5507837342589329113352496188906367161790372084365285966741761856353367255709",
            "challengeSignatureS": "2093461910575977345603199789919760192811763972089699387324401771367839603655",
            "issuerClaim": ["3677203805624134172815825715044445108615", "286312392162647260160287083374160163061246635086990474403590223113720496128", "10", "0", "30803922965249841627828060161", "0", "0", "0"],
            "issuerClaimClaimsTreeRoot": "12781049434766209895790529815771921100011665835724745028505992240548230711728",
            "issuerClaimIdenState": "20606705619830543359176597576564222044873771515109680973150322899613614552596",
            "issuerClaimMtp": ["0", "3007906543589053223183609977424583669571967498470079791401931468580200755448", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0"],
            "issuerClaimRevTreeRoot": "0",
            "issuerClaimRootsTreeRoot": "0",
            "issuerClaimNonRevClaimsTreeRoot": "12781049434766209895790529815771921100011665835724745028505992240548230711728",
            "issuerClaimNonRevRevTreeRoot": "0",
            "issuerClaimNonRevRootsTreeRoot": "0",
            "issuerClaimNonRevState": "20606705619830543359176597576564222044873771515109680973150322899613614552596",
            "issuerClaimNonRevMtp": ["0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0"],
            "issuerClaimNonRevMtpAuxHi": "0",
            "issuerClaimNonRevMtpAuxHv": "0",
            "issuerClaimNonRevMtpNoAux": "1",
            "issuerClaimSchema": "274380136414749538182079640726762994055",
            "userClaimsTreeRoot": "8033159210005724351649063848617878571712113104821846241291681963936214187701",
            "userState": "5816868615164565912277677884704888703982258184820398645933682814085602171910",
            "userRevTreeRoot": "0",
            "userRootsTreeRoot": "0",
            "userID": "286312392162647260160287083374160163061246635086990474403590223113720496128",
            "issuerID": "296941560404583387587196218166209608454370683337298127000644446413747191808",
            "operator": 0,
            "slotIndex": 2,
            "timestamp": "1642074362",
            "value": ["10", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0"]
        }

        const expOut = {
            challenge: "1",
            userID: "286312392162647260160287083374160163061246635086990474403590223113720496128",
            issuerClaimSchema: "274380136414749538182079640726762994055",
            slotIndex: "2",
            operator: "0",
            timestamp: "1642074362",
            issuerID: "296941560404583387587196218166209608454370683337298127000644446413747191808",
            value  : ["10", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0"],

        }
        const w = await circuit.calculateWitness(inputs, true);
        await circuit.checkConstraints(w);
        await circuit.assertOut(w, expOut);
    });
})
;
