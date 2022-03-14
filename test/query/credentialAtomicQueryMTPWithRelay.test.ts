import {describe} from "mocha";

const path = require("path");
const wasm_tester = require("circom_tester").wasm;

export {};

describe("credentialAtomicQueryMTPWithRelayTest", function () {

    this.timeout(600000);

    let circuit;

    before(async () => {
        circuit = await wasm_tester(
            path.join(__dirname, "../circuits/query", "credentialAtomicQueryMTPWithRelayTest.circom"),
            {
                output: path.join(__dirname, "../circuits", "build", "credentialAtomicQueryMTPWithRelayTest"),
                recompile: true,
                reduceConstraints: false,
            },
        );
    });

    after(async () => {
        circuit.release()
    })

    it("credentialAtomicQueryMTPWithRelayTest", async () => {

        const inputs = {
            "authClaim": ["269270088098491255471307608775043319525", "0", "17640206035128972995519606214765283372613874593503528180869261482403155458945", "20634138280259599560273310290025659992320584624461316485434108770067472477956", "15930428023331155902", "0", "0", "0"],
            "authClaimMtp": ["0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0"],
            "authClaimNonRevMtp": ["0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0"],
            "authClaimNonRevMtpAuxHi": "0",
            "authClaimNonRevMtpAuxHv": "0",
            "authClaimNonRevMtpNoAux": "1",
            "challenge": "1",
            "challengeSignatureR8x": "8553678144208642175027223770335048072652078621216414881653012537434846327449",
            "challengeSignatureR8y": "5507837342589329113352496188906367161790372084365285966741761856353367255709",
            "challengeSignatureS": "2093461910575977345603199789919760192811763972089699387324401771367839603655",
            "claim": ["3677203805624134172815825715044445108615", "286312392162647260160287083374160163061246635086990474403590223113720496128", "10", "0", "30803922965249841627828060161", "0", "0", "0"],
            "claimIssuanceClaimsTreeRoot": "12781049434766209895790529815771921100011665835724745028505992240548230711728",
            "claimIssuanceIdenState": "20606705619830543359176597576564222044873771515109680973150322899613614552596",
            "claimIssuanceMtp": ["0", "3007906543589053223183609977424583669571967498470079791401931468580200755448", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0"],
            "claimIssuanceRevTreeRoot": "0",
            "claimIssuanceRootsTreeRoot": "0",
            "claimNonRevIssuerClaimsTreeRoot": "12781049434766209895790529815771921100011665835724745028505992240548230711728",
            "claimNonRevIssuerRevTreeRoot": "0",
            "claimNonRevIssuerRootsTreeRoot": "0",
            "claimNonRevIssuerState": "20606705619830543359176597576564222044873771515109680973150322899613614552596",
            "claimNonRevMtp": ["0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0"],
            "claimNonRevMtpAuxHi": "0",
            "claimNonRevMtpAuxHv": "0",
            "claimNonRevMtpNoAux": "1",
            "claimSchema": "274380136414749538182079640726762994055",
            "issuerID": "296941560404583387587196218166209608454370683337298127000644446413747191808",
            "operator": 0,
            "relayProofValidClaimsTreeRoot": "2060811543840122903021294548450764657313814588813683444535079629430883892728",
            "relayProofValidRevTreeRoot": "0",
            "relayProofValidRootsTreeRoot": "0",
            "relayState": "12527121556679585334655533668561010635144996798189529744449089887229252528399",
            "slotIndex": 2,
            "timestamp": "1642074362",
            "userClaimsTreeRoot": "8033159210005724351649063848617878571712113104821846241291681963936214187701",
            "userID": "286312392162647260160287083374160163061246635086990474403590223113720496128",
            "userRevTreeRoot": "0",
            "userRootsTreeRoot": "0",
            "userStateInRelayClaim": ["928251232571379559706167670634346311933", "286312392162647260160287083374160163061246635086990474403590223113720496128", "0", "0", "0", "0", "5816868615164565912277677884704888703982258184820398645933682814085602171910", "0"],
            "userStateInRelayClaimMtp": ["1501244652861114532352800692615798696848833011443509616387313576023182892460", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0"],
            "value": ["10", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0"]
        }
        const expOut = {
            challenge: "1",
            userID: "286312392162647260160287083374160163061246635086990474403590223113720496128",
            claimSchema: "274380136414749538182079640726762994055",
            slotIndex: "2",
            operator: "0",
            timestamp: "1642074362",
            issuerID: "296941560404583387587196218166209608454370683337298127000644446413747191808",
        }

        const w = await circuit.calculateWitness(inputs, true);
        await circuit.checkConstraints(w);
        await circuit.assertOut(w, expOut);
    });

});
