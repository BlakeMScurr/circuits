import {expect} from "chai";

const path = require("path");
const tester = require("circom_tester").wasm;

export {};

describe("StateTransition", function () {
    this.timeout(600000);

    let circuit;

    before(async () => {
        circuit = await tester(
            path.join(__dirname, "circuits", "stateTransitionTest.circom"),
            {
                output: path.join(__dirname, "circuits", "build"),
                recompile: true,
                reduceConstraints: false,
            },
        );
    });

    it("Positive: old state is genesis", async () => {
        const inputs = {
            "signatureR8x": "18891701860171247371699518630881407036190044751726720953837079527749022642971",
            "signatureR8y": "21444001181259678079255820231321016703398537151088948323486157803158249798767",
            "signatureS": "2403787647597303302429499961881962995523849856351947148212895665031614821037",
            "isOldStateGenesis": "1",
            "newUserState": "8061408109549794622894897529509400209321866093562736009325703847306244896707",
            "oldUserState": "18656147546666944484453899241916469544090258810192803949522794490493271005313",
            "authClaim": ["304427537360709784173770334266246861770", "0", "17640206035128972995519606214765283372613874593503528180869261482403155458945", "20634138280259599560273310290025659992320584624461316485434108770067472477956", "15930428023331155902", "0", "0", "0"],
            "authClaimMtp": ["0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0"],
            "authClaimNonRevMtp": ["0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0"],
            "authClaimNonRevMtpAuxHi": "0",
            "authClaimNonRevMtpAuxHv": "0",
            "authClaimNonRevMtpNoAux": "1",
            "claimsTreeRoot": "9763429684850732628215303952870004997159843236039795272605841029866455670219",
            "userID": "379949150130214723420589610911161895495647789006649785264738141299135414272",
            "revTreeRoot": "0",
            "rootsTreeRoot": "0",
        }

        const witness = await circuit.calculateWitness(inputs);
        await circuit.checkConstraints(witness);
    });

    it("Positive: old state is not genesis", async () => {
        const inputs = {
            "signatureR8x": "9963881174551151922441340254613012801484978219057350392635273039034477790087",
            "signatureR8y": "5227194134413368539113399325631930295918450896610312637388805543808887140194",
            "signatureS": "1823411791360468338002259292951620034220736904584300393074931377735723104972",
            "isOldStateGenesis": "0",
            "newUserState": "5451025638486093373823263243878919389573792510506430020873967410859218112302",
            "oldUserState": "8061408109549794622894897529509400209321866093562736009325703847306244896707",
            "authClaim": ["304427537360709784173770334266246861770", "0", "17640206035128972995519606214765283372613874593503528180869261482403155458945", "20634138280259599560273310290025659992320584624461316485434108770067472477956", "15930428023331155902", "0", "0", "0"],
            "authClaimMtp": ["16935233905999379395228879484629933212061337894505747058350106225580401780334", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0"],
            "authClaimNonRevMtp": ["0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0"],
            "authClaimNonRevMtpAuxHi": "0",
            "authClaimNonRevMtpAuxHv": "0",
            "authClaimNonRevMtpNoAux": "1",
            "claimsTreeRoot": "13140014475758763008111388434617161215041882690796230451685700392789570848755",
            "userID": "379949150130214723420589610911161895495647789006649785264738141299135414272",
            "revTreeRoot": "0",
            "rootsTreeRoot": "0",
        };

        const witness = await circuit.calculateWitness(inputs);
        await circuit.checkConstraints(witness);
    });

    it("Negative: old state is genesis", async () => {
        const inputs = {
            "signatureR8x": "9963881174551151922441340254613012801484978219057350392635273039034477790087",
            "signatureR8y": "5227194134413368539113399325631930295918450896610312637388805543808887140194",
            "signatureS": "1823411791360468338002259292951620034220736904584300393074931377735723104972",
            "isOldStateGenesis": "1",
            "newUserState": "5451025638486093373823263243878919389573792510506430020873967410859218112302",
            "oldUserState": "8061408109549794622894897529509400209321866093562736009325703847306244896707",
            "authClaim": ["304427537360709784173770334266246861770", "0", "17640206035128972995519606214765283372613874593503528180869261482403155458945", "20634138280259599560273310290025659992320584624461316485434108770067472477956", "15930428023331155902", "0", "0", "0"],
            "authClaimMtp": ["16935233905999379395228879484629933212061337894505747058350106225580401780334", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0"],
            "authClaimNonRevMtp": ["0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0"],
            "authClaimNonRevMtpAuxHi": "0",
            "authClaimNonRevMtpAuxHv": "0",
            "authClaimNonRevMtpNoAux": "1",
            "claimsTreeRoot": "13140014475758763008111388434617161215041882690796230451685700392789570848755",
            "userID": "379949150130214723420589610911161895495647789006649785264738141299135414272",
            "revTreeRoot": "0",
            "rootsTreeRoot": "0",
        }

        let error;
        await circuit.calculateWitness(inputs, true).catch((err) => {
            error = err;
        });

        expect(error.message).to.include("Error: Assert Failed. Error in template StateTransition")
    });
});
