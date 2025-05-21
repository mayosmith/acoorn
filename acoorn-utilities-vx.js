/********************************************************************************
 * MIT License
 * 
 * Copyright (c) 2024-2025 Mayo-Smith & Partrners, LLC
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 ********************************************************************************/

/*
-----------------------------------------------------------------------------------------------------
Acoorn Utilities v1.06.00

Goes great with static html, Node.js server, or within an AWS Lambda function.
                    
                    NODE v16.xx +        AWS s3 STATIC       AWS LAMBDA  
 SERVER_CONFIG       false               false               true
 AWS_CONFIG          false               false               true
 EXPORTS             export              export              module.exports

-----------------------------------------------------------------------------------------------------
*/
const SERVER_CONFIG = false; //set to "true" when operating on a Node.js server or within an AWS Lambda function; set to "false" when running in a client-side environment.
const AWS_CONFIG = false; //true for AWS Lambda, false for standard node server
const ABLOCK_PATH = './ablock/ablock.json'; 
const BUCKET_NAME = ["**BUCKET NAME HERE**"];
const NETWORK_FILE = 'acoorn-network.json';

const NETWORK_LOOKUP_ENDPOINT = ["**ENDPOINT HERE**"];
const NODE_ID = base62Hash(NETWORK_LOOKUP_ENDPOINT);
const DEFAULT_NODE_ENDPOINT = ["**DEFAULT NODE ENDPOINT HERE**"];
const NODE_TERM_DURATION = 5;
const BLOCK_SIZE = 20; //transactions per block
const ACOORN_POOBAH = "NORTH:0.0_EAST:0.0";    //the location of Acoorn Grand Poobah
const TX_FEE = 0;
const FILENAME_PREFIX = 'ablock-';
const PUZZLE_DIFFICULTY = 4;
const VERSION = "(v. 0.0.6)";



if (SERVER_CONFIG) {
    const crypto = require('node:crypto'); //requred for node server and AWS Lambda
    const { TextEncoder } = require('util');
}
if (AWS_CONFIG) {
    const AWS = require('aws-sdk');
    var s3 = new AWS.S3();
}



const MAP_WIDTH = 256;
const MAP_HEIGHT = 256;


/*  
-----------------------------------------------------------------------------------------------------
ARRAY BUFFER FUNCTIONS
-----------------------------------------------------------------------------------------------------
*/

function arrayBufferToBase64(buffer) {
    const binary = String.fromCharCode.apply(null, new Uint8Array(buffer));
    if (SERVER_CONFIG) {
        return Buffer.from(binary, 'binary').toString('base64');
    } else {
        return window.btoa(binary);
    }
}

function base64ToArrayBuffer(base64) {
    let binaryString;
    try {
        if (SERVER_CONFIG) {
            binaryString = Buffer.from(base64, 'base64').toString('binary');
        } else {
            binaryString = window.atob(base64);
        }
    } catch (error) {
        
        console.error('Error decoding base64 string:', error);
        return null;
    }
    try {
        if (SERVER_CONFIG) {
            binaryString = Buffer.from(base64, 'base64').toString('binary');
        } else {
            binaryString = window.atob(base64);
        }
   
    } catch (error) {
        
        console.error('Error decoding base64 string:', error);
        return null;
    }
    const len = binaryString.length;
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
        bytes[i] = binaryString.charCodeAt(i);
    }
    return bytes;
}
/*
-----------------------------------------------------------------------------------------------------
HASH FUNCTIONS
SHA256
-----------------------------------------------------------------------------------------------------  
*/

async function generateSHA256Hash(data) {
    if (typeof data !== 'string') {
        data = JSON.stringify(data);
    }
    const encoder = new TextEncoder();
    const dataBuffer = encoder.encode(data);
    const hashBuffer = await crypto.subtle.digest('SHA-256', dataBuffer);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    return hashHex;
}


/*
-----------------------------------------------------------------------------------------------------
Transaction Validation Functions
-----------------------------------------------------------------------------------------------------
*/

async function validateTransaction(txPayload){
    try {
        const vResult = {
            "result": "FAIL",
            "checksum": false,
            "txN": false,
            "origin": false,
            "destination": false,
            "transactionHash": false,
            "signature": false,
            "previousHash": false,
            "beginningBalance": 0,
            "endingBalance": 0,
            "balanceResult": false
        }
        const ablockBundle = await getBlockBundle();
        var txbp = {};
        
        txbp = JSON.parse(txPayload);

        const txBundle = JSON.stringify(txbp.TransactionBundle);
        const checksum = txbp.Checksum;

        vResult.checksum = await validateTxChecksum(txBundle, checksum);
        vResult.txN = await validateTxN(txBundle, ablockBundle);
        vResult.origin = await validateOrigin(txBundle);        
        vResult.destination = await validateDestination(txBundle);
        vResult.transactionHash = await validateTransactionHash(txBundle);
        vResult.signature = await validateSignature(txBundle);
        vResult.previousHash = await validatePreviousHash(txBundle, ablockBundle);
        const bResult = await validateBalance(txBundle, ablockBundle); 
        vResult.beginningBalance = bResult.beginningBalance;
        vResult.fee = TX_FEE;
        vResult.endingBalance = bResult.endingBalance;
        vResult.balanceResult = bResult.result;

        if (vResult.checksum && vResult.origin && vResult.destination && vResult.transactionHash && vResult.signature && vResult.previousHash && vResult.balanceResult) {
            vResult.result = "PASS";
        }
        return vResult;
    } catch (error) {
        console.error('Error validating transaction:', error);
        const failResult = {
            "result": "FAIL",
            "checksum": false,
            "txN": false,
            "origin": false,
            "destination": false,
            "transactionHash": false,
            "signature": false,
            "previousHash": false,
            "balance": 0,
            "balanceResult": false
        }
        
        return failResult;
    }
    

}

async function validateGeoKeyChecksum(geoKey){
    let gk;
   
 
   
    try{
        gk = JSON.parse(geoKey);

        const geoKeyCheck = {
            "Location": gk.Location,
            "PublicKey": gk.PublicKey,
            "SecretPassword": gk.SecretPassword
        }

        const checksum_validation = await createChecksum(geoKeyCheck);
        if (checksum_validation === gk.Checksum) {
            return true;
        } else {
            return false;
            
        }
    } catch (error) {
        return false;
    }

}


async function validateDestination(txBundle){
    const txBundleJSON = JSON.parse(txBundle);
    const { AcoornTx } = txBundleJSON;
const northPattern = new RegExp(`^NORTH:(\\d+)\\.([a-f0-9]{16})_EAST:(\\d+)\\.([a-f0-9]{16})$`);
const match = northPattern.exec(AcoornTx.dest);

if (!match) {
    return false;
}

const northValue = parseInt(match[1], 10);
const eastValue = parseInt(match[3], 10);

if (northValue < 0 || northValue > MAP_HEIGHT || eastValue < 0 || eastValue > MAP_WIDTH) {
    return false;
}

return true;

}

async function validateOrigin(txBundle) {
    const txBundleJSON = JSON.parse(txBundle);
    const { AcoornTx, PublicKey } = txBundleJSON;
    // Generate SHA-256 hash of PublicKey
    const publicKeyHash = await generateSHA256Hash(txBundleJSON.PublicKey);
    // Extract nHash from Origin
   
    const north = txBundleJSON.AcoornTx.orig.split('_')[0];
    const nHash = north.split('.')[1];
  

    // Extract eHash from Origin
    const east = txBundleJSON.AcoornTx.orig.split('_')[1];
    const eHash = east.split('.')[1];
 

    // Check if nHash + eHash is equal to the first 32 characters of the publicKeyHash
    const combinedHash = nHash + eHash;

    const pubKeyHashFirst32 = publicKeyHash.slice(0, 32);

    if (combinedHash === pubKeyHashFirst32) {
        return true;
    } else {
        return false;
    }
}

async function validateTxChecksum(txBundle, checksum){
    const txBundleJSON = JSON.parse(txBundle);
const { AcoornTx, PublicKey, Signature} = txBundleJSON;
const txBundleWithoutChecksum = {
    "TransactionBundle": {
        "AcoornTx": AcoornTx,
        "PublicKey": PublicKey,
        "Signature": Signature
    }
};
const checksum_validation = await createChecksum(txBundleWithoutChecksum);
if (checksum_validation === checksum) {
    return true;
} else {
    return false;
}

}

async function validateTransactionHash(txBundle) {
    txBundle = JSON.parse(txBundle);
    const { AcoornTx} = txBundle; // Deconstructing cHsh

    const txJSONnoHash = {
        "txN": AcoornTx.txN,
        "orig": AcoornTx.orig,
        "dest": AcoornTx.dest,
        "val": AcoornTx.val,
        "time": AcoornTx.time,
        "msg": AcoornTx.msg,
        "pHsh": AcoornTx.pHsh
    }
    const generatedHash = await generateSHA256Hash(txJSONnoHash);

    // Compare the generated hash with the current hash
    
    if (generatedHash === AcoornTx.cHsh) {
       
        return true;
    } else {
       
        return false;
    }
}

async function validateSignature(txBundle) {
    txBundle = JSON.parse(txBundle);
    const { Signature, PublicKey, AcoornTx } = txBundle;

    const txJSON = {
        "txN": AcoornTx.txN,
        "orig": AcoornTx.orig,
        "dest": AcoornTx.dest,
        "val": AcoornTx.val,
        "time": AcoornTx.time,
        "msg": AcoornTx.msg,
        "pHsh": AcoornTx.pHsh,
        "cHsh": AcoornTx.cHsh 
    }
    const txString = JSON.stringify(txJSON);

    let publicKeyBuffer, signatureBuffer, encodedTxData;
    try {
        publicKeyBuffer = base64ToArrayBuffer(PublicKey);
        signatureBuffer = base64ToArrayBuffer(Signature);

        const encoder = new TextEncoder();
        encodedTxData = encoder.encode(txString);
    } catch (error) {
        console.error('Error processing transaction data:', error);
        return false;
    }

    const publicKey = await crypto.subtle.importKey(
        "spki",
        publicKeyBuffer,
        {
            name: "RSA-PSS",
            hash: { name: "SHA-256" },
        },
        true,
        ["verify"]
    );

    const checkSignature = await crypto.subtle.verify(
        {
            name: "RSA-PSS",
            saltLength: 32,
        },
        publicKey,
        signatureBuffer,
        encodedTxData
    );

    if (checkSignature) {
        
        return true;
    } else {
        
        return false;
    }
}

async function validateTxN(txBundle, ablockBundle) {
    txBundle = JSON.parse(txBundle);
    const { AcoornTx} = txBundle; 

    const previousTransaction = getLastTransaction(ablockBundle);

    const pTxN = Number(previousTransaction.AcoornTx.txN);
    const aTxN = Number(AcoornTx.txN);

    if (aTxN-1 === pTxN) {
        return true;
    } else {
        return false;
    }
}

async function validatePreviousHash(txBundle, ablockBundle) {
    txBundle = JSON.parse(txBundle);
    const { AcoornTx} = txBundle; 

    const previousTransaction = getLastTransaction(ablockBundle);


    if (previousTransaction.AcoornTx.cHsh === AcoornTx.pHsh) {
        return true;
    } else {
        return false;
    }
}

async function getBlockBundle(blockNumber){
    var ablockBundle;
    if (AWS_CONFIG) {
        ablockBundle = await getBlockBundle_S3(blockNumber);       
    } else {
        const response = await fetch(DEFAULT_NODE_ENDPOINT + blockNumber); 
        ablockBundle = await response.json();
    }
    return ablockBundle;
}

async function getBlockTransactions(){
    const ablockBundle = await getBlockBundle();
    return ablockBundle.Block.Transactions;
}

//returns balance map updated with new transactions
async function getBalances(ablockBundle){
   
    const balMap = getBalMap(ablockBundle);
    const ablockTransactions = ablockBundle.Block.Transactions;    
    ablockTransactions.forEach(transaction => {
        const { orig, dest, val } = transaction.AcoornTx;

        if (!balMap.has(orig)) {
            balMap.set(orig, 0);
        }
        if (!balMap.has(dest)) {
            balMap.set(dest, 0);
        }

        balMap.set(dest, balMap.get(dest) + Number(val));
        balMap.set(orig, balMap.get(orig) - Number(val));

        balMap.set(ACOORN_POOBAH, balMap.get(ACOORN_POOBAH) + TX_FEE);
        balMap.set(orig, balMap.get(orig) - TX_FEE);


    });

    return balMap;

}


    
async function validateBalance(txBundle, ablockBundle){
    const balanceMap = await getBalances(ablockBundle);

    var txBundle = JSON.parse(txBundle);
    var { AcoornTx} = txBundle; 

    const originBalance = balanceMap.get(AcoornTx.orig);
    const bresult = {
        "result": false,
        "beginningBalance": originBalance,
        "endingBalance": 0
    }

    if (originBalance <= 0){
        bresult.result = false
        bresult.endingBalance = originBalance;
        return bresult;
    }

    if (originBalance >= Number(AcoornTx.val) + TX_FEE) {
        bresult.result = true;
        bresult.endingBalance = originBalance - AcoornTx.val - TX_FEE;
        return bresult;
    } else {
        bresult.result = false; 
        bresult.endingBalance = originBalance;
        return bresult;
    }  
}

async function saveBalMap(ablockBundle,newBalMap) {
    ablockBundle.Block.PrevBlockBal = Array.from(newBalMap);
    return ablockBundle;
}

function getBalMap(ablockBundle) {
    const BalMap = new Map(ablockBundle.Block.PrevBlockBal);

    return BalMap;
}


/*
-----------------------------------------------------------------------------------------------------
Acoorn AWS FUNCTIONS
-----------------------------------------------------------------------------------------------------
*/

async function getETag() {
    const key = await getLatestAblockFile();
    const params = {
        Bucket: BUCKET_NAME,
        Key: key
    };

    try {
        const headObject = await s3.headObject(params).promise();
        return headObject.ETag;
    } catch (error) {
        console.error('Error getting S3 object ETag:', error);
        throw error;
    }
}


async function createNewBlockFileBundle(){
    const currentBlockBundle = await getBlockBundle();
    const lastTransaction = getLastTransaction(currentBlockBundle);
    const balances = await getBalances(currentBlockBundle);
    const balanceMapJson = Array.from(balances); // Convert map to array

    var newBlockBundle = {
        BlockHash: {},
        Block: {
            Header: {
                FileName: await createNextAblockFileName(),
                PrevBlockHash: currentBlockBundle.BlockHash,
                BlockNumber: currentBlockBundle.Block.Header.BlockNumber + 1,
                BlockTime: new Date().toISOString(),
                BlockTransactions: 0,
                BlockStatus: "PENDING"
            },
            PrevBlockBal: balanceMapJson, // Store the array here
            PrevBlockTx: {
                AcoornTx: lastTransaction.AcoornTx,
                PublicKey: lastTransaction.PublicKey,
                Signature: lastTransaction.Signature
            },
            Transactions: []
        }
    }
        
    newBlockBundle.BlockHash = await calculateBlockHash(newBlockBundle);

    return newBlockBundle;
}


async function addTxToBlock(txBundle){
    var eTag = await getETag(); 
    const vResult = await validateTransaction(txBundle);

    if (vResult.result !== "PASS"){
        return vResult;
    }
        
    const newTransaction = JSON.parse(txBundle).TransactionBundle;
   
        var ablockBundle = await getBlockBundle();
        if (ablockBundle.Block.Transactions.length >= BLOCK_SIZE) {
            ablockBundle = await createNewBlockFileBundle();
        }

        ablockBundle.Block.Transactions.push(newTransaction);
        ablockBundle.Block.Header.BlockTransactions = ablockBundle.Block.Transactions.length;
        ablockBundle.BlockHash = await calculateBlockHash(ablockBundle);
        const fileName = ablockBundle.Block.Header.FileName;

        var s3Params = {
            Bucket: BUCKET_NAME,
            Key: fileName,
            Body: JSON.stringify(ablockBundle),
            ContentType: "application/json"
        };

        if (eTag != await getETag()) {
            vResult.result = "BUSY";
            return vResult;
        }else{
            await s3.putObject(s3Params).promise();
            var eTag = await getETag(); 
            vResult.result = "PASS";
            return vResult;
        }
        
      
    
}



async function saveAblock_Local(ablock){
    const filePath = ABLOCK_PATH;
    fs.writeFileSync(filePath, JSON.stringify(ablock, null, 2));
}


async function getCurrentBlockNumber(){
    const ablockBundle = await getBlockBundle();
    return ablockBundle.Block.Header.BlockNumber;
}

async function getLatestAblockFile() {
    const listParams = {
        Bucket: BUCKET_NAME,
        Prefix: FILENAME_PREFIX
    };

    try {
        
        const data = await s3.listObjectsV2(listParams).promise();
        
        const files = data.Contents.map(file => file.Key);

        const ablockFiles = files.filter(file => file.startsWith(FILENAME_PREFIX));
        
        // Extract the numbers and find the maximum
        const maxFile = ablockFiles.reduce((max, file) => {
            const num = parseInt(file.split('-')[1]);
            return num > max ? num : max;
        }, -1);

        return `${FILENAME_PREFIX}${maxFile}.json`;
    } catch (error) {
        console.error('Error Fetching aBlock Files:', error);
        throw error;
    }
}

async function getBlockBundle_S3(blockNumber) {
    let fileName;
try {
    if (blockNumber >= 0 && blockNumber < await getCurrentBlockNumber()){
        fileName = FILENAME_PREFIX + blockNumber + ".json";
    } else {
        fileName = await getLatestAblockFile();
    }
} catch (error) {
    console.error('Error determining fileName:', error);
    throw error;
}

    const bucketName = BUCKET_NAME;

    try {
        const data = await s3.getObject({ Bucket: bucketName, Key: fileName }).promise();
        const fileContent = data.Body.toString('utf-8');
        const ablockBundle = JSON.parse(fileContent);
        return ablockBundle;
    } catch (error) {
        console.error('Error fetching and parsing ablock:', error);
        throw error;
    }
}

/*
-----------------------------------------------------------------------------------------------------
LEDGER & ABLOCK FUNCTIONS
-----------------------------------------------------------------------------------------------------
*/

async function createNextAblockFileName(){
    const fileName = await getLatestAblockFile();
    const fileNameArray = fileName.split("-");
    const blockNumber = parseInt(fileNameArray[1]);
    const nextBlockNumber = blockNumber + 1;
    return `${FILENAME_PREFIX}${nextBlockNumber}.json`;
}







async function getAcoornBlock_Local() {
    try {
        const response = await fetch(ABLOCK_PATH);
        if (response.ok) {
            const ablockData = await response.json();
            return ablockData;
        } else {
            console.error('Error fetching ablock.json:', response.statusText);
            return null;
        }
    } catch (error) {
        console.error('Error fetching ablock.json:', error);
        return null;
    }
}


async function validateAllTransactions() {
    let blockNumber = 0;
    let validationResults = {
        results: [],
        totalCount: 0,
        finalResult: true
    };
    

    while (true) {
        const fileName = `${FILENAME_PREFIX}${blockNumber}.json`;
        try {
            const ablockData = await getBlockBundle();
            if (!ablockData) {
                break; // No more blocks to validate
            }

            for (const transaction of ablockData.Block.Transactions) {
                const validationResult = await validateTransaction(transaction);
                validationResults.results.push({
                    blockNumber: blockNumber,
                    transaction: transaction,
                    result: validationResult.result
                });

                if (validationResult.result !== "PASS") {
                    console.error(`Invalid transaction in block ${blockNumber}:`, transaction);
                    
                    validationResults.finalResult = false;

                }
            }

            blockNumber++;
        } catch (error) {
            console.error(`Error validating transactions in block ${blockNumber}:`, error);
            validationResults.finalResult = false;
            break;
        }
    }

    return validationResults;
}

async function fetchAblockData(fileName) {
    try {
        const response = await fetch(`./ablock/${fileName}`);
        if (response.ok) {
            const ablockData = await response.json();
            return ablockData;
        } else {
            console.error(`Error fetching ${fileName}:`, response.statusText);
            return null;
        }
    } catch (error) {
        console.error(`Error fetching ${fileName}:`, error);
        return null;
    }
}




/*
-----------------------------------------------------------------------------------------------------
CHECKSUM FUNCTIONS
-----------------------------------------------------------------------------------------------------
*/
 
async function createChecksum(txt){
    const full_hash = await generateSHA256Hash(txt);
    return full_hash.slice(0, 8);
}

function getLastTransaction(ablockBundle){

if (ablockBundle.Block.Transactions.length > 0) {
    //return the last transaction from the current block
    return ablockBundle.Block.Transactions[ablockBundle.Block.Transactions.length - 1];
} else {
    //return the last transaction from the prior block
    return ablockBundle.Block.PrevBlockTx;
}

}


/*
-----------------------------------------------------------------------------------------------------
TRANSACTION OBJECT & BUNDLE FUNCTIONS
-----------------------------------------------------------------------------------------------------
*/  
async function calculateBlockHash(ablockBundle){
    const hashVal = await generateSHA256Hash(JSON.stringify(ablockBundle.Block));
    return hashVal;
}


//Create a transaction bundle
async function createTxBundle(geoKey, dest, val, msg){

    let gk;


    try {
        gk = JSON.parse(geoKey);
    } catch (error) {
        console.error('GeoKey Error:', error);
        
        return null;
    }
    
    const geoKeyChecksum = await validateGeoKeyChecksum(geoKey);
    if (!geoKeyChecksum) {
        alert("GeoKey CheckSum Error.");
        return null;
    }
    const orig = gk.Location;

    const txObject =JSON.parse(await createTransactionObject(orig, dest, val, msg));
    

    const sig = await signString(JSON.stringify(txObject), gk.PublicKey, gk.SecretPassword);



   
    const txBundle = {
        "TransactionBundle":   
            {
                    "AcoornTx": {
                        "txN": txObject.txN,
                        "orig": txObject.orig,
                        "dest": txObject.dest,
                        "val": txObject.val,
                        "time": txObject.time,
                        "msg": txObject.msg,
                        "pHsh": txObject.pHsh,
                        "cHsh": txObject.cHsh
                    },
                    "PublicKey": gk.PublicKey,
                    "Signature": sig
            }
                };
                const checksum = await createChecksum(JSON.stringify(txBundle));
                txBundle.Checksum = checksum;
            
                return txBundle;
            
}

async function signString(txString, pubKey, priKey){
    const publicKeyBuffer = base64ToArrayBuffer(pubKey);
    const privateKeyBuffer = base64ToArrayBuffer(priKey);
    
    const encoder = new TextEncoder();
    const encodedTxData = encoder.encode(txString);


    const publicKey = await crypto.subtle.importKey(
        "spki",
        publicKeyBuffer,
        {
            name: "RSA-PSS",
            hash: { name: "SHA-256" },
        },
        true,
        ["verify"]
    );

    const privateKey = await crypto.subtle.importKey(
        "pkcs8",
        privateKeyBuffer,
        {
            name: "RSA-PSS",
            hash: { name: "SHA-256" },
        },
        true,
        ["sign"]
    );

    const keyPair = { publicKey, privateKey };
    const signature = await crypto.subtle.sign(
        {
            name: "RSA-PSS",
            saltLength: 32,
        },
        keyPair.privateKey,
        encodedTxData
    );

    const signatureString = arrayBufferToBase64(signature);
    return signatureString;
}

//Follows Acoorn Transaction Format: {txN, orig, dest, val, time, msg, pHsh, cHsh}  
async function createTransactionObject(orig, dest, val, msg){
    const MSG_LENGTH = 32; //Max message length
    const msgTrim = msg.substring(0, MSG_LENGTH).trim();
    
    const timeStamp = new Date().toISOString();

    const ablockBundle = await getBlockBundle();

    const lastTransaction = getLastTransaction(ablockBundle);
    const lastTransactionJSON = lastTransaction;
    const txN = lastTransactionJSON.AcoornTx.txN + 1;
    const pHsh = lastTransactionJSON.AcoornTx.cHsh;

    const txJSONnoHash = {
        "txN": txN,
        "orig": orig,
        "dest": dest,
        "val": val,
        "time": timeStamp,
        "msg": msgTrim,
        "pHsh": pHsh
    }
    
    const txHash = await generateSHA256Hash(txJSONnoHash);

    const txJSON = {
        "txN": txN,
        "orig": orig,
        "dest": dest,
        "val": val,
        "time": timeStamp,
        "msg": msgTrim,
        "pHsh": pHsh,
        "cHsh": txHash 
    }

    return JSON.stringify(txJSON);
}

/*
-----------------------------------------------------------------------------------------------------
KEY PAIR FUNCTIONS
-----------------------------------------------------------------------------------------------------
*/

async function generateKeyPair() {
    const keyPair = await crypto.subtle.generateKey(
        {
            name: "RSA-PSS",
            modulusLength: 2048,
            publicExponent: new Uint8Array([1, 0, 1]),
            hash: { name: "SHA-256" },
        },
        true,
        ["sign", "verify"]
    );

    return keyPair;
}


/*
-----------------------------------------------------------------------------------------------------

LOCATION, MAP & GEOGRAPHIC FUNCTIONS
-----------------------------------------------------------------------------------------------------

*/

function getMapDimensions(){
    const dimensions = {
        width: MAP_WIDTH,
        height: MAP_HEIGHT
    };
    return dimensions;
}


function getCoord(location){
    const coord = {x:0, y:0};
    coord.x = location.substring(location.indexOf("NORTH:") + 6, location.indexOf("."));
    const eastIndex = location.indexOf("EAST:") + 5; // after "EAST:"
    coord.y = location.slice(eastIndex, location.indexOf(".", eastIndex)); // Extract the y coordinate
    return coord;
}

//get all unique locations from the ablock
async function getAllLocations(){
    var ablock = await getBlockTransactions();
    const locations = [];
    var coord = {x:0, y:0};
    ablock.AcoornTx.forEach(tx => {
        coord = getCoord(tx.orig);
        // Check if coord doesn't exist in locations
        if (!locations.some(loc => loc.x === coord.x && loc.y === coord.y)) {
            locations.push(coord);
        }
        coord = getCoord(tx.dest);
        // Check if coord doesn't exist in locations
        if (!locations.some(loc => loc.x === coord.x && loc.y === coord.y)) {
            locations.push(coord);
        }
    });
    return locations;
}


async function createGeoKey(address){
    const geoKey = {
        "Location": address.north + "_"+ address.east,
        "PublicKey": address.publicKey,
        "SecretPassword": address.privateKey
    };
    const checksum = await createChecksum(JSON.stringify(geoKey));
    geoKey.Checksum = checksum;
    return geoKey;
}


async function reserveLocation(x,y){
    x = Math.floor(x);
    y = Math.floor(y);
    const address ={x:0,y:0,publicKey:0, privateKey:0, publicKeyHash:0,north:0,east:0}
    //generate key pair
    const keyPair = await generateKeyPair();

   
    const exportedPublicKey = await crypto.subtle.exportKey("spki", keyPair.publicKey);
    const exportedPrivateKey = await crypto.subtle.exportKey("pkcs8", keyPair.privateKey);

    const publicKeyString = arrayBufferToBase64(exportedPublicKey);
    const privateKeyString = arrayBufferToBase64(exportedPrivateKey);
    const publicKeyHashString = await generateSHA256Hash(publicKeyString);
    
    address.x = x;
    address.y = y;
    address.privateKey = privateKeyString;
    address.publicKey = publicKeyString;
    address.publicKeyHash = publicKeyHashString;
   
    //split hash into 2 parts and assign to n and e address
    const pkhn = publicKeyHashString.slice(0,16); //first 32 bytes 
    const pkhe = publicKeyHashString.slice(16,32); //second 32 bytes truncate the rest

    address.north = "NORTH:"+address.y+"."+pkhn;
    address.east = "EAST:"+address.x+"."+pkhe;
    return address;
}

/*
-----------------------------------------------------------------------------------------------------
NODE MANAGEMENT FUNCTIONS
-----------------------------------------------------------------------------------------------------
*/ 

async function compareNode(nodeID){
    const blockBundle = await getBlockBundle();
    const nodeBlockBundle = await getNodeBlockBundle(nodeID);
    const blockHash = await calculateBlockHash(blockBundle);
    const nodeBlockHash = await calculateBlockHash(nodeBlockBundle);
    const lastTx = getLastTransaction(blockBundle);
    const lastNodeTx = getLastTransaction(nodeBlockBundle);

    let compareResult = {
        "ReferenceNode":{
            "BlockNumber":blockBundle.Block.Header.BlockNumber,
            "BlockHash":blockBundle.BlockHash,
            "Transactions":blockBundle.Block.Transactions.length,
            "TxNumber":lastTx.AcoornTx.txN
            
        },
        "ComparisonNode":{
            "BlockNumber":nodeBlockBundle.Block.Header.BlockNumber,
            "BlockHash":nodeBlockBundle.BlockHash,
            "Transactions":nodeBlockBundle.Block.Transactions.length,
            "TxNumber":lastNodeTx.AcoornTx.txN
            
        },
        "result":false
    }

    if(blockHash === nodeBlockHash){ 
        compareResult.result = true;
    }
    return compareResult;
}


async function compareBlocks(nodeID, blockNumber){
    const nodeBlockBundle = await getNodeBlockBundle(nodeID, blockNumber);
    const blockBundle = await getBlockBundle(blockNumber);
    const blockHash = await calculateBlockHash(blockBundle);
    const nodeBlockHash = await calculateBlockHash(nodeBlockBundle);

    if(blockHash === nodeBlockHash){ 
        return true;
    }
    return false;
}


async function updateChain(nodeID, blockNumber){
    const nodeBlockBundle = await getNodeBlockBundle(nodeID, blockNumber);
    const fileName = nodeBlockBundle.Block.Header.FileName;
}


async function updateBlock(nodeID, blockNumber){
    const nodeBlockBundle = await getNodeBlockBundle(nodeID, blockNumber);
    const fileName = nodeBlockBundle.Block.Header.FileName;

    let vResult = {
        result: "Block Update Failed"
    }
    var s3Params = {
        Bucket: BUCKET_NAME,
        Key: fileName,
        Body: JSON.stringify(nodeBlockBundle),
        ContentType: "application/json"
    };
        try {
            await s3.putObject(s3Params).promise();
            vResult.result = "Block Replaced";
        } catch (error) {
            console.error('Error replacing block:', error);
            vResult.result = "Block Update Failed";
        }
        return vResult;

}    



async function syncToNode(nodeId){

    const nodeBlockBundle = await getNodeBlockBundle(nodeId);
    const nodeBlockNumber = nodeBlockBundle.Block.Header.BlockNumber;

    const blockComparisonResults = [];

    for (let n = 1; n <= nodeBlockNumber; n++) {
        if(! await compareBlocks(nodeId, n))
            updateBlock(nodeId, n);
    }


}

async function testHandshake(){
    const node_endpoint = NETWORK_LOOKUP_ENDPOINT; 
    const address = await reserveLocation(100,100);
    const publicKey = address.publicKey;
    const privateKey = address.privateKey;
    const secretHandshake = await handshake(node_endpoint, publicKey, privateKey);
    return secretHandshake;
}

function convertNumberToLocation(number){
    const maxCoordinate = 256;

    const x = n % maxCoordinate;
    const y = Math.floor(n / maxCoordinate) % maxCoordinate;

    return { x, y };


}




async function handshake(node_endpoint, publicKey, privateKey){

    const sig = await signString(node_endpoint, publicKey, privateKey);
    const isoTimestamp = new Date().toISOString();
    const puzzle_result = await cryptoPuzzle(node_endpoint+isoTimestamp, PUZZLE_DIFFICULTY);


    return {
        "node_endpoint": node_endpoint,
        "signature": sig,
        "public_key": publicKey,
        "nonce": puzzle_result.nonce,
        "hash": puzzle_result.hash,
        "time": isoTimestamp,
        "puzzle_input": node_endpoint+isoTimestamp
    }
}


async function cryptoPuzzle(input, difficulty) {
    let nonce = 0;
    let hash = "";

    const target = "ac" + "0".repeat(difficulty);
    
    while (true) {
        hash = await generateSHA256Hash(nonce + input);

            
        if (hash.startsWith(target)) {
            return { nonce, hash };
        }
        nonce++;
    }
}



async function updateAcoornNetwork(networkData){
    let vResult = {
        result: "Network Update Failed"
    }
    var s3Params = {
        Bucket: BUCKET_NAME,
        Key: NETWORK_FILE,
        Body: JSON.stringify(networkData),
        ContentType: "application/json"
    };
        try {
            await s3.putObject(s3Params).promise();
            vResult.result = "Network Updated";
        } catch (error) {
            console.error('Error updating network:', error);
            vResult.result = "Network Update Failed";
        }
        return vResult;
}    
    
async function getNodeLocation(){
    const networkData = await getAcoornNetwork();
    return networkData.Location;
}

async function getAcoornNetwork() {
    try {
        const response = await fetch(NETWORK_LOOKUP_ENDPOINT);
        if (response.ok) {
            const networkData = await response.json();
            return networkData;
        } else {
            console.error('Error fetching acoorn-network.json:', response.statusText);
            return [];
        }
    } catch (error) {
        console.error('Error fetching acoorn-network.json:', error);
        return [];
    }
}

function isBlockApproved(approvedBlocks, blockNumber){
    return approvedBlocks.some(block => block.BlockNumber == blockNumber);
}

function confirmPriorBlocks(approvedBlocks,blockNumber){

for (let i = 0; i < blockNumber; i++) {
    const blockApproved = approvedBlocks.some(block => block.BlockNumber == i);
    if (!blockApproved) {
        return false;
    }
}
return true;
}

async function validateBlockHash(blockBundle){
    const blockHash = blockBundle.BlockHash;
    const blockHashValid = await generateSHA256Hash(blockBundle.Block);
    return blockHash === blockHashValid;
}
function validatePreviousTx(prevBlockBundle, blockBundle) {
    const previousTx = getLastTransaction(prevBlockBundle);
    return blockBundle.Block.PrevBlockTx.cHsh === previousTx.cHsh;
}


async function approveBlock(blockNumber){

    if (!AWS_CONFIG) return;
        //are all prior blocks approved?
        //is the blockhash valid?
        //is the transaction number sequential?
        //does the previous transaction match the last transaction from the prev block?
        //are all the transactions valid?
    
    const blockBundle = await getBlockBundle_S3(blockNumber);
    const prevBlockBundle = await getBlockBundle_S3(blockNumber - 1);
    const networkData = await getAcoornNetwork();
    const approvedBlocks = networkData.ApprovedBlocks;
    if (isBlockApproved(approvedBlocks, blockNumber)) return true;

    const newBlockApproval = {
        "ApprovalTime": new Date().toISOString(),
        "BlockNumber": blockNumber,
        "BlockHash": blockBundle.BlockHash
    }

    
    try {
        if (!confirmPriorBlocks(approvedBlocks, blockNumber)) return false;
        if (await !validateBlockHash(blockBundle)) return false;
        if (!validatePreviousTx(prevBlockBundle, blockBundle)) return false;
        
    } catch (error) {
        console.error('Error during block validation:', error);
        return false;
    }

    networkData.ApprovedBlocks.push(newBlockApproval);
    const result = await updateAcoornNetwork(networkData);
    return result;
    
}

async function selectNode(hashValue, numberOfNodes) {
    // Convert the hash value to a big integer
    const hashBigInt = BigInt('0x' + hashValue);

    // Calculate the node index by taking the modulus of the hash value with the number of nodes
    const nodeIndex = Number(hashBigInt % BigInt(numberOfNodes));

    return nodeIndex;
}



async function castVote(ablockBundle,nodeId,vote) {
    const voteStatusHeader = {
        status: "PENDING",
        leadNode: leadNode,
        nodeVotes: nodeVotes // Example: { "node1": "yes", "node2": "no", "node3": "abstain", "node4": "pending" }
    };
    return voteStatusHeader;
}









//create 8 character base62 hash from data
async function base62Hash(data){

    const hash = await generateSHA256Hash(data);
    const truncatedHash = hash.slice(0, 8);
    const base62Hash = stringToBase58(truncatedHash);
    return base62Hash;
}

function getAPIRoute(endpoint, type, value){
    return endpoint + "/" + type + "/" + value;
}


async function getNodeBlockBundle(nodeId,blockNumber){
    const collaborators = await getNodeCollaborators(nodeId);
    const agentEndpoint = collaborators.LocalAgent;
    try {
        const route = getAPIRoute(agentEndpoint, "block", blockNumber);
        const response = await fetch(route);

        if (response.ok) {
            const data = await response.json();
            return data;
        } else {
            console.error(`Error fetching from ${agentEndpoint}:`, response.statusText);
            return null;
        }
    } catch (error) {
        console.error(`Error fetching from ${agentEndpoint}:`, error);
        return null;
    }

    
}



//get the collaborators for a given node
async function getNodeCollaborators(nodeId){
    const nodeTable = await getNodeTable();
    const endpoint = nodeTable[nodeId];

    if (endpoint) {
        try {
            const response = await fetch(endpoint + "/"+ NETWORK_FILE);
            if (response.ok) {
                const data = await response.json();
                return data;
            } else {
                console.error(`Error fetching from ${endpoint}:`, response.statusText);
                return null;
            }
        } catch (error) {
            console.error(`Error fetching from ${endpoint}:`, error);
            return null;
        }
    } else {
        console.error(`Endpoint for nodeId ${nodeId} not found.`);
        return null;
    }

    
    return nodeTable[nodeId];
}


async function getNodeTable(){

    const networkData = await getAcoornNetwork();
    return networkData.Collaborators;
/*
    try {
        const response = await fetch(NETWORK_LOOKUP_ENDPOINT);
        if (response.ok) {
            const data = await response.json();

            
            return data.Collaborators;
        } else {
            console.error(`Error fetching from ${NETWORK_LOOKUP_ENDPOINT}:`, response.statusText);
            return null;
        }
    } catch (error) {
        console.error(`Error fetching from ${NETWORK_LOOKUP_ENDPOINT}:`, error);
        return null;
    }
    */
}

async function getLedgerVersion(){
    const version = {
        "transactions": 0,
        "txHash": "",
        "number": ""
    }
    const ablockBundle = await getBlockBundle();

    version.transactions = ablockBundle.Block.Header.BlockTransactions;
    version.txHash = ablockBundle.BlockHash;
    version.number = ablockBundle.Block.Header.BlockNumber;
    
    return version;
}






async function getSelectionState() {
    var selectionState = {
        node: null,  //the node that is currently selected  
        termExpiry: null  //when the term expires, the node will be selected again
    }

 

    const expiryTime = new Date();

    
    expiryTime.setMilliseconds(0);
    const remainder = expiryTime.getSeconds() % NODE_TERM_DURATION;
    
    if (remainder !== 0) {
        expiryTime.setMilliseconds(0);
        expiryTime.setSeconds(expiryTime.getSeconds() + (NODE_TERM_DURATION - remainder));
    }


    
    selectionState.termExpiry =  expiryTime.toISOString();
    selectionState.node = await chooseNode(NODE_TERM_DURATION);
    
    return selectionState;
};


async function chooseNode(duration) {



    const currentTime = new Date();
    const secondsSinceEpoch = Math.floor(currentTime.getTime() / 1000);
    const nodeIndex = Math.floor(secondsSinceEpoch / duration)% nodeTable.length;

    return nodeTable[nodeIndex];
}


/*
-----------------------------------------------------------------------------------------------------
MISC FUNCTIONS
-----------------------------------------------------------------------------------------------------
*/ 



// Function to convert a buffer to a Base58 string
function stringToBase58(str) {
    const base58Chars = '0123456789abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ';
  
    let base58Str = '';
    let num = BigInt('0x' + str);

    while (num > 0) {
        const remainder = num % 58n;
        base58Str = base58Chars[Number(remainder)] + base58Str;
        num = num / 58n;
    }

    return base58Str;
    
}



async function createGenesisBlock(firstDestination, startingAmount){
    const ablock_0 = {
        
            "BlockHash": "",
                "Block": {
                    "Header": {
                        "FileName": "ablock-0.json",
                        "PrevBlockHash": "",
                        "BlockNumber": 0,
                        "BlockTime": "2025-01-06T14:27:07Z",
                        "BlockTransactions": 1,
                        "BlockStatus": "FINAL"
                    },
                    "PrevBlockBal": [],
                    "PrevBlockTx": {
                        "AcoornTx": {
                        "txN": "",
                        "orig": "",
                        "dest": "",
                        "val": "",
                        "time": "",
                        "msg": "",
                        "pHsh": "",
                        "cHsh": ""
                        },
                        "PublicKey": "",
                        "Signature": ""

                    },
                    "Transactions": [
                        {
                            "AcoornTx": {
                            "txN": 0,
                            "orig": "",
                            "dest": "NORTH:0.0_EAST:0.0",
                            "val": startingAmount,
                            "time": "2025-01-06T14:27:07Z",
                            "msg": "Acoorns Hic Incipiunt",
                            "pHsh": "2718281828459045235360287471352662497757247093699959574966967627"
                            //"cHsh": ""
                            },
                            "PublicKey": "",
                            "Signature": ""
                        }
                    ]
                }
    };
    ablock_0.Block.Transactions[0].AcoornTx.cHsh = await generateSHA256Hash(ablock_0.Block.Transactions[0]);
    ablock_0.BlockHash = await generateSHA256Hash(ablock_0.Block);


const negStartingAmount = -startingAmount;
const ablock_1 =  {
        
            "BlockHash": "",
                "Block": {
                    "Header": {
                        "FileName": "ablock-1.json",
                        "PrevBlockHash": ablock_0.BlockHash,
                        "BlockNumber": 1,
                        "BlockTime": "2025-01-06T14:27:07Z",
                        "BlockTransactions": 1,
                        "BlockStatus": "PENDING"
                    },
                    "PrevBlockBal": [
                        [
                          "NORTH:0.0_EAST:0.0",
                          0]
                      ],
                    "PrevBlockTx": {
                        "AcoornTx": {
                        "txN": "0",
                        "orig": "",
                        "dest": "NORTH:0.0_EAST:0.0",
                        "val": startingAmount,
                        "time": "2025-01-06T14:27:07Z",
                        "msg": "Acoorns Hic Incipiunt",
                        "pHsh": "2718281828459045235360287471352662497757247093699959574966967627",
                        "cHsh": ablock_0.Block.Transactions[0].AcoornTx.cHsh
                        },
                        "PublicKey": "",
                        "Signature": ""
                    },
                    "Transactions": [
                        {
                            "AcoornTx": {
                            "txN": 1,
                            "orig": "NORTH:0.0_EAST:0.0",
                            "dest": firstDestination,
                            "val": startingAmount,
                            "time": "2025-01-06T14:27:07Z",
                            "msg": "First Transaction",
                            "pHsh": ablock_0.Block.Transactions[0].AcoornTx.cHsh,
                            //"cHsh": ""
                            },
                            "PublicKey": "1618033988749894848204586834365638117720309179805762862135448622",
                            "Signature": "3141592653589793238462643383279502884197169399375105820974944592"
                        }
                    ]
                }
    };
    ablock_1.Block.Transactions[0].AcoornTx.cHsh = await generateSHA256Hash(ablock_1.Block.Transactions[0]);
    ablock_1.BlockHash = await generateSHA256Hash(ablock_1.Block);
        

    const bReturn = {
        "ablock_0": ablock_0,
        "ablock_1": ablock_1
    }


    return bReturn; 
}



/*
-----------------------------------------------------------------------------------------------------
EXPORTS
-----------------------------------------------------------------------------------------------------
*/ 

//module.exports = {      //for hosted enviroments like AWS Lambda
export {                  //for node server running on localhost
    addTxToBlock,
    approveBlock,
    arrayBufferToBase64,
    base64ToArrayBuffer,
    chooseNode,
    compareNode,
    createChecksum,
    createGeoKey,
    createGenesisBlock,
    createNewBlockFileBundle,
    createNextAblockFileName,
    createTransactionObject,
    createTxBundle,
    generateKeyPair,
    generateSHA256Hash,
    getAllLocations,
    getBalances,
    getBalMap,
    getBlockBundle,
    getBlockTransactions,
    getCoord,
    getETag,
    getLastTransaction,
    getLedgerVersion,
    getMapDimensions,
    getNodeTable,
    getNodeCollaborators,
    getNodeBlockBundle,
    base62Hash,
    getSelectionState,
    reserveLocation,
    saveBalMap,
    signString,
    syncToNode,
    testHandshake,
    validateAllTransactions,
    validateBalance,
    validateGeoKeyChecksum,
    validateOrigin,
    validatePreviousHash,
    validateSignature,
    validateTransaction,
    validateTransactionHash,
    validateTxChecksum,
    validateTxN,
    NODE_ID,
    VERSION
     
}




