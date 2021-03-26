"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    Object.defineProperty(o, k2, { enumerable: true, get: function() { return m[k]; } });
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (k !== "default" && Object.prototype.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
    __setModuleDefault(result, mod);
    return result;
};
Object.defineProperty(exports, "__esModule", { value: true });
const crypto = __importStar(require("crypto"));
// TypeScript for Object Oriented principles is really helpful here
// Transfering funds is the main part of the process
class Transaction {
    constructor(amount, sender, // public key
    receiver // public key
    ) {
        this.amount = amount;
        this.sender = sender;
        this.receiver = receiver;
    }
    toString() {
        // Stringyfies the object for serialization/encryption
        return JSON.stringify(this);
    }
}
// Container for multiple transactions (single transaction in this case for simplicity)
// A block is like an element on a Linked List (Chain)
class Block {
    constructor(
    // Hashing Functions allows us to take a string of arbitraty size and map it to a value of fixed length (hash or hash digest).
    // Once the hash is created it CANNOT be reversed back to the original value, but you can compare two hashes to ensure it's the same initial value. That's important here because we can ensure linked blocks were not manipulated.
    prevHash, transaction, 
    // Blocks are placed in chronological order
    time = Date.now()) {
        this.prevHash = prevHash;
        this.transaction = transaction;
        this.time = time;
        // One-Time-Use Random number associated with the block to create the Proof of Work
        this.nonce = Math.round(Math.random() * 999999999);
    }
    get hash() {
        const str = JSON.stringify(this);
        // Secure Hash Algorithm of 256 bits - One Way Cryptographic Function
        // We use hashes and not the stringyfied object because of the fixed length and mainly because we obviously don't want transactions being public.
        const hash = crypto.createHash('SHA256');
        hash.update(str).end();
        return hash.digest('hex');
    }
}
// Essentially a Linked List of blocks. There should be only one Chain!!!
class Chain {
    constructor() {
        // Adds the Genesis Block to the chain
        this.chain = [new Block(null, new Transaction(100, 'genesis', 'satoshi'))];
    }
    get lastBlock() {
        return this.chain[this.chain.length - 1];
    }
    // Mining to find a number that, combined with the block's nonce, produces a hash that start with 2 zeros.
    mine(nonce) {
        let solution = 1;
        console.log('⛏️ mining...');
        while (true) {
            const hash = crypto.createHash('MD5');
            hash.update((nonce + solution).toString()).end();
            const attempt = hash.digest('hex');
            if (attempt.substr(0, 4) === '0000') {
                console.log(`Solved: ${solution}`);
                return solution;
            }
            solution += 1;
        }
    }
    // Signature to verify before we add the block to the chain
    addBlock(transaction, senderPublicKey, signature) {
        // Verifying the signature of that transaction to see if we can add the block
        const verifier = crypto.createVerify('SHA256');
        verifier.update(transaction.toString());
        // Validade wether the transaction's signature (created with a private key) is valid using the same user's public key.
        // Note that is doesnt decrypt (SHA256 is a one way encryption), it only verified if the transaction has been changed (if it had happened, we would have a different signature and the validation would fail).
        const isValid = verifier.verify(senderPublicKey, signature);
        if (isValid) {
            const newBlock = new Block(this.lastBlock.hash, transaction);
            this.mine(newBlock.nonce);
            this.chain.push(newBlock);
        }
    }
}
Chain.instance = new Chain();
// Wallets are necessary so that only secure and valid transactions happen
class Wallet {
    constructor() {
        // RSA is a full encryption algorithm, so it can be encrypted with the public key and decrypted with the private key.
        // In this case we will use the private key to create a signature (no need to encrypt, only create a signed hash of the document), which can be verified using the public key.
        const keypair = crypto.generateKeyPairSync('rsa', {
            modulusLength: 2048,
            publicKeyEncoding: { type: 'spki', format: 'pem' },
            privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
        });
        this.privateKey = keypair.privateKey;
        this.publicKey = keypair.publicKey;
    }
    sendMoney(amount, receiverPublicKey) {
        // Creating a new transaction with both parties and the amount
        const transaction = new Transaction(amount, this.publicKey, receiverPublicKey);
        // Creating a One-Way encrypted hash of the transaction
        const sign = crypto.createSign('SHA256');
        sign.update(transaction.toString()).end();
        // Signing the encrypted hash with the private key
        // The signature depends on the transcation data (amt and public keys) and the sender private key. However it can be verified as authentic with only the public key.
        const signature = sign.sign(this.privateKey);
        Chain.instance.addBlock(transaction, this.publicKey, signature);
    }
}
const satoshi = new Wallet();
const alice = new Wallet();
const bob = new Wallet();
satoshi.sendMoney(50, bob.publicKey);
bob.sendMoney(50, alice.publicKey);
alice.sendMoney(50, bob.publicKey);
