import * as crypto from 'crypto';

// TypeScript for Object Oriented principles is really helpful here

// Transfering funds is the main part of the process
class Transaction {
    constructor(
        public amount: number,
        public sender: string,   // public key
        public receiver: string  // public key
    ){}

    toString() {
        // Stringyfies the object for serialization/encryption
        return JSON.stringify(this);
    }
}

// Container for multiple transactions (single transaction in this case for simplicity)
// A block is like an element on a Linked List (Chain)
class Block {

    // One-Time-Use Random number associated with the block to create the Proof of Work
    public nonce = Math.round(Math.random() * 999999999)

    constructor(
        // Hashing Functions allows us to take a string of arbitraty size and map it to a value of fixed length (hash or hash digest).
        // Once the hash is created it CANNOT be reversed back to the original value, but you can compare two hashes to ensure it's the same initial value. That's important here because we can ensure linked blocks were not manipulated.
        public prevHash: string | null,
        public transaction: Transaction,

        // Blocks are placed in chronological order
        public time = Date.now()
    ){}

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
    public static instance = new Chain();

    chain: Block[];

    constructor() {
        // Adds the Genesis Block to the chain
        this.chain = [new Block(null, new Transaction(100, 'genesis', 'satoshi'))];
    }

    get lastBlock() {
        return this.chain[this.chain.length - 1];
    }

    // Mining to find a number that, combined with the block's nonce, produces a hash that start with 2 zeros.
    mine(nonce: number) {
        let solution = 1;
        console.log('⛏️ mining...')

        while(true) {

            const hash = crypto.createHash('MD5')
            hash.update((nonce + solution).toString()).end();

            const attempt = hash.digest('hex');
            if (attempt.substr(0,4) === '0000') {
                console.log(`Solved: ${solution}`)
                return solution;
            }

            solution += 1;
        }

    }

    // Signature to verify before we add the block to the chain
    addBlock(transaction: Transaction, senderPublicKey: string, signature: Buffer) {

        // Verifying the signature of that transaction to see if we can add the block
        const verifier = crypto.createVerify('SHA256');
        verifier.update(transaction.toString());

        // Validade wether the transaction's signature (created with a private key) is valid using the same user's public key.
        // Note that is doesnt decrypt (SHA256 is a one way encryption), it only verified if the transaction has been changed (if it had happened, we would have a different signature and the validation would fail).
        const isValid = verifier.verify(senderPublicKey, signature);

        if (isValid) {
            const newBlock = new Block(this.lastBlock.hash, transaction);
            this.mine(newBlock.nonce);
            this.chain.push(newBlock)
        }
    }
}

// Wallets are necessary so that only secure and valid transactions happen
class Wallet {
    // Key to receive money
    public publicKey: string;

    // Key to give money
    public privateKey: string;

    constructor() {
        // RSA is a full encryption algorithm, so it can be encrypted with the public key and decrypted with the private key.
        // In this case we will use the private key to create a signature (no need to encrypt, only create a signed hash of the document), which can be verified using the public key.
        const keypair = crypto.generateKeyPairSync('rsa', {
            modulusLength: 2048,
            publicKeyEncoding: { type: 'spki', format: 'pem' },
            privateKeyEncoding: { type: 'pkcs8', format: 'pem'},
        });

        this.privateKey = keypair.privateKey;
        this.publicKey = keypair.publicKey;
    }

    sendMoney(amount: number, receiverPublicKey: string) {

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