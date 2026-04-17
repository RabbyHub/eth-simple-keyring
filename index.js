const { EventEmitter } = require('events');
// const Wallet = require('ethereumjs-wallet').default;
const ethUtil = require('@ethereumjs/util');
const sigUtil = require('@metamask/eth-sig-util');
const { keccak256 } = require('ethereum-cryptography/keccak');
const { getRandomBytesSync } = require('ethereum-cryptography/random');
const { privateKeyToAccount } = require('viem/accounts');
const { Transaction: TempoTransaction } = require('viem/tempo');

const type = 'Simple Key Pair';

function generateKey() {
  const privateKey = getRandomBytesSync(32);

  if (!ethUtil.isValidPrivate(privateKey)) {
    throw new Error(
      'Private key does not satisfy the curve requirements (ie. it is invalid)',
    );
  }
  return privateKey;
}

function add0x(hexadecimal) {
  if (hexadecimal.startsWith('0x')) {
    return hexadecimal;
  }

  if (hexadecimal.startsWith('0X')) {
    return `0x${hexadecimal.substring(2)}`;
  }

  return `0x${hexadecimal}`;
}

function isTempoTransactionType(type) {
  return type === 118 || type === '0x76' || type === '0X76';
}

function normalizePrivateKeyHex(privateKey) {
  let hex;

  if (typeof privateKey === 'string') {
    hex =
      privateKey.startsWith('0x') || privateKey.startsWith('0X')
        ? privateKey.slice(2)
        : privateKey;
  } else if (
    privateKey &&
    (privateKey instanceof Uint8Array || Buffer.isBuffer(privateKey))
  ) {
    hex = ethUtil.stripHexPrefix(ethUtil.bytesToHex(privateKey));
  } else {
    throw new Error('invalid private key source');
  }

  if (!/^[0-9a-fA-F]{64}$/.test(hex)) {
    throw new Error(`invalid private key hex length: ${hex.length}`);
  }

  return `0x${hex.toLowerCase()}`;
}

function toBigIntSafe(value) {
  if (value === null || typeof value === 'undefined') return undefined;
  if (value === '0x' || value === '0X') return BigInt(0);
  if (typeof value === 'bigint') return value;
  if (typeof value === 'number') return BigInt(value);
  if (typeof value === 'string' && value.length) {
    try {
      return BigInt(value);
    } catch (e) {
      return undefined;
    }
  }
  return undefined;
}

function normalizeHexValue(value) {
  if (typeof value === 'string') {
    if (!value.length || value === '0x' || value === '0X') return '0x0';
    return value;
  }
  return value;
}

function normalizeTempoCalls(tx) {
  if (Array.isArray(tx.calls) && tx.calls.length) {
    return tx.calls.map((call) => ({
      to: call && call.to ? call.to : tx.to,
      data: call ? call.data : tx.data,
      value:
        call && typeof call.value !== 'undefined'
          ? toBigIntSafe(normalizeHexValue(call.value))
          : typeof tx.value !== 'undefined'
          ? toBigIntSafe(normalizeHexValue(tx.value))
          : BigInt(0),
    }));
  }

  return [
    {
      to: tx.to,
      data: tx.data,
      value:
        typeof tx.value !== 'undefined'
          ? toBigIntSafe(normalizeHexValue(tx.value))
          : BigInt(0),
    },
  ];
}

function normalizeTempoTxForSign(tx) {
  const nextTx = {
    ...tx,
    calls: normalizeTempoCalls(tx || {}),
  };

  const bigintFields = [
    'gas',
    'gasLimit',
    'gasPrice',
    'maxFeePerGas',
    'maxPriorityFeePerGas',
    'nonce',
    'nonceKey',
    'value',
  ];

  bigintFields.forEach((field) => {
    if (typeof nextTx[field] === 'undefined') return;
    const normalized = toBigIntSafe(nextTx[field]);
    if (typeof normalized === 'undefined') return;
    nextTx[field] = normalized;
  });

  if (typeof nextTx.chainId !== 'undefined') {
    const chainId = Number(nextTx.chainId);
    if (!Number.isNaN(chainId)) nextTx.chainId = chainId;
  }

  ['validBefore', 'validAfter'].forEach((field) => {
    if (typeof nextTx[field] === 'undefined') return;
    const value = nextTx[field];
    try {
      const normalized =
        typeof value === 'number'
          ? value
          : typeof value === 'bigint'
          ? Number(value)
          : Number(value);
      if (!Number.isNaN(normalized)) nextTx[field] = normalized;
    } catch (e) {
      // ignore invalid values and keep original payload
    }
  });

  return nextTx;
}

function extractTempoSignatureParts(parsedTx) {
  const signatureEnvelope =
    parsedTx && parsedTx.signature ? parsedTx.signature : {};
  const signature = signatureEnvelope.signature || signatureEnvelope;

  const r = toBigIntSafe(
    typeof parsedTx.r !== 'undefined' ? parsedTx.r : signature.r,
  );
  const s = toBigIntSafe(
    typeof parsedTx.s !== 'undefined' ? parsedTx.s : signature.s,
  );
  const yParity = Number(
    typeof parsedTx.yParity !== 'undefined'
      ? parsedTx.yParity
      : typeof signature.yParity !== 'undefined'
      ? signature.yParity
      : typeof parsedTx.v !== 'undefined'
      ? Number(parsedTx.v) - 27
      : 0,
  );

  if (typeof r === 'undefined' || typeof s === 'undefined') {
    throw new Error('invalid tempo signature from viem');
  }

  return {
    r,
    s,
    yParity,
    v: BigInt(yParity + 27),
  };
}

class SimpleKeyring extends EventEmitter {
  constructor(opts) {
    super();
    this.type = type;
    this.wallets = [];
    this.deserialize(opts);
  }

  serialize() {
    return Promise.resolve(
      this.wallets.map((w) =>
        ethUtil.stripHexPrefix(ethUtil.bytesToHex(w.privateKey)),
      ),
    );
  }

  deserialize(privateKeys = []) {
    return new Promise((resolve, reject) => {
      try {
        this.wallets = privateKeys.map((hexPrivateKey) => {
          let privk = hexPrivateKey;
          if (!privk.startsWith('0x')) {
            privk = ethUtil.addHexPrefix(privk);
          }
          const privateKey = ethUtil.hexToBytes(privk);
          const publicKey = ethUtil.privateToPublic(privateKey);
          return { privateKey, publicKey };
        });
      } catch (e) {
        reject(new Error('invalid private key'));
      }
      resolve();
    });
  }

  addAccounts(n = 1) {
    const newWallets = [];
    for (let i = 0; i < n; i++) {
      const privateKey = generateKey();
      newWallets.push({
        privateKey,
        publicKey: ethUtil.privateToPublic(privateKey),
      });
    }
    this.wallets = this.wallets.concat(newWallets);
    const hexWallets = newWallets.map(({ publicKey }) =>
      add0x(ethUtil.bytesToHex(ethUtil.publicToAddress(publicKey))),
    );
    return Promise.resolve(hexWallets);
  }

  getAccounts() {
    return Promise.resolve(
      this.wallets.map(({ publicKey }) => {
        return add0x(ethUtil.bytesToHex(ethUtil.publicToAddress(publicKey)));
      }),
    );
  }

  signEip7702Authorization(address, authorization, opts = {}) {
    const privKey = ethUtil.addHexPrefix(this.getPrivateKeyFor(address, opts));
    return Promise.resolve(
      sigUtil.signEIP7702Authorization({
        privateKey: privKey,
        authorization,
      }),
    );
  }

  // tx is an instance of the ethereumjs-transaction class.
  signTransaction(address, tx, opts = {}) {
    if (isTempoTransactionType(tx && tx.type)) {
      const privateKey = normalizePrivateKeyHex(
        this.getPrivateKeyFor(address, opts),
      );
      const account = privateKeyToAccount(privateKey);
      const tempoTx = normalizeTempoTxForSign(tx || {});

      return account
        .signTransaction(tempoTx, {
          serializer: TempoTransaction.serialize,
        })
        .then((serializedTransaction) => {
          const parsed = TempoTransaction.deserialize(serializedTransaction);
          const signature = extractTempoSignatureParts(parsed);
          return {
            ...signature,
            serializedTransaction,
          };
        });
    }

    const privKey = ethUtil.addHexPrefix(this.getPrivateKeyFor(address, opts));
    const signedTx = tx.sign(Buffer.from(privKey, 'hex'));
    // Newer versions of Ethereumjs-tx are immutable and return a new tx object
    return Promise.resolve(signedTx === undefined ? tx : signedTx);
  }

  // For eth_sign, we need to sign arbitrary data:
  signMessage(address, data, opts = {}) {
    const message = ethUtil.stripHexPrefix(data);
    const privKey = this.getPrivateKeyFor(address, opts);
    const msgSig = ethUtil.ecsign(Buffer.from(message, 'hex'), privKey);
    const rawMsgSig = sigUtil.concatSig(msgSig.v, msgSig.r, msgSig.s);
    return Promise.resolve(rawMsgSig);
  }

  // For eth_sign, we need to sign transactions:
  newGethSignMessage(withAccount, msgHex, opts = {}) {
    const privKey = this.getPrivateKeyFor(withAccount, opts);
    const msgBuffer = ethUtil.toBuffer(msgHex);
    const msgHash = ethUtil.hashPersonalMessage(msgBuffer);
    const msgSig = ethUtil.ecsign(msgHash, privKey);
    const rawMsgSig = sigUtil.concatSig(msgSig.v, msgSig.r, msgSig.s);
    return Promise.resolve(rawMsgSig);
  }

  // For personal_sign, we need to prefix the message:
  signPersonalMessage(address, msgHex, opts = {}) {
    const privKey = ethUtil.stripHexPrefix(
      ethUtil.bytesToHex(this.getPrivateKeyFor(address, opts)),
    );
    const sig = sigUtil.personalSign({
      privateKey: privKey,
      data: msgHex,
    });
    return Promise.resolve(sig);
  }

  // For eth_decryptMessage:
  decryptMessage(withAccount, encryptedData) {
    const wallet = this._getWalletForAccount(withAccount);
    const privKey = ethUtil.stripHexPrefix(
      ethUtil.bytesToHex(wallet.privateKey),
    );
    const sig = sigUtil.decrypt({
      encryptedData,
      privateKey: privKey,
    });
    return Promise.resolve(sig);
  }

  // personal_signTypedData, signs data along with the schema
  signTypedData(withAccount, typedData, opts = { version: 'V1' }) {
    switch (opts.version) {
      case 'V1':
        return this.signTypedData_v1(withAccount, typedData, opts);
      case 'V3':
        return this.signTypedData_v3(withAccount, typedData, opts);
      case 'V4':
        return this.signTypedData_v4(withAccount, typedData, opts);
      default:
        return this.signTypedData_v1(withAccount, typedData, opts);
    }
  }

  // personal_signTypedData, signs data along with the schema
  signTypedData_v1(withAccount, typedData, opts = {}) {
    const privKey = ethUtil.stripHexPrefix(
      ethUtil.bytesToHex(this.getPrivateKeyFor(withAccount, opts)),
    );
    const sig = sigUtil.signTypedData({
      privateKey: Buffer.from(privKey, 'hex'),
      data: typedData,
      version: sigUtil.SignTypedDataVersion.V1,
    });
    return Promise.resolve(sig);
  }

  // personal_signTypedData, signs data along with the schema
  signTypedData_v3(withAccount, typedData, opts = {}) {
    const privKey = ethUtil.stripHexPrefix(
      ethUtil.bytesToHex(this.getPrivateKeyFor(withAccount, opts)),
    );
    const sig = sigUtil.signTypedData({
      privateKey: Buffer.from(privKey, 'hex'),
      data: typedData,
      version: sigUtil.SignTypedDataVersion.V3,
    });
    return Promise.resolve(sig);
  }

  // personal_signTypedData, signs data along with the schema
  signTypedData_v4(withAccount, typedData, opts = {}) {
    const privKey = ethUtil.stripHexPrefix(
      ethUtil.bytesToHex(this.getPrivateKeyFor(withAccount, opts)),
    );
    const sig = sigUtil.signTypedData({
      privateKey: Buffer.from(privKey, 'hex'),
      data: typedData,
      version: sigUtil.SignTypedDataVersion.V4,
    });
    return Promise.resolve(sig);
  }

  // get public key for nacl
  getEncryptionPublicKey(withAccount, opts = {}) {
    const privKey = ethUtil.stripHexPrefix(
      ethUtil.bytesToHex(this.getPrivateKeyFor(withAccount, opts)),
    );
    const publicKey = sigUtil.getEncryptionPublicKey(privKey);
    return Promise.resolve(publicKey);
  }

  getPrivateKeyFor(address, opts = {}) {
    if (!address) {
      throw new Error('Must specify address.');
    }
    const wallet = this._getWalletForAccount(address, opts);
    return wallet.privateKey;
  }

  // returns an address specific to an app
  getAppKeyAddress(address, origin) {
    if (!origin || typeof origin !== 'string') {
      throw new Error(`'origin' must be a non-empty string`);
    }
    return new Promise((resolve, reject) => {
      try {
        const wallet = this._getWalletForAccount(address, {
          withAppKeyOrigin: origin,
        });
        const appKeyAddress = sigUtil.normalize(
          ethUtil.bytesToHex(ethUtil.publicToAddress(wallet.publicKey)),
        );
        return resolve(appKeyAddress);
      } catch (e) {
        return reject(e);
      }
    });
  }

  // exportAccount should return a hex-encoded private key:
  exportAccount(address, opts = {}) {
    const wallet = this._getWalletForAccount(address, opts);
    return Promise.resolve(ethUtil.bytesToHex(wallet.privateKey));
  }

  removeAccount(address) {
    if (
      !this.wallets
        .map(({ publicKey }) =>
          add0x(
            ethUtil.bytesToHex(ethUtil.publicToAddress(publicKey)),
          ).toLowerCase(),
        )
        .includes(address.toLowerCase())
    ) {
      throw new Error(`Address ${address} not found in this keyring`);
    }

    this.wallets = this.wallets.filter(
      ({ publicKey }) =>
        add0x(
          ethUtil.bytesToHex(ethUtil.publicToAddress(publicKey)),
        ).toLowerCase() !== address.toLowerCase(),
    );
  }

  /**
   * @private
   */
  _getWalletForAccount(account, opts = {}) {
    const address = sigUtil.normalize(account);
    let wallet = this.wallets.find(
      ({ publicKey }) =>
        add0x(
          ethUtil.bytesToHex(ethUtil.publicToAddress(publicKey)),
        ).toLowerCase() === address.toLowerCase(),
    );
    if (!wallet) {
      throw new Error('Simple Keyring - Unable to find matching address.');
    }

    if (opts.withAppKeyOrigin) {
      const { privateKey } = wallet;
      const appKeyOriginBuffer = Buffer.from(opts.withAppKeyOrigin, 'utf8');
      const appKeyBuffer = Buffer.concat([privateKey, appKeyOriginBuffer]);
      const appKeyPrivateKey = keccak256(appKeyBuffer);
      const appKeyPublicKey = ethUtil.privateToPublic(appKeyPrivateKey);
      wallet = { privateKey: appKeyPrivateKey, publicKey: appKeyPublicKey };
    }

    return wallet;
  }
}

SimpleKeyring.type = type;
module.exports = SimpleKeyring;
