"use strict";

/********* Imports ********/

const subtle = require("crypto").webcrypto;

import {
    /* The following functions are all of the cryptographic
    primatives that you should need for this assignment.
    See lib.js for details on usage. */
    byteArrayToString,
    genRandomSalt,
    HKDF, // async
    HMACtoHMACKey, // async
    HMACtoAESKey, // async
    encryptWithGCM, // async
    decryptWithGCM, // async
    generateEG, // async
    computeDH, // async
    verifyWithECDSA, // async
  } from "./lib";

/********* Implementation ********/


export default class MessengerClient {
  constructor(certAuthorityPublicKey, govPublicKey) {
      // the certificate authority DSA public key is used to
      // verify the authenticity and integrity of certificates
      // of other users (see handout and receiveCertificate)

      // you can store data as needed in these objects.
      // Feel free to modify their structure as you see fit.
      this.caPublicKey = certAuthorityPublicKey;
      this.govPublicKey = govPublicKey;
      this.conns = {}; // data for each active connection
      //this.certs = {}; // certificates of other users
      this.startKeys = {};
      this.myPrivateKey = 0;
      this.myPublicKey = 0;


      this.encoder = new TextEncoder();
    };

    /*helper to serialize a kvs into bytes
    */

    async kvsAsBytes(kvs) {
      const kvsAsStr = JSON.stringify(kvs);
      const kvsAsBytes = this.encoder.encode(kvsAsStr);
      return kvsAsBytes;
    }

  /**
   * Generate a certificate to be stored with the certificate authority.
   * The certificate must contain the field "username".
   *
   * Arguments:
   *   username: string
   *
   * Return Type: certificate object/dictionary
   */
  async generateCertificate(username) {
    //console.log("gen cert");
    //let salt1 = genRandomSalt();
    let keyPair = await generateEG();
    let publicKey = keyPair.pub;
    //console.log(keyPair);
    let privateKey = keyPair.sec;
    this.myPrivateKey = privateKey;
    this.myPublicKey = publicKey;
    const certificate = {username:username, publicKey: publicKey};// add keys
    //console.log(certificate);
    return certificate;
  }

  /**
   * Generates the data structure that goes in this.conns
   * when a new certificate is received. Starting data
   * for a new conversation
   */
  async newConnectionData(theirPublicKey) {
    //console.log("generate new connection data");
    let data = {}
    data.iSentLastMessage = false;
    data.theirCurrentPublicKey = theirPublicKey;
    data.myCurrentPublicKey = this.myPublicKey;
    data.myCurrentPrivateKey = this.myPrivateKey;
    data.currentSendingKey = 0;
    data.currentReceivingKey = 0;
    data.initialized = false;
    data.numRootKeysComputed = 1;
    let rootKey = await computeDH(this.myPrivateKey, theirPublicKey);
    data.rootKey = rootKey;
    return data;
  }

  /* derive a new root key from a received public key and our old root key*/
  async deriveNewRootKey(oldRootKey, receivedPublicKey) {
    //console.log("derive new root key");
    let newEGKeyPair = await generateEG();
    let myNewPrivateKey = newEGKeyPair.sec;
    let myNewPublicKey = newEGKeyPair.pub;
    let newSharedSecret = await computeDH(myNewPrivateKey, receivedPublicKey);
    //console.log(newSharedSecret);
    //console.log(oldRootKey);
    let twoNewKeys = await HKDF(oldRootKey, newSharedSecret, "arbitrary_and_fixed");
    //console.log('twokey')
    //console.log(twoNewKeys);
    let newRootKey = twoNewKeys[0];
    let newSendingChainKey = twoNewKeys[1];
    //console.log('firstkey');
    //console.log(newRootKey);
    //console.log('secodkey');
    //console.log(newSendingChainKey);
    //console.log(newSendingChainKey);
    let ret =  {newRootKey: newRootKey, newSendingChainKey: newSendingChainKey,
            myNewPublicKey: myNewPublicKey, myNewPrivateKey: myNewPrivateKey};
    //console.log(ret);
    return ret;
  }

  async deriveNewRootKeyWithOldPrivateKey(oldRootKey, receivedPublicKey, myPrivateKey) {
    //console.log("derive new root key with old private key");
    let newSharedSecret = await computeDH(myPrivateKey, receivedPublicKey);
    //console.log(newSharedSecret);
    //console.log(oldRootKey);
    let twoNewKeys = await HKDF(oldRootKey, newSharedSecret, "arbitrary_and_fixed");
    //console.log('twokey')
    //console.log(twoNewKeys);
    let newRootKey = twoNewKeys[0];
    let newSendingChainKey = twoNewKeys[1];
    //console.log('firstkey');
    //console.log(newRootKey);
    //console.log('secodkey');
    //console.log(newSendingChainKey);
    //console.log(newSendingChainKey);
    let ret =  {newRootKey: newRootKey, newSendingChainKey: newSendingChainKey};
    //console.log(ret);
    return ret;
  }

  /* derive a new chain key and message key from an old message key */
  async deriveNewMessageKey(oldMessageKey) {
    //console.log('derive message key');
    let constant1 = 'Rayan cant code';
    let constant2 = 'robbie can code';
    //console.log(oldMessageKey);
    let newChainKey = await HMACtoHMACKey(oldMessageKey, constant1);
    let newMessageKey = await HMACtoAESKey(oldMessageKey, constant2);
    let govMessageKeyBytes = await HMACtoAESKey(oldMessageKey, constant2, true);
    return [newChainKey, newMessageKey, govMessageKeyBytes];
  }


  /**
   * Receive and store another user's certificate.
   *
   * Arguments:
   *   certificate: certificate object/dictionary
   *   signature: string
   *
   * Return Type: void
   */
  async receiveCertificate(certificate, signature) {
    //console.log("receive cert");
    //do verification
    const certificateAsStr = JSON.stringify(certificate);
    const certificateAsArray = this.encoder.encode((certificateAsStr));
    let verification = await verifyWithECDSA(this.caPublicKey, certificateAsArray, signature);
    //console.log('aqui');
    //this.certs[signature] = certificate;
    //console.log(certificate);
    this.startKeys[certificate.username] = certificate.publicKey;
    this.conns[certificate.username] = await this.newConnectionData(certificate.publicKey);
    //console.log(this.conns[certificate.username]);
    //console.log(this.startKeys);
  }
/*
  async printKey(key) {
    console.log(subtle.exportKey('raw', key));
  }
  */

  async encryptForGovernment(sessionKeyBytes) {
    //console.log('encrypting for gov');
    let ivgov = genRandomSalt();
    let egKeys = await generateEG();
    let sharedSecret = await computeDH(egKeys.sec, this.govPublicKey);
    let aesKey = await HMACtoAESKey(sharedSecret, "AES-generation");
    let govData = await encryptWithGCM(aesKey, sessionKeyBytes, ivgov);
    let vgov = egKeys.pub;// additional data for government elgamal. Used to decrypt session ket
    let cgov = govData; //government ciphertext, which is session key encrypted
    return [vgov, cgov, ivgov];
  }

  /**
   * Generate the message to be sent to another user.
   *
   * Arguments:
   *   name: string
   *   plaintext: string
   *
   * Return Type: Tuple of [dictionary, string]
   */
  async sendMessage(name, plaintext) {
    //console.log('sendmessage');
    let oldRootKey = this.conns[name].rootKey;
    //console.log(oldRootKey);
    let curData = this.conns[name];
    if (! curData.iSentLastMessage) {
      curData.iSentLastMessage = true;
      let data = await this.deriveNewRootKey(oldRootKey, curData.theirCurrentPublicKey);
      curData.numRootKeysComputed += 1;
      curData.myCurrentPrivateKey = data.myNewPrivateKey;
      curData.myCurrentPublicKey = data.myNewPublicKey;
      curData.currentSendingKey = data.newSendingChainKey;
      curData.rootKey = data.newRootKey;
    }

    let chainAndMsgKeys = await this.deriveNewMessageKey(curData.currentSendingKey);
    let newChainKey = chainAndMsgKeys[0];
    let newMessageKey = chainAndMsgKeys[1];
    let govMessageKeyBytes = chainAndMsgKeys[2];
    curData.currentSendingKey = newChainKey;
    let ivRecipient = genRandomSalt();
    let govData = await this.encryptForGovernment(govMessageKeyBytes);
    //console.log(govData);

    const header = {senderPublicKey: curData.myCurrentPublicKey, receiver_iv:ivRecipient,
                    vGov: govData[0], cGov:govData[1] , ivGov:govData[2]};
    const headerAsBytes = await this.kvsAsBytes(header);
    const ciphertext = await encryptWithGCM(newMessageKey, plaintext, ivRecipient, headerAsBytes);
    return [header, ciphertext];
  }


  /**
   * Decrypt a message received from another user.
   *
   * Arguments:
   *   name: string
   *   [header, ciphertext]: Tuple of [dictionary, string]
   *
   * Return Type: string
   */
  async receiveMessage(name, [header, ciphertext]) {
    //console.log("receive message");
    let headerAsBytes = await this.kvsAsBytes(header);
    let curData = this.conns[name];
    if (curData.iSentLastMessage || ! curData.initialized) {
      curData.initialized = true;
      curData.iSentLastMessage = false;
      curData.theirCurrentPublicKey = header.senderPublicKey;
      let data = await this.deriveNewRootKeyWithOldPrivateKey(curData.rootKey, curData.theirCurrentPublicKey, curData.myCurrentPrivateKey);
      curData.numRootKeysComputed += 1;
      //let ret =  {newRootKey: newRootKey, newSendingChainKey: newSendingChainKey,
      curData.currentReceivingKey = data.newSendingChainKey;
      curData.rootKey = data.newRootKey;
    }
    let chainAndMsgKeys = await this.deriveNewMessageKey(curData.currentReceivingKey);
    let newChainKey = chainAndMsgKeys[0];
    let newMessageKey = chainAndMsgKeys[1];
    curData.currentReceivingKey = newChainKey;
    let plaintextAsBytes = await decryptWithGCM(newMessageKey, ciphertext, header.receiver_iv, headerAsBytes);
    let plaintextAsStr = byteArrayToString(plaintextAsBytes);
    //console.log(plaintextAsStr);
    return plaintextAsStr;
  }
};
