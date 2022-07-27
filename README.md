# End-to-End-Encrypted-Messaging-Client

In this project I built an end-to-end encrypted messaging client using the [Double Ratchet algorithm](https://signal.org/docs/specifications/doubleratchet/) used by Whatsapp and Signal. Key derivation utilized the HDKF function based on the HMAC message authentication code. Also featured additional use of AES-GCM as the symmetric encryption algorithm for encrypting messages.

The goal of the project is to ensure forward secrecy and functional break-in recovery. 
