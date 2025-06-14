This is my JavaCard application used for encrypting and decrypting files. It uses a script that installs, deploys, and sends the necessary APDUs for testing, then undeploys the applet.

It uses Oracle JavaCard techinology for building the applet, and a Java client for testing. The client sends an APDU with a 16 byte key used for AES-ECB encryption, and then chunks of 128 bytes for encryption decryption.

The JavaCard Applet supports the following operations:
INS_SET_KEY = 0x10;
INS_ENCRYPT = 0x20;
INS_DECRYPT = 0x30;
