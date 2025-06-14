package com.oracle;

import java.io.IOException;

import javax.print.attribute.standard.MediaSize.ISO;

import javacard.framework.*;
import javacard.security.*;
import javacardx.crypto.*;

public class EncryptDecryptApplet extends Applet {
    private static final byte INS_SET_KEY = (byte) 0x10;
    private static final byte INS_ENCRYPT = (byte) 0x20;
    private static final byte INS_DECRYPT = (byte) 0x30;

    private AESKey aesKey;
    private Cipher aesCipher;

    private EncryptDecryptApplet() {
        aesKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES_TRANSIENT_RESET,
                                               KeyBuilder.LENGTH_AES_128, false);
        aesCipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_ECB_NOPAD, false);

        register();
    }

    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new EncryptDecryptApplet();
    }

    public void process(APDU apdu) {
        if (selectingApplet()) return;
        byte[] buffer = apdu.getBuffer();
        switch (buffer[ISO7816.OFFSET_INS]) {
            case INS_SET_KEY:
                setAESKey(apdu);
                break;

                case INS_ENCRYPT:
                aesCipher.init(aesKey, Cipher.MODE_ENCRYPT);
                processAES(apdu);
                break;
    
                case INS_DECRYPT:   
                aesCipher.init(aesKey, Cipher.MODE_DECRYPT);
                processAES(apdu);
                break;

            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
     }  
    }
        
    

    private void setAESKey(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        byte numBytes = buffer[ISO7816.OFFSET_LC];
        short bytesRead =  (apdu.setIncomingAndReceive());
        if ((numBytes != 16) || (bytesRead != 16)) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        aesKey.setKey(buffer, ISO7816.OFFSET_CDATA);
        apdu.setOutgoing();
        apdu.setOutgoingLength(bytesRead);
        apdu.sendBytes(ISO7816.OFFSET_CDATA, bytesRead);
    }

    private void processAES( APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        byte ins = buffer[ISO7816.OFFSET_INS];
        short bytesRead = apdu.setIncomingAndReceive();

        if ((bytesRead % 16) != 0) {
           ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        short outputLength = aesCipher.doFinal(buffer, ISO7816.OFFSET_CDATA, bytesRead, buffer, (short) 0);

        apdu.setOutgoing();
        apdu.setOutgoingLength(outputLength);
        apdu.sendBytes((short) 0, outputLength);
    }

    
}
