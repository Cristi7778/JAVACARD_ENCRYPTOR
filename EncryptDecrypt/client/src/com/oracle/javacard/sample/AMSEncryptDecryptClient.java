package com.oracle.javacard.sample;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.LinkedList;
import java.util.List;
import java.util.Properties;
import java.util.stream.IntStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;

import javax.smartcardio.Card;
import javax.smartcardio.CardChannel;
import javax.smartcardio.CardException;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import javax.smartcardio.TerminalFactory;

import com.oracle.javacard.ams.AMService;
import com.oracle.javacard.ams.AMServiceFactory;
import com.oracle.javacard.ams.AMSession;
import com.oracle.javacard.ams.config.AID;
import com.oracle.javacard.ams.config.CAPFile;
import com.oracle.javacard.ams.script.APDUScript;
import com.oracle.javacard.ams.script.ScriptFailedException;
import com.oracle.javacard.ams.script.Scriptable;

public class AMSEncryptDecryptClient {

	static final String isdAID = "aid:A000000151000000";
	static final String sAID_CAP = "aid:A00000009903010C06";
	static final String sAID_AppletClass = "aid:A00000009903010C0601";
	static final String sAID_AppletInstance = "aid:A00000009903010C0601";
	static final CommandAPDU selectApplet = new CommandAPDU(0x00, 0xA4, 0x04, 0x00, AID.from(sAID_AppletInstance).toBytes(), 256);
    static final byte INS_SET_KEY = (byte) 0x10; 
	static final byte INS_ENCRYPT = (byte) 0x20; 
	static final byte INS_DECRYPT = (byte) 0x30; 
	static final int CHUNK_SIZE = 128;
	public static void main(String[] args) {

		int iResult = 0;
        byte[] keyData = new byte[] {
            (byte)0xFF, (byte)0xEE,
            (byte)0xDD, (byte)0xCC,
            (byte)0xBB, (byte)0xAA,
            (byte)0x99, (byte)0x88,
            (byte)0x77, (byte)0x66,
            (byte)0x55, (byte)0x44,
            (byte)0x33, (byte)0x22,
            (byte)0x11, (byte)0x00
        };
		
		try {
			CAPFile appFile = CAPFile.from(getArg(args, "cap"));
			Properties props = new Properties();
			props.load(new FileInputStream(getArg(args, "props")));

			AMService ams = AMServiceFactory.getInstance("GP2.2");
			ams.setProperties(props);
			for (String key : ams.getPropertiesKeys()) {
				System.out.println(key + " = " + ams.getProperty(key));
			}

			AMSession deploy = ams.openSession(isdAID)
					.load(sAID_CAP, appFile.getBytes())
					.install(sAID_CAP,
							sAID_AppletClass, sAID_AppletInstance, new byte[] {0x05, 0x01, 0x02, 0x03, 0x04, 0x05})
					.close();

			AMSession undeploy = ams.openSession(isdAID)
					.uninstall(sAID_AppletInstance)
					.unload(sAID_CAP)
					.close();

			TestScript testScript = new TestScript()
					.append(deploy)
					.append(selectApplet);
					CommandAPDU setKeyApdu=new CommandAPDU(0x00, INS_SET_KEY, 0x00, 0x00, keyData,keyData.length);
                    testScript.append(setKeyApdu);
					TestScript undeployScript= new TestScript().append(undeploy);

			CardTerminal t = getTerminal("socket", "127.0.0.1", "9025");

			if (t.waitForCardPresent(10000)) {
				System.out.println("Connection to simulator established: "+ t.getName());
				Card c = t.connect("*");
				System.out.println(getFormattedATR(c.getATR().getBytes()));

				List<ResponseAPDU> responses = testScript.run(c.getBasicChannel());
				sendEncryptApdu(c.getBasicChannel());
				sendDecryptApdu(c.getBasicChannel());
				responses.addAll(undeployScript.run(c.getBasicChannel()));

				c.disconnect(true);

				System.out.println("Responses count: " + responses.size());
			}
			else {
				System.out.println("Connection to simulator failed");
				iResult = -1;
			}

		} catch (NoSuchAlgorithmException | NoSuchProviderException | CardException | ScriptFailedException | IOException e) {
			e.printStackTrace();
			iResult = -1;
		}
		System.exit(iResult);
		
	}

	private static void sendEncryptApdu(CardChannel channel)throws IOException, CardException{
		byte[] inputBytes=new byte[0];
		short count=0;
		try{
		Path path = Paths.get("input.txt");
		inputBytes = Files.readAllBytes(path);
	    } catch (IOException e) {
		e.printStackTrace();
		System.exit(1);
		}
		int paddingLen = 16 - (inputBytes.length % 16);
		if (paddingLen == 0) paddingLen = 16;

		int paddedLen = inputBytes.length + paddingLen;
		byte[] paddedInput = new byte[paddedLen];

		System.arraycopy(inputBytes, 0, paddedInput, 0, inputBytes.length);

		Arrays.fill(paddedInput, inputBytes.length, paddedLen, (byte) paddingLen);
		FileOutputStream fout=null;
		try{
			fout=new FileOutputStream(new File("ciphertext.txt"));
		} catch(Exception e){
			e.printStackTrace();
		}
		for (int i = 0; i < paddedInput.length; i += CHUNK_SIZE) {
			count++;
			int end = Math.min(i + CHUNK_SIZE, paddedInput.length);
			byte[] chunk = Arrays.copyOfRange(paddedInput, i, end);
			CommandAPDU encryptApdu = new CommandAPDU(0x00, INS_ENCRYPT, 0x00, 0x00, chunk,CHUNK_SIZE);
			TestScript.print(encryptApdu);
			ResponseAPDU response = channel.transmit(encryptApdu);
			TestScript.print(response);
			if(response.getSW() == 0x9000) {
				fout.write(response.getData());
			} else {
				System.err.println("Error response: " + response.getSW());
			}
			
		}
		System.out.println("\nRan the send encrypt APDU script with "+count+" chunks\n");

	}
	private static void sendDecryptApdu(CardChannel channel)throws IOException, CardException{
		byte[] targetBytes = Files.readAllBytes(Paths.get("ciphertext.txt"));
		short count=0;
		try (FileOutputStream fout = new FileOutputStream("restored.txt")) {
			for (int i = 0; i < targetBytes.length; i += CHUNK_SIZE) {
				count++;
				int end = Math.min(i + CHUNK_SIZE, targetBytes.length);
				byte[] chunk = Arrays.copyOfRange(targetBytes, i, end);
	
				CommandAPDU decryptApdu = new CommandAPDU(0x00,INS_DECRYPT, 0x00, 0x00, chunk, CHUNK_SIZE);
				TestScript.print(decryptApdu);
	
				ResponseAPDU response = channel.transmit(decryptApdu);
				TestScript.print(response);
	
				if (response.getSW() == 0x9000) {
					fout.write(response.getData());
				} else {
					System.err.println("Error response: " + response.getSW());
				}
			}
			System.out.println("\nRan the send decrypt APDU script with "+count+" chunks\n");
		}
	}

	private static String getArg(String[] args, String argName) throws IllegalArgumentException {
		String value = null;

		for (String param : args) {
			if (param.startsWith("-" + argName + "=")) {
				value = param.substring(param.indexOf('=') + 1);
			}
		}

		if(value == null || value.length() == 0) {
			throw new IllegalArgumentException("Argument " + argName + " is missing");
		}
		return value;
	}

	private static String getFormattedATR(byte[] ATR) {
		StringBuilder sb = new StringBuilder();
		for (byte b : ATR) {
			sb.append(String.format("%02X ", b));
		}
		return String.format("ATR: [%s]", sb.toString().trim());
	}

	private static CardTerminal getTerminal(String... connectionParams) throws NoSuchAlgorithmException, NoSuchProviderException, CardException {
		TerminalFactory tf;
		String connectivityType = connectionParams[0];
		if (connectivityType.equals("socket")) {
			String ipaddr = connectionParams[1];
			String port = connectionParams[2];
			tf = TerminalFactory.getInstance("SocketCardTerminalFactoryType",
					List.of(new InetSocketAddress(ipaddr, Integer.parseInt(port))),
					"SocketCardTerminalProvider");
		} else {
			tf = TerminalFactory.getDefault();
		}
		return tf.terminals().list().get(0);
	}

	private static class TestScript extends APDUScript {
		private List<CommandAPDU>  commands = new LinkedList<>();
		private List<ResponseAPDU> responses = new LinkedList<>();
		private int index = 0;

		public List<ResponseAPDU> run(CardChannel channel) throws ScriptFailedException {
			return super.run(channel, c -> lookupIndex(c), r -> !isExpected(r));
		}

		@Override
		public TestScript append(Scriptable<CardChannel, CommandAPDU, ResponseAPDU> other) {
			super.append(other);
			return this;
		}

		public TestScript append(CommandAPDU apdu, ResponseAPDU expected) {
			super.append(apdu);
			this.commands.add(apdu);
			this.responses.add(expected);
			return this;
		}

		public TestScript append(CommandAPDU apdu) {
			super.append(apdu);
			return this;
		}

		private CommandAPDU lookupIndex(CommandAPDU apdu) {
			print(apdu);
			this.index = IntStream.range(0, this.commands.size())
			        .filter(i -> apdu == this.commands.get(i))
					.findFirst()
					.orElse(-1);
			return apdu;
		}

		private boolean isExpected(ResponseAPDU response) {

			ResponseAPDU expected = (index < 0)? response : this.responses.get(index);
			if (!response.equals(expected)) {
				System.out.println("Received: ");
				print(response);
				System.out.println("Expected: ");
				print(expected);
				return false;
			}
			print(response);
			return true;
		}

		protected static void print(CommandAPDU apdu) {
			StringBuilder sb = new StringBuilder();
			sb.append(String.format("%02X%02X%02X%02X %02X[", apdu.getCLA(), apdu.getINS(), apdu.getP1(), apdu.getP2(), apdu.getNc()));
			for (byte b : apdu.getData()) {
				sb.append(String.format("%02X", b));
			}
			sb.append("]");
			System.out.format("[%1$tF %1$tT %1$tL %1$tZ] [APDU-C] %2$s %n", System.currentTimeMillis(), sb.toString());
		}

		protected static void print(ResponseAPDU apdu) {
			byte[] bytes = apdu.getData();
			StringBuilder sb = new StringBuilder();
			for (byte b : bytes) {
				sb.append(String.format("%02X", b));
			}
			System.out.format("[%1$tF %1$tT %1$tL %1$tZ] [APDU-R] [%2$s] SW:%3$04X %n", System.currentTimeMillis(), sb.toString(), apdu.getSW());
		}
	}
}