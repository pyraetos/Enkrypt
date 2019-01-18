package net.pyraetos;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.util.Random;
import java.util.Scanner;

public class Enkrypt {
	
	private static Scanner in = new Scanner(System.in);
	public static final boolean DEBUG = false;
	public static final String PRE = "<Enkrypt> ";
	
	public static final int[] RC = {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36};
	
	public static final int SBOX[] =  {0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
									   0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
									   0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
									   0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
									   0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
									   0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
									   0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
									   0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
									   0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
									   0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
									   0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
									   0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
									   0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
									   0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
									   0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
									   0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16};
	
	public static final int INVERSE_SBOX[] = {0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
											  0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
											  0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
											  0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
											  0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
											  0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
											  0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
											  0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
											  0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
											  0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
											  0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
											  0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
											  0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
											  0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
											  0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
											  0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d};


	public static final int[][] IV = {
			{0,0,0,0},
			{0,0,0,0},
			{0,0,0,0},
			{0,0,0,0}
	};
	
	public static void main(String[] args) {
		byte[] data = loadData();
		
		if(DEBUG) {
			System.out.println("LOADED INPUT DATA, SIZE (" + data.length + "):");
			debugBytesAsHex(data);
			debugBytesRaw(data);
			System.out.println();
		}
		
		char mode = loadMode();

		int keyMatrix[] = loadKey();
		int roundKeys[][] = keySchedule(keyMatrix);
		
		int[][][] blocks = new int[data.length >>> 4][16][16];
		if(mode == 'e') {
			encrypt(data, roundKeys, blocks);
		}else {
			decrypt(data, roundKeys, blocks);
		}
		
		saveData(blocks);
		print("Enter any value to exit:\n> ");
		in.nextLine();
		in.close();
	}
	
	private static void encrypt(byte[] data, int[][] roundKeys, int[][][] blocks) {
		int[][] lastBlock = null;
		for(int i = 0; i < data.length; i += 16) {
			int block[][] = blockMatrix(data, i);
			int mask[][] = i == 0 ? IV : lastBlock;
			if(DEBUG) {
				System.out.println("\n****** BLOCK " + (i>>>4) + " ******");
				System.out.println("PLAINTEXT BLOCK | MASK BLOCK | INPUT BLOCK");
				int[][] old = copy(block);
				cbc(block, mask);
				debugBlocks(old, mask, block);
			}else{
				cbc(block, mask);
			}
			for(int r = 0; r < 10; r++) {
				addRoundKey(block, roundKeys[r]);
				if(DEBUG) {
					System.out.println("*** ROUND " + r + " ***\nADD ROUND KEY");
					debugKeyMatrix(roundKeys[r]);
					System.out.println("RESULT");
					debugBlocks(block);
				}
				subBytes(block);
				if(DEBUG) {
					System.out.println("SUB BYTES");
					debugBlocks(block);
				}
				shiftRows(block);
				if(DEBUG) {
					System.out.println("SHIFT ROWS");
					debugBlocks(block);
				}
				if(r != 9) { 
					mixColumns(block);
					if(DEBUG) {
						System.out.println("MIX COLUMNS");
						debugBlocks(block);
					}
				}
			}
			addRoundKey(block, roundKeys[10]);
			lastBlock = copy(block);
			blocks[i >>> 4] = lastBlock;
		}
	}
	
	private static void decrypt(byte[] data, int[][] roundKeys, int[][][] blocks) {
		int block[][] = blockMatrix(data, 0);
		int[][] lastBlock = null;
		/*for(int i = 0; i < data.length; i += 16) {
			int block[][] = blockMatrix(data, i);
			int mask[][] = i == 0 ? IV : lastBlock;
			if(DEBUG) {
				System.out.println("\n****** BLOCK " + (i>>>4) + " ******");
				System.out.println("PLAINTEXT BLOCK | MASK BLOCK | INPUT BLOCK");
				int[][] old = copy(block);
				cbc(block, mask);
				debugBlocks(old, mask, block);
			}else{
				cbc(block, mask);
			}*/
			addRoundKey(block, roundKeys[10]);
			if(DEBUG) {
				System.out.println("INITIAL ADD ROUND KEY");
				debugKeyMatrix(roundKeys[10]);
				System.out.println("RESULT");
				debugBlocks(block);
			}
			for(int r = 0; r < 10; r++) {
				shiftRowsInverse(block);
				if(DEBUG) {
					System.out.println("INVERSE SHIFT ROWS");
					debugBlocks(block);
				}
				subBytesInverse(block);
				if(DEBUG) {
					System.out.println("INVERSE SUB BYTES");
					debugBlocks(block);
				}
				addRoundKey(block, roundKeys[9-r]);
				if(DEBUG) {
					System.out.println("*** ROUND " + r + " ***\nADD ROUND KEY");
					debugKeyMatrix(roundKeys[r]);
					System.out.println("RESULT");
					debugBlocks(block);
				}
				if(r != 9) { 
					mixColumnsInverse(block);
					if(DEBUG) {
						System.out.println("MIX COLUMNS");
						debugBlocks(block);
					}
				}
			}
			lastBlock = copy(block);
			/*blocks[i >>> 4] = lastBlock;
		}*/
			blocks[0] = lastBlock;
	}
	
	public static void cbc(int[][] a, int[][] b){
		for(int i = 0; i < 4; i++) {
			for(int j = 0; j < 4; j++) {
				a[i][j] ^= b[i][j];
			}
		}
	}
	
	private static void addRoundKey(int[][] block, int[] roundKey) {
		for(int i = 0; i < 4; i++) {
			for(int j = 0; j < 4; j++) {
				int rkByte = (roundKey[i] >>> ((3-j)*8)) & 0xFF;
				block[j][i] ^= rkByte;
			}
		}
	}
	
	private static void subBytes(int[][] block) {
		for(int i = 0; i < block.length; i++) {
			for(int j = 0; j < block[i].length; j++) {
				block[j][i] = sbox8(block[j][i]);
			}
		}
	}
	
	private static void subBytesInverse(int[][] block) {
		for(int i = 0; i < block.length; i++) {
			for(int j = 0; j < block[i].length; j++) {
				block[j][i] = sbox8inverse(block[j][i]);
			}
		}
	}
	
	private static void shiftRows(int[][] block) {
		int temp = block[1][0];
		block[1][0] = block[1][1];
		block[1][1] = block[1][2];
		block[1][2] = block[1][3];
		block[1][3] = temp;
		
		temp = block[2][0];
		block[2][0] = block[2][2];
		block[2][2] = temp;
		
		temp = block[2][1];
		block[2][1] = block[2][3];
		block[2][3] = temp;
		
		temp = block[3][0];
		block[3][0] = block[3][3];
		block[3][3] = block[3][2];
		block[3][2] = block[3][1];
		block[3][1] = temp;
	}

	private static void mixColumns(int[][] block) {
		for(int i = 0; i < 4; i++) {
			int b0 = block[0][i];
			int b1 = block[1][i];
			int b2 = block[2][i];
			int b3 = block[3][i];
			int d0 = gmul(b0, 2) ^ gmul(b1, 3) ^ b2 ^ b3;
			int d1 = b0 ^ gmul(b1, 2) ^ gmul(b2, 3) ^ b3;
			int d2 = b0 ^ b1 ^ gmul(b2, 2) ^ gmul(b3, 3);
			int d3 = gmul(b0, 3) ^ b1 ^ b2 ^ gmul(b3, 2);
			block[0][i] = d0;
			block[1][i] = d1;
			block[2][i] = d2;
			block[3][i] = d3;
		}
	}
	
	public static int[][] keySchedule(int[] keyMatrix){
		int[][] w = new int[11][4];
		for(int i = 0; i < 11; i++) {
			if(i == 0) {
				w[i][0] = keyMatrix[0];
				w[i][1] = keyMatrix[1];
				w[i][2] = keyMatrix[2];
				w[i][3] = keyMatrix[3];
			}else{
				w[i][0] = w[i-1][0] ^ g(w[i-1][3], i);
				w[i][1] = w[i][0] ^ w[i-1][1];
				w[i][2] = w[i][1] ^ w[i-1][2];
				w[i][3] = w[i][2] ^ w[i-1][3];
			}
			if(DEBUG) {
				System.out.println("KEY SCHEDULER ROUND " + i + ":");
				debugKeyMatrix(w[i]);
				System.out.println();
			}
		}
		return w;
	}

	private static int getS(int hi, int lo) {
		return SBOX[hi * 16 + lo];
	}

	private static int sbox32(int w) {
		int b0 = w >>> 24;
		int b1 = (w >>> 16) & 0xFF;
		int b2 = (w >>> 8) & 0xFF;
		int b3 = w & 0xFF;
		b0 = getS(b0 >>> 4, b0 & 0xF);
		b1 = getS(b1 >>> 4, b1 & 0xF);
		b2 = getS(b2 >>> 4, b2 & 0xF);
		b3 = getS(b3 >>> 4, b3 & 0xF);
		return (b0 << 24) | (b1 << 16) | (b2 << 8) | b3;
	}
	
	private static int sbox8(int w) {
		return getS(w >>> 4, w & 0xF);
	}
	
	private static int sbox8inverse(int w) {
		return getS((w >>> 4) * 16 + w & 0xF);
	}
	
	private static int g(int w, int i) {
		int rotW = (w >>> 24) | (w << 8);
		int subbed = sbox32(rotW);
		int rCon = RC[i-1] << 24;
		if(DEBUG) {
			System.out.printf("ROUND %d G: %x -> %x -> %x -> %x\n", i, w, rotW, subbed, subbed ^ rCon);
		}
		return subbed ^ rCon;
	}
	
	public static int[] keyMatrix(int... keys) {
		int keyMatrix[] = new int[4];
		keyMatrix[0] = keys.length > 0 ? keys[0] : 0;
		keyMatrix[1] = keys.length > 1 ? keys[1] : 0;
		keyMatrix[2] = keys.length > 2 ? keys[2] : 0;
		keyMatrix[3] = keys.length > 3 ? keys[3] : 0;
		return keyMatrix;
	}

	public static int[][] blockMatrix(byte data[], int i){
		int blockMatrix[][] = new int[4][4];
		for(int c = 0; c < 4; c++)
			for(int r = 0; r < 4; r++)
				blockMatrix[r][c] = btoi(data[i++]);
		return blockMatrix;
	}

	public static byte[] loadData() {
		print("Enter path of file to encrypt:\n> ");
		File file;
		while(true) {
			String str = in.nextLine();
			file = new File(str);
			if(!file.exists()) print("Input file not found! Try again:\n> ");
			else break;
		}
		try {
			BufferedInputStream is = new BufferedInputStream(new FileInputStream(file));
			int curSz = 16;
			byte oldData[] = null;
			boolean justExpanded = false;
			byte data[] = new byte[curSz];
			for(int n = 0; n < curSz; n++) data[n] = 0;
			int i = 0;
			int next;
			while((next = is.read()) != -1) {
				byte nextByte = (byte)next;
				data[i] = nextByte;
				if(i == data.length-1) {
					oldData = data;
					int newSz = curSz + 16;
					byte newData[] = new byte[newSz];
					for(int n = 0; n < curSz; n++) newData[n] = data[n];
					data = newData;
					curSz = newSz;
					justExpanded = true;
				}else {
					justExpanded = false;
				}
				i++;
			}
			if(justExpanded) data = oldData;
			is.close();
			println("Data loaded!");
			return data;
		}catch(Exception e) {
			exit(e.getMessage());
			return null;
		}
	}
	
	public static void saveData(int[][][] blocks) {
		println("Saving to \"out.txt\"...");
		File file = new File("out.txt");
		if(file.exists()) file.delete();
		try {
			file.createNewFile();
			BufferedOutputStream os = new BufferedOutputStream(new FileOutputStream(file));
			for(int[][] block : blocks) {
				for(int c = 0; c < 4; c++) {
					for(int r = 0; r < 4; r++) {
						if(DEBUG) System.out.printf("%x ", block[r][c]);
						os.write(block[r][c]);
					}
				}
			}
			os.flush();
			os.close();
			println("File saved successfully!");
		}catch(Exception e) {
			exit(e.getMessage());
		}
	}
	
	public static int[] loadKey() {
		print("Enter key, or press enter to use default:\n> ");
		String str = in.nextLine();
		int[] keyMatrix;
		if(str.length() != 0) {
			Random r = new Random(str.hashCode());
			int hc1 = r.nextInt(Integer.MAX_VALUE);
			int hc2 = String.valueOf(hc1).hashCode();
			int hc3 = String.valueOf(hc2).hashCode();
			int hc4 = String.valueOf(hc3).hashCode();
			keyMatrix = keyMatrix(hc1, hc2, hc3, hc4);
		}else{
			keyMatrix = keyMatrix(0xdeafbabe, 0xbadcafe, 0xdeadbeef, 0xfeedabe);
		}
		String hexKey = "";
		for(int i = 0; i < 4; i++) {
			for(int j = 0; j < 4; j++) {
				String hex = Integer.toHexString(0xFF & (keyMatrix[i] >>> (8*(3-j))));
				if(hex.length() == 1) hex = "0" + hex;
				hexKey += hex;
			}
		}
		println("Key stored as " + hexKey + "!");
		String ivString = "";
		for(int i = 0; i < 4; i++) {
			for(int j = 0; j < 4; j++) {
				String hex = Integer.toHexString(IV[j][i]);
				if(hex.length() == 1) hex = "0" + hex;
				ivString += hex;
			}
		}
		println("Using CBC mode with IV " + ivString + "!");
		return keyMatrix;
	}

	public static char loadMode() {
		while(true) {
			print("Enter \'e\' to encrypt or \'d\' to decrypt:\n> ");
			String line = in.nextLine();
			if(line.length() == 1) {
				if(line.equalsIgnoreCase("d")) {
					return 'd';
				}else
				if(line.equalsIgnoreCase("e")) {
					return 'e';
				}
			}
			println("Unrecognized value!");
		}
	}

	public static int gmul(int a, int b) {
		int c;
		if(b == 2) {
			c = (a << 1) & 0xFF;
			if((a & 0x80) > 0) c ^= 0x1b;
		}else
		if(b == 3) {
			c = gmul(a, 2);
			c ^= a;
		}else c = Integer.MIN_VALUE;
		return c;
	}
	
	public static int[][] copy(int[][] a){
		int[][] b = new int[4][4];
		for(int i = 0; i < 4; i++) {
			for(int j = 0; j < 4; j++) {
				b[i][j] = a[i][j];
			}
		}
		return b;
	}
	
	public static int btoi(byte b) {
		if(b >= 0) return b;
		return ((int)(b & 0x7F)) | 0x80;
	}
	
	public static void println(String str) {
		System.out.println(PRE + str);
	}
	
	public static void print(String str) {
		System.out.print(PRE + str);
	}
	
	public static void exit(String str) {
		println(str);
		System.exit(0);
	}
	
	private static void debugBytesRaw(byte[] data) {
		for(byte b : data) {
			System.out.printf("%c ", (char)b);
		}
		System.out.println();
	}
	
	private static void debugBytesAsHex(byte[] data) {
		for(byte b : data) {
			System.out.printf("%x ", b);
		}
		System.out.println();
	}
	
	private static void debugKeyMatrix(int[] keyMatrix) {
		int[][] temp = new int[4][4];
		int c = 0;
		for(int i : keyMatrix) {
			temp[0][c] = (i >> 24) & 0xff;
			temp[1][c] = (i >> 16) & 0xff;
			temp[2][c] = (i >> 8) & 0xff;
			temp[3][c++] = i & 0xff;
		}
		for(int i = 0; i < 4; i++) {
			for(int j = 0; j < 4; j++) {
				System.out.printf("%x ", temp[i][j]);
			}
			System.out.println();
		}
	}
	
	private static void debugBlocks(int[][]...blocks) {
		int[][] line = new int[blocks.length][4];
		for(int r = 0; r < 4; r++) {
			for(int c = 0; c < 4; c++) {
				for(int b = 0; b < blocks.length; b++) {
					int[][] block = blocks[b];
					line[b][c] = block[r][c];
				}
			}
			for(int[] haha : line) {
				for(int i : haha) {
					System.out.printf("%x ", i);
				}
				System.out.printf("\t");
			}
			line = new int[blocks.length][4];
			System.out.println();
		}
		System.out.println();
	}
	
}
