package Utils;

/**
 * �� Ŭ������ Byte ���� �Լ��� �����մϴ�. 
 * 
 * @author <a href="mailto:kangwoo@jarusoft.com">kangwoo</a>
 * @version 1.0
 * @since 1.0
 */
public class ByteUtils {
	
	/**
	 * <p>�Ϲ� ���ڿ��� ASCII 16���� ������ ��ȯ�Ѵ�.</p>
	 * 
	 * <pre>
	 * ByteUtils.toByte("v")	= 76
	 * ByteUtils.toByte("#")	= 23
	 * ByteUtils.toByte("]")	= 5D
	 * </pre>
	 * 
	 * @param s Ư�����ڸ� ������ ASCII ���ڿ�
	 * @return 16���� ������ ��ȯ�� ���ڿ�
	 */
	public static String stringToHex(String s) {
		String str = "";
		for (int i = 0; i < s.length(); i++) {
	    	str += String.format("%02X", (int) s.charAt(i));
	    }
	    return str;
	}
	
	public static Byte DEFAULT_BYTE = new Byte((byte) 0);
	
	/**
	 * <p>���ڿ��� ����Ʈ�� ��ȯ�Ѵ�.</p>
	 * 
	 * <pre>
	 * ByteUtils.toByte("1", *)    = 0x01
	 * ByteUtils.toByte("-1", *)   = 0xff
	 * ByteUtils.toByte("a", 0x00) = 0x00
	 * </pre>
	 * 
	 * @param value 10���� ���ڿ� ��
	 * @param defaultValue
	 * @return
	 */
	public static byte toByte(String value, byte defaultValue) {
		try {
			return Byte.parseByte(value);	
		} catch(Exception e) {
			return defaultValue;
		}
	}

	/**
	 * <p>���ڿ��� ����Ʈ�� ��ȯ�Ѵ�.</p>
	 * 
	 * <pre>
	 * ByteUtils.toByteObject("1", *)    = 0x01
	 * ByteUtils.toByteObject("-1", *)   = 0xff
	 * ByteUtils.toByteObject("a", 0x00) = 0x00
	 * </pre>
	 * 
	 * @param value 10���� ���ڿ� ��
	 * @param defaultValue
	 * @return
	 */
	public static Byte toByteObject(String value, Byte defaultValue) {
		try {
			return new Byte(value);
		} catch (Exception e) {
			return defaultValue;
		}
	}

    
    /**
     * <p>singed byte�� unsinged byte�� ��ȯ�Ѵ�.</p>
     * <p>Java���� unsinged Ÿ���� ���⶧����, int�� ��ȯ�Ѵ�.(b & 0xff)</p>
     * 
     * @param b singed byte
     * @return unsinged byte 
     */
	public static int unsignedByte(byte b) {
		return  b & 0xFF;
	}

	/**
	 * <p>�Է��� ����Ʈ �迭(4����Ʈ)�� int ������ ��ȯ�Ѵ�.</p>
	 * 
	 * @param src
	 * @param srcPos
	 * @return
	 */
	public static int toInt(byte[] src, int srcPos) {
		int dword = 0;
		for (int i = 0; i < 4; i++) {
			dword = (dword << 8) + (src[i + srcPos] & 0xFF);
		}
		return dword;
	}
	
	/**
	 * <p>�Է��� ����Ʈ �迭(4����Ʈ)�� int ������ ��ȯ�Ѵ�.</p>
	 * 
	 * @param src
	 * @return
	 */
	public static int toInt(byte[] src) {
		return toInt(src, 0);
	}
	
	/**
	 * <p>�Է��� ����Ʈ �迭(8����Ʈ)�� long ������ ��ȯ�Ѵ�.</p>
	 * 
	 * @param src
	 * @param srcPos
	 * @return
	 */
	public static long toLong(byte[] src, int srcPos) {
		long qword = 0;
		for (int i = 0; i < 8; i++) {
			qword = (qword << 8) + (src[i + srcPos] & 0xFF);
		}
		return qword;
	}
	
	/**
	 * <p>�Է��� ����Ʈ �迭(8����Ʈ)�� long ������ ��ȯ�Ѵ�.</p>
	 * 
	 * @param src
	 * @return
	 */
	public static long toLong(byte[] src) {
		return toLong(src, 0);
	}

	/**
	 * <p>int ���� ���� ����Ʈ �迭(4����Ʈ)�� ��ȯ�Ѵ�.</p>
	 * 
	 * @param value
	 * @param dest
	 * @param destPos
	 */
	public static void toBytes(int value, byte[] dest, int destPos) {
		for (int i = 0; i < 4; i++) {
			dest[i + destPos] = (byte)(value >> ((7 - i) * 8));
		}
	}
	
	/**
	 * <p>int ���� ���� ����Ʈ �迭(4����Ʈ)�� ��ȯ�Ѵ�.</p>
	 * 
	 * @param value
	 * @return
	 */
	public static byte[] toBytes(int value) {
		byte[] dest = new byte[4];
		toBytes(value, dest, 0);
		return dest;
	}
	
	/**
	 * <p>long ���� ���� ����Ʈ �迭(8����Ʈ)�� ��ȯ�Ѵ�.</p>
	 * 
	 * @param value
	 * @param dest
	 * @param destPos
	 */
	public static void toBytes(long value, byte[] dest, int destPos) {
		for (int i = 0; i < 8; i++) {
			dest[i + destPos] = (byte)(value >> ((7 - i) * 8));
		}
	}
	
	/**
	 * <p>long ���� ���� ����Ʈ �迭(8����Ʈ)�� ��ȯ�Ѵ�.</p>
	 * 
	 * @param value
	 * @return
	 */
	public static byte[] toBytes(long value) {
		byte[] dest = new byte[8];
		toBytes(value, dest, 0);
		return dest;
	}
	
	/**
	 * <p>8, 10, 16���� ���ڿ��� ����Ʈ �迭�� ��ȯ�Ѵ�.</p>
	 * <p>8, 10������ ���� ���ڿ��� 3�ڸ���, 16������ ���� 2�ڸ���, �ϳ��� byte�� �ٲ��.</p>
	 * 
	 * <pre>
	 * ByteUtils.toBytes(null)     = null
	 * ByteUtils.toBytes("0E1F4E", 16) = [0x0e, 0x1f, 0x4e]
	 * ByteUtils.toBytes("48414e", 16) = [0x48, 0x41, 0x4e]
	 * </pre>
	 * 
	 * @param digits ���ڿ�
	 * @param radix ����(8, 10, 16�� ����)
	 * @return
	 * @throws NumberFormatException
	 */
	public static byte[] toBytes(String digits, int radix) throws IllegalArgumentException, NumberFormatException {
		if (digits == null) {
			return null;
		}
		if (radix != 16 && radix != 10 && radix != 8) {
			throw new IllegalArgumentException("For input radix: \"" + radix + "\"");
		}
		int divLen = (radix == 16) ? 2 : 3;
    	int length = digits.length();
    	if (length % divLen == 1) {
    		throw new IllegalArgumentException("For input string: \"" + digits + "\"");
    	}
    	length = length / divLen;
    	byte[] bytes = new byte[length];
    	for (int i = 0; i < length; i++) {
    		int index = i * divLen;
    		bytes[i] = (byte)(Short.parseShort(digits.substring(index, index+divLen), radix));
    	}
    	return bytes;
	}
	
	/**
	 * <p>16���� ���ڿ��� ����Ʈ �迭�� ��ȯ�Ѵ�.</p>
	 * <p>���ڿ��� 2�ڸ��� �ϳ��� byte�� �ٲ��.</p>
	 * 
	 * <pre>
	 * ByteUtils.toBytesFromHexString(null)     = null
	 * ByteUtils.toBytesFromHexString("0E1F4E") = [0x0e, 0xf4, 0x4e]
	 * ByteUtils.toBytesFromHexString("48414e") = [0x48, 0x41, 0x4e]
	 * </pre>
	 * 
	 * @param digits 16���� ���ڿ�
	 * @return
	 * @throws NumberFormatException
	 * @see HexUtils.toBytes(String)
	 */
	public static byte[] toBytesFromHexString(String digits) throws IllegalArgumentException, NumberFormatException {
		if (digits == null) {
			return null;
		}
    	int length = digits.length();
    	if (length % 2 == 1) {
    		throw new IllegalArgumentException("For input string: \"" + digits + "\"");
    	}
    	length = length / 2;
    	byte[] bytes = new byte[length];
    	for (int i = 0; i < length; i++) {
    		int index = i * 2;
    		bytes[i] = (byte)(Short.parseShort(digits.substring(index, index+2), 16));
    	}
    	return bytes;
	}
	
	/**
	 * <p>unsigned byte(����Ʈ)�� 16���� ���ڿ��� �ٲ۴�.</p>
	 * 
	 * ByteUtils.toHexString((byte)1)   = "01"
	 * ByteUtils.toHexString((byte)255) = "ff"
	 * 
	 * @param b unsigned byte
	 * @return
	 * @see HexUtils.toString(byte)
	 */
	public static String toHexString(byte b) {
		StringBuffer result = new StringBuffer(3);
		result.append(Integer.toString((b & 0xF0) >> 4, 16));
		result.append(Integer.toString(b & 0x0F, 16));
		return result.toString();
	}
	
	/**
	 * <p>unsigned byte(����Ʈ) �迭�� 16���� ���ڿ��� �ٲ۴�.</p>
	 * 
	 * <pre>
	 * ByteUtils.toHexString(null)                   = null
	 * ByteUtils.toHexString([(byte)1, (byte)255])   = "01ff"
	 * </pre>
	 * 
	 * @param bytes unsigned byte's array
	 * @return
	 * @see HexUtils.toString(byte[])
	 */
	public static String toHexString(byte[] bytes) {
		if (bytes == null) {
			return null;
		}
		
		StringBuffer result = new StringBuffer();
		for (byte b : bytes) {
			result.append(Integer.toString((b & 0xF0) >> 4, 16));
			result.append(Integer.toString(b & 0x0F, 16));
		}
		return result.toString();
	}
	
	/**
	 * <p>unsigned byte(����Ʈ) �迭�� 16���� ���ڿ��� �ٲ۴�.</p>
	 * 
	 * <pre>
	 * ByteUtils.toHexString(null, *, *)                   = null
	 * ByteUtils.toHexString([(byte)1, (byte)255], 0, 2)   = "01ff"
	 * ByteUtils.toHexString([(byte)1, (byte)255], 0, 1)   = "01"
	 * ByteUtils.toHexString([(byte)1, (byte)255], 1, 2)   = "ff"
	 * </pre>
	 * 
	 * @param bytes unsigned byte's array
	 * @return
	 * @see HexUtils.toString(byte[])
	 */
	public static String toHexString(byte[] bytes, int offset, int length) {
		if (bytes == null) {
			return null;
		}
		
		StringBuffer result = new StringBuffer();
		for (int i = offset; i < offset + length; i++) {
			result.append(Integer.toString((bytes[i] & 0xF0) >> 4, 16));
			result.append(Integer.toString(bytes[i] & 0x0F, 16));
		}
		return result.toString();
	}
    
	/**
	 * <p>�� �迭�� ���� �������� ���Ѵ�.</p>
	 * 
	 * <pre>
	 * ArrayUtils.equals(null, null)                        = true
	 * ArrayUtils.equals(["one", "two"], ["one", "two"])    = true
	 * ArrayUtils.equals(["one", "two"], ["three", "four"]) = false
	 * </pre>
	 * 
	 * @param array1
	 * @param array2
	 * @return �����ϸ� <code>true</code>, �ƴϸ� <code>false</code>
	 */
	public static boolean equals(byte[] array1, byte[] array2) {
		if (array1 == array2) {
			return true;
		}
		
		if (array1 == null || array2 == null) {
			return false;
		}
		
		if (array1.length != array2.length) {
			return false;
		}
		
		for (int i = 0; i < array1.length; i++) {
			if (array1[i] != array2[i]) {
				return false;
			}
		}
		
		return true;
	}
	
	public static void printByte(String m, byte[] msg) {
        System.out.println("============[ " + m + " ]==============");
        for(int i = 0; i < msg.length; i++) {
             if(i != 0 && i % 20 == 0) {
                  System.out.println("");
             }
             byte c = msg[i];
             System.out.format("[%02X]", c);
        }
        System.out.println("");
   }
}