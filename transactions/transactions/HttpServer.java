package transactions;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;

public class HttpServer {
	private static String hexString = "0123456789ABCDEF";
	private static String mmk = "3D1C205404B070E3";

	public static void main(String[] args) {
		try {
			ServerSocket ss = new ServerSocket(8888);

			Socket socket = ss.accept();
			InputStream in = socket.getInputStream();
			String receive;// 获得输入流
			if (in != null) {
				ByteArrayOutputStream outStream = new ByteArrayOutputStream();
				byte[] buffer = new byte[1024];
				int len = 0;
				if ((len = in.read(buffer)) != -1) {
					outStream.write(buffer, 0, len);
					receive = bytesToHexString(outStream.toByteArray());
					System.out.println(receive);
					Map<String, String> requestMessage = new HashMap<String, String>();
					int position = 290;
					requestMessage.put("messageLength", decode(receive.substring(position, position + 8)));
					position = position + 8;
					requestMessage.put("headerField1", receive.substring(position, position + 2));
					position = position + 2;
					requestMessage.put("headerField2", receive.substring(position, position + 2));
					position = position + 2;
					requestMessage.put("headerField3", decode(receive.substring(position, position + 8)));
					position = position + 8;
					requestMessage.put("headerField4", decode(receive.substring(position, position + 22)).trim());
					position = position + 22;
					requestMessage.put("headerField5", decode(receive.substring(position, position + 22)).trim());
					position = position + 22;
					requestMessage.put("headerField6", receive.substring(position, position + 6));
					position = position + 6;
					requestMessage.put("headerField7", receive.substring(position, position + 2));
					position = position + 2;
					requestMessage.put("headerField8", decode(receive.substring(position, position + 16)));
					position = position + 16;
					requestMessage.put("headerField9", receive.substring(position, position + 2));
					position = position + 2;
					requestMessage.put("headerField10", decode(receive.substring(position, position + 10)));
					position = position + 10;
					requestMessage.put("MTI", decode(receive.substring(position, position + 8)));
					position = position + 8;
					requestMessage.put("bitmap", receive.substring(position, position + 32));
					position = position + 32;
					requestMessage.put("7", decode(receive.substring(position, position + 20)));
					position = position + 20;
					requestMessage.put("11", decode(receive.substring(position, position + 12)));
					position = position + 12;
					requestMessage.put("48L", decode(receive.substring(position, position + 6)));
					position = position + 6;
					requestMessage.put("48D", decode(
							receive.substring(position, position + Integer.parseInt(requestMessage.get("48L")) * 2)));
					position = position + Integer.parseInt(requestMessage.get("48L")) * 2;
					requestMessage.put("53", decode(receive.substring(position, position + 32)));
					position = position + 32;
					requestMessage.put("70", decode(receive.substring(position, position + 6)));
					position = position + 6;
					requestMessage.put("96", receive.substring(position, position + 16));
					position = position + 16;
					requestMessage.put("100L", decode(receive.substring(position, position + 4)));
					position = position + 4;
					requestMessage.put("100D", decode(
							receive.substring(position, position + Integer.parseInt(requestMessage.get("100L")) * 2)));
					position = position + Integer.parseInt(requestMessage.get("100L")) * 2;
					
					for(String key:requestMessage.keySet()){
						System.out.println(key+" : "+requestMessage.get(key));
					}
					
					requestMessage.put("128", receive.substring(position, position + 16));

					// 128 check
					List<String> mabFields = new ArrayList<String>();
					mabFields.add(requestMessage.get("MTI"));
					mabFields.add(requestMessage.get("7"));
					mabFields.add(requestMessage.get("11"));
					mabFields.add(requestMessage.get("53"));
					mabFields.add(requestMessage.get("70"));
					if (Integer.parseInt(requestMessage.get("100L")) < 10) {
						mabFields.add("8" + requestMessage.get("100L") + requestMessage.get("100D"));
					} else {
						mabFields.add(requestMessage.get("100L") + requestMessage.get("100D"));
					}
					String mab = makeMab(mabFields);
					try {
						String mak = bytesToString(
								decrypt(hexStringToByte(requestMessage.get("96")), hexStringToByte(mmk)));
						System.out.println("工作密钥解密结果:" + mak);
						String machalf1 = makeMac(mab, mak).substring(0,4);
						String checkvalue = bytesToString(
								decrypt(hexStringToByte("0000000000000000"),hexStringToByte(requestMessage.get("96"))));
						String machalf2=checkvalue.substring(0, 4);
						String mac=encode(machalf1+machalf2);
						

						if(mac.equals(requestMessage.get("128"))){
							System.out.println("Pass:128域校验成功");
						}else{
							System.out.println("Fail:128域校验失败,计算结果结果: " + mac+"  ,实际收到: "+requestMessage.get("128"));
						}
						
						
					} catch (Exception e1) {
						e1.printStackTrace();
					}

					
				}

				// 发送回执
				PrintWriter pw = new PrintWriter(socket.getOutputStream());

				pw.println("HTTP/1.1 200 OK");
				pw.println("Content-type:text/html");
				pw.println();
				pw.println("<h1>访问成功！</h1>");
				pw.flush();
			}
			socket.close();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	public static final String bytesToHexString(byte[] bArray) {
		StringBuffer sb = new StringBuffer(bArray.length);
		String sTemp;
		for (int i = 0; i < bArray.length; i++) {
			sTemp = Integer.toHexString(0xFF & bArray[i]);
			if (sTemp.length() < 2)
				sb.append(0);
			sb.append(sTemp.toUpperCase());
		}
		return sb.toString();
	}

	//ASCII to BCD
	  public static String encode(String str)
	  {
	  //
	  byte[] bytes=str.getBytes();
	  StringBuilder sb=new StringBuilder(bytes.length*2);

	  for(int i=0;i<bytes.length;i++)
	  {
	  sb.append(hexString.charAt((bytes[i]&0xf0)>>4));
	  sb.append(hexString.charAt((bytes[i]&0x0f)>>0));
	  }
	  return sb.toString();
	  }  
  
	
	// BCD to ASCII
	public static String decode(String bytes) {
		ByteArrayOutputStream baos = new ByteArrayOutputStream(bytes.length() / 2);

		for (int i = 0; i < bytes.length(); i += 2)
			baos.write((hexString.indexOf(bytes.charAt(i)) << 4 | hexString.indexOf(bytes.charAt(i + 1))));
		return new String(baos.toByteArray());
	}

	public static byte[] hexStringToByte(String hex) {
		int len = (hex.length() / 2);
		byte[] result = new byte[len];
		char[] achar = hex.toCharArray();
		for (int i = 0; i < len; i++) {
			int pos = i * 2;
			result[i] = (byte) (toByte(achar[pos]) << 4 | toByte(achar[pos + 1]));
		}
		return result;
	}

	private static byte toByte(char c) {
		byte b = (byte) "0123456789ABCDEF".indexOf(c);
		return b;
	}

	public static void phex(String prefix, byte[] bytes) {
		// System.out.print(prefix);
		for (int i1 = 0; i1 < bytes.length; i1++) {
			// System.out.printf("%02X ", bytes[i1]);
		}
		// System.out.println();
	}

	public static String bytesToString(byte[] bytes) {
		String s = "";
		for (int i = 0; i < bytes.length; i++) {
			s += String.format("%02X", bytes[i]);
		}
		return s;
	}

	public static String makeMac(String mab, String macKey) {
		byte[] key = hexStringToByte(macKey);
		byte[] bv = new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
		for (int i = 0; i < mab.length(); i += 8) {
			String s = "";
			if (i + 8 > mab.length()) {
				s = mab.substring(i);
				for (int j = 0; j < i + 8 - mab.length(); j++) {
					s += '\0';
				}
			} else {
				s = mab.substring(i, i + 8);
			}

			byte[] sb = s.getBytes();
			phex("orig ", sb);

			for (int j = 0; j < 8; j++) {
				bv[j] ^= sb[j];
			}
			phex("xor  ", bv);
			bv = desCrypto(bv, key);
			phex("enc  ", bv);
		}

		String mac = bytesToString(bv).substring(0, 8);
		return mac;
	}

	public static String makeMab(List<String> mabFields) {
		String mab = "";
		for (String f : mabFields) {
			mab += f.trim().toUpperCase().replaceAll("[^A-Z0-9,. ]", "") + " ";
		}
		mab = mab.trim();
		return mab;
	}

	public static byte[] desCrypto(byte[] datasource, byte[] password) {
		try {
			SecureRandom random = new SecureRandom();
			DESKeySpec desKey = new DESKeySpec(password);

			SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DES");
			SecretKey securekey = keyFactory.generateSecret(desKey);

			Cipher cipher = Cipher.getInstance("DES");

			cipher.init(Cipher.ENCRYPT_MODE, securekey, random);

			return cipher.update(datasource);
		} catch (Throwable e) {
			e.printStackTrace();
		}
		return null;
	}

	private static byte[] decrypt(byte[] src, byte[] password) throws Exception {

		SecureRandom random = new SecureRandom();

		DESKeySpec desKey = new DESKeySpec(password);

		SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DES");

		SecretKey securekey = keyFactory.generateSecret(desKey);

		Cipher cipher = Cipher.getInstance("DES/ECB/NoPadding");

		cipher.init(Cipher.DECRYPT_MODE, securekey, random);

		return cipher.doFinal(src);
	}

}
