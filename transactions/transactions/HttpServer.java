package transactions;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.HashMap;
import java.util.Map;

public class HttpServer {
	private static String hexString = "0123456789ABCDEF";

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
					Map<String,String> requestMessage = new HashMap<String,String>();
					requestMessage.put("messageLength", decode(receive.substring(290,298)));
					requestMessage.put("headerField1",receive.substring(298,300));
					requestMessage.put("headerField2",receive.substring(300,302));
					requestMessage.put("headerField3",decode(receive.substring(302,310)));
					requestMessage.put("headerField4",decode(receive.substring(310,332)).trim());
					
					String request = decode(receive.substring(290));
					System.out.println(request);
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

	// BCD to ASCII
	public static String decode(String bytes) {
		ByteArrayOutputStream baos = new ByteArrayOutputStream(bytes.length() / 2);

		for (int i = 0; i < bytes.length(); i += 2)
			baos.write((hexString.indexOf(bytes.charAt(i)) << 4 | hexString.indexOf(bytes.charAt(i + 1))));
		return new String(baos.toByteArray());
	}

}
