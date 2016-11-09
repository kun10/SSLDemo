package com.ssl.SSLSocket;

import java.io.FileInputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.security.KeyStore;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.TrustManagerFactory;

/**
 * java原生包使用SSLServerSocket实现SSL通信服务器端
 *
 */
public class SSLServer {
	private SSLServerSocket sslServerSocket;
	public static void main(String[] args) throws Exception {
		SSLServer server = new SSLServer();
		server.init();
		System.out.println("SSLServer initialized.");
		server.process();
	}
	
	//初始化
	public void init() throws Exception {
		int port = 1234;
		String keystorePath = "E:\\cer\\server.keystore";
		String trustKeystorePath = "E:\\cer\\server.truststore";
		String keystorePassword = "121314";
		String truststorePassword = "121314";
		
		//这个类是原生包中的SSL连接的上下文类
		SSLContext context = SSLContext.getInstance("SSL");
		
		//服务器端证书库
		KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
		FileInputStream keystoreFis = new FileInputStream(keystorePath);
		keystore.load(keystoreFis, keystorePassword.toCharArray());
		//信任证书库
		KeyStore trustKeystore = KeyStore.getInstance("jks");
		FileInputStream trustKeystoreFis = new FileInputStream(trustKeystorePath);
		trustKeystore.load(trustKeystoreFis, truststorePassword.toCharArray());
		
		//密钥库
		KeyManagerFactory kmf = KeyManagerFactory.getInstance("sunx509");
		kmf.init(keystore, keystorePassword.toCharArray());

		//信任库
		TrustManagerFactory tmf = TrustManagerFactory.getInstance("sunx509");
		tmf.init(trustKeystore);
		
		//初始化SSL上下文
		context.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
		//初始化SSLSocket
		sslServerSocket = (SSLServerSocket)context.getServerSocketFactory().createServerSocket(port);
		//设置这个SSLServerSocket需要授权的客户端访问
		sslServerSocket.setNeedClientAuth(true);
	}
	
	public void process() throws Exception {
		String bye = "Bye!";
		byte[] buffer = new byte[50];
		while(true) {
			Socket socket = sslServerSocket.accept();
			InputStream in = socket.getInputStream();
			in.read(buffer);
			System.out.println("Received: " + new String(buffer));
			OutputStream out = socket.getOutputStream();
			out.write(bye.getBytes());
			out.flush();
			break;
		}
	}
}
