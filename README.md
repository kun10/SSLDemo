# SSLDemo
Tomcat搭建SSL双向认证Demo、Java原生类库SSLSocket编程、Apache的Httpclient库模拟请求

# 证书准备

见之前[keytool命令](http://note.youdao.com/noteshare?id=3c769cd3ed0547004a87e31acb67d00c)中的**keytool生成双向认证证书**章节

测试证书库：/TestSSL/WebContent/keystore

# Tomcat配置

在${catalina.base}/conf/server.xml找到

```
 <!--
    <Connector port="8443" protocol="org.apache.coyote.http11.Http11Protocol"
               maxThreads="150" SSLEnabled="true" scheme="https" secure="true"
               clientAuth="false" sslProtocol="TLS" />
-->
```

   
    
取消注释，并修改成如下：

```
<Connector SSLEnabled="true" clientAuth="true" keystoreFile="e:\cer\server.keystore" keystorePass="121314" maxThreads="150" port="8443" protocol="HTTP/1.1" scheme="https" secure="true" sslProtocol="SSL" truststoreFile="e:\cer\server.truststore" truststorePass="121314"/>
```


# 服务端项目

1. 项目结构

![项目结构](http://a.hiphotos.baidu.com/image/pic/item/21a4462309f79052604c4ff104f3d7ca7acbd5aa.jpg)

2. 关键代码

/TestSSL/WebContent/WEB-INF/web.xml

该演示项目强制使用了SSL，即普通的HTTP请求也会强制重定向为HTTPS请求，配置在最下面，可以去除，这样HTTP和HTTPS都可以访问。

```
<?xml version="1.0" encoding="UTF-8"?>
<web-app version="2.5" xmlns="http://java.sun.com/xml/ns/javaee" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="http://java.sun.com/xml/ns/javaee
 http://java.sun.com/xml/ns/javaee/web-app_2_5.xsd">
    <session-config>
        <session-timeout>30</session-timeout>
    </session-config>
    <servlet>
        <servlet-name>SSLServlet</servlet-name>
        <servlet-class>com.ssl.servlet.SSLServlet</servlet-class>
    </servlet>
    <servlet-mapping>
        <servlet-name>SSLServlet</servlet-name>
        <url-pattern>/sslServlet</url-pattern>
    </servlet-mapping>
    <!-- 强制SSL配置，即普通的请求也会重定向为SSL请求 -->
     <security-constraint>
        <web-resource-collection>
            <web-resource-name>TestSSL</web-resource-name>
            <url-pattern>/*</url-pattern> <!-- 全站使用SSL -->
        </web-resource-collection> 
        <user-data-constraint>
            <description>SSL required</description>
            <!-- CONFIDENTIAL: 要保证服务器和客户端之间传输的数据不能够被修改，且不能被第三方查看到
            INTEGRAL: 要保证服务器和client之间传输的数据不能够被修改
            NONE: 指示容器必须能够在任一的连接上提供数据。（即用HTTP或HTTPS，由客户端来决定） -->
            <transport-guarantee>CONFIDENTIAL</transport-guarantee>
        </user-data-constraint>
    </security-constraint> 
</web-app>
```


---

/TestSSL/src/com/ssl/servlet/SSLServlet.java

```
package com.ssl.servlet;

import java.io.IOException;
import java.io.PrintWriter;
import java.security.cert.X509Certificate;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class SSLServlet extends HttpServlet {
	private static final long serialVersionUID = 1L;
	
	private static final String ATTR_CER = "javax.servlet.request.X509Certificate";
    private static final String CONTENT_TYPE = "text/plain;charset=UTF-8";
    private static final String DEFAULT_ENCODING = "UTF-8";
    private static final String SCHEME_HTTPS = "https";

    public void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
    	response.setContentType(CONTENT_TYPE);
        response.setCharacterEncoding(DEFAULT_ENCODING);
        PrintWriter out = response.getWriter();
        out.println("cmd=["+request.getParameter("cmd")+"], data=["+request.getParameter("data")+"]");
        X509Certificate[] certs = (X509Certificate[]) request.getAttribute(ATTR_CER);
        if (certs != null) {
            int count = certs.length;
            out.println("共检测到[" + count + "]个客户端证书");
            for (int i = 0; i < count; i++) {
                out.println("客户端证书 [" + (++i) + "]： ");
                out.println("校验结果：" + verifyCertificate(certs[--i]));
                out.println("证书详细：\r" + certs[i].toString());
            }
        } else {
            if (SCHEME_HTTPS.equalsIgnoreCase(request.getScheme())) {
                out.println("这是一个HTTPS请求，但是没有可用的客户端证书");
            } else {
                out.println("这不是一个HTTPS请求，因此无法获得客户端证书列表 ");
            }
        }
        out.close();
    }

    public void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        doGet(request, response);
    }


    private boolean verifyCertificate(X509Certificate certificate) {
        boolean valid = false;
        try {
            certificate.checkValidity();
            valid=true;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return valid;
    }
}
```

---

/TestSSL/WebContent/index.jsp


```
<%@ page language="java" pageEncoding="UTF-8"%>
<!doctype html>
<html lang="zh-cn">
<head>
  <title>客户端证书上传</title>
  <meta http-equiv="pragma" content="no-cache">
  <meta http-equiv="cache-control" content="no-cache">
  <meta http-equiv="expires" content="0">
</head>
<body>
<form action="sslServlet" method="post">
  <input type="submit" value="提交证书"/>
</form>
</body>
</html>
```


---

# 浏览器演示

发布演示项目，通过浏览器访问： https://127.0.0.1:8443/TestSSL ，提示无法访问，需要导入客户端SSL证书：
双击“client.p12”或在浏览器的工具，输入生成密钥时的客户端密码“134679”,证书存储在“受信任的根证书颁发机构”，刷新浏览器即可正常访问了。

![image](http://g.hiphotos.baidu.com/image/pic/item/6609c93d70cf3bc7e900ba23d900baa1cc112af8.jpg)

![image](http://b.hiphotos.baidu.com/image/pic/item/94cad1c8a786c9170e0325f6c13d70cf3ac757f8.jpg)

![image](http://e.hiphotos.baidu.com/image/pic/item/c8177f3e6709c93d04e87938973df8dcd00054e2.jpg)

# java原生类库SSLSocket编程

/TestSSL/src/com/ssl/SSLSocket/SSLServer.java

```
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

```


---


/TestSSL/src/com/ssl/SSLSocket/SSLClient.java


```
package com.ssl.SSLSocket;

import java.io.FileInputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.KeyStore;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManagerFactory;

import org.apache.http.HttpEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;


/**
 * java原生包使用SSLSocket实现SSL通信客户端端
 *
 */
public class SSLClient {
	private SSLSocket sslSocket;
	
	public static void main(String[] args) throws Exception {
		SSLClient client = new SSLClient();
		client.init();
		System.out.println("SSLClient initialized.");
		client.process();
	}
	
	
	public void init() throws Exception {
		String host = "127.0.0.1";
		int port = 1234;
		String keystorePath = "e:\\cer\\client.p12";
		String trustKeystorePath = "e:\\cer\\client.truststore";
		String keystorePassword = "134679";
		String keystoreTrustPassword = "121314";
		
		//这个类是原生包中的SSL连接的上下文类
		SSLContext context = SSLContext.getInstance("SSL");
		
		//客户端证书库
		KeyStore clientKeystore = KeyStore.getInstance("PKCS12");
		FileInputStream keystoreFis = new FileInputStream(keystorePath);
		clientKeystore.load(keystoreFis, keystorePassword.toCharArray());
		//信任证书库
		KeyStore trustKeystore = KeyStore.getInstance("jks");
		FileInputStream trustKeystoreFis = new FileInputStream(trustKeystorePath);
		trustKeystore.load(trustKeystoreFis, keystoreTrustPassword.toCharArray());
		
		//密钥库
		KeyManagerFactory kmf = KeyManagerFactory.getInstance("sunx509");
		kmf.init(clientKeystore, keystorePassword.toCharArray());

		//信任库
		TrustManagerFactory tmf = TrustManagerFactory.getInstance("sunx509");
		tmf.init(trustKeystore);
		
		//初始化SSL上下文
		context.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
		
		//原生包SSLSocket方式
		sslSocket = (SSLSocket)context.getSocketFactory().createSocket(host, port);
		
		/*用apache包来提供get请求*/
		/*SSLConnectionSocketFactory sslsf = new SSLConnectionSocketFactory(context, new String[] { "TLSv1" }, null,
				SSLConnectionSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER);
		CloseableHttpClient httpclient = HttpClients.custom().setSSLSocketFactory(sslsf).build();
		// 创建http请求(get方式)
		HttpGet httpget = new HttpGet("https://localhost:8443/TestSSL/sslServlet");
		
		System.out.println("executing request" + httpget.getRequestLine());
		CloseableHttpResponse response = httpclient.execute(httpget);
		try {
			HttpEntity entity = response.getEntity();
			System.out.println("----------------------------------------");
			System.out.println(response.getStatusLine());
			if (entity != null) {
				System.out.println("Response content length: " + entity.getContentLength());
				System.out.println(EntityUtils.toString(entity));
				EntityUtils.consume(entity);
			}
		} finally {
			response.close();
		}*/
	}
	
	public void process() throws Exception {
		//往SSLSocket中写入数据
		String hello = "hello boy!";
		OutputStream out = sslSocket.getOutputStream();
		out.write(hello.getBytes(), 0, hello.getBytes().length);
		out.flush();
		
		//从SSLSocket中读取数据
		InputStream in = sslSocket.getInputStream();
		byte[] buffer = new byte[50];
		in.read(buffer);
		System.out.println(new String(buffer));
	}
}

```

# Apache的Httpclient库模拟请求


/TestSSL/src/com/ssl/ApacheSSL/HttpRequestService.java

```
package com.ssl.ApacheSSL;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;

import org.apache.http.Header;
import org.apache.http.HttpEntity;
import org.apache.http.ParseException;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.conn.ssl.AllowAllHostnameVerifier;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.conn.ssl.SSLContextBuilder;
import org.apache.http.conn.ssl.SSLSocketFactory;
import org.apache.http.conn.ssl.TrustSelfSignedStrategy;
import org.apache.http.conn.ssl.TrustStrategy;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.util.EntityUtils;

/**
 * Apache库HttpClient模拟SSL请求
 *
 */
public class HttpRequestService {

	private static SSLContext sslContext;

	private static String KEY_STORE_FILE = "e:\\cer\\client.p12";
	private static String KEY_STORE_PASS = "134679";
	private static String TRUST_STORE_FILE = "e:\\cer\\client.truststore";
	private static String TRUST_STORE_PASS = "121314";

	private static HttpClientBuilder httpClientBuilder = null;
	
	public static void main(String[] args) {
		HttpRequestService httpService = new HttpRequestService();
//		String res = httpService.sendPost("https://127.0.0.1:8443/TestSSL/sslServlet", "");
		List<BasicNameValuePair> formparams = new ArrayList<BasicNameValuePair>();
		formparams.add(new BasicNameValuePair("cmd", "zhou"));
		formparams.add(new BasicNameValuePair("data", "kunkun"));
		String res = httpService.sendPost("https://127.0.0.1:8443/TestSSL/sslServlet", formparams);
	}

	public HttpRequestService() {
		httpClientBuilder = getScketBuilder();
	}

	/**
	 * 
	 * 获取双向ssl链接
	 * 
	 * @return
	 * 
	 */
	private HttpClientBuilder getScketBuilder() {

		try {
			//信任自签名方式一
			sslContext = new SSLContextBuilder().loadTrustMaterial(getTrustStore(), new TrustSelfSignedStrategy())
					.loadKeyMaterial(getkeyStore(), KEY_STORE_PASS.toCharArray()).build();
			
			/* 信任自签名方式一
			 * sslContext = new SSLContextBuilder().loadTrustMaterial(getTrustStore(), new TrustStrategy() {
				// 信任所有
				public boolean isTrusted(X509Certificate[] chain, String authType) throws CertificateException {
					return true;
				}
			}).loadKeyMaterial(getkeyStore(), KEY_STORE_PASS.toCharArray()).build();*/
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		// 只允许使用TLSv1协议
		SSLConnectionSocketFactory sslsf = new SSLConnectionSocketFactory(sslContext, new String[] { "TLSv1" }, null, SSLConnectionSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER);

		return HttpClients.custom().setSSLSocketFactory(sslsf);//.build();
	}

	/**
	 * 发送 get请求
	 */
	public String sendGet(String url, String param) {
		CloseableHttpClient httpclient =  httpClientBuilder.build();//HttpClients.createDefault();

		String result = "";
		try {
			// 创建httpGet请求
			HttpGet httpget = new HttpGet(url + "?" + param);
			System.out.println("executing request " + httpget.getURI());
			// 执行Get请求
			CloseableHttpResponse response = httpclient.execute(httpget);

			try {
				// 获取响应实体
				HttpEntity entity = response.getEntity();
				System.out.println("--------------------------------------");
				// 打印响应状态
				System.out.println(response.getStatusLine());
				if (entity != null) {
					// 打印响应内容长度
					// System.out.println("Response content length: " +
					// entity.getContentLength());
					// 打印响应内容
					// System.out.println("Response content: " +
					// EntityUtils.toString(entity));
					result = EntityUtils.toString(entity);

				}
				System.out.println("------------------------------------");
			} finally {
				response.close();
			}
		} catch (ClientProtocolException e) {
			e.printStackTrace();
		} catch (ParseException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		} finally {
			// 关闭连接,释放资源
			try {
				httpclient.close();
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
		return result;
	}

	/**
	 * 发送 post请求访问本地应用并根据传递参数不同返回不同结果
	 */
	public String sendPost(String url, List<BasicNameValuePair> formparams) {
		return 	sendPost(url, formparams,null);
	}

	public String sendPost(String url, List<BasicNameValuePair> formparams,Map<String,String> headers) {
		// 创建默认的httpClient实例.
		CloseableHttpClient httpclient = httpClientBuilder.build();//setScketFactory();// HttpClients.createDefault();
		// 创建httpPost
		HttpPost httppost = new HttpPost(url);
		// 创建参数队列

		UrlEncodedFormEntity uefEntity;
		String result = "";
		try {
			uefEntity = new UrlEncodedFormEntity(formparams, "UTF-8");
			httppost.setEntity(uefEntity);
			if(headers!=null){
				for(String header :headers.keySet()){
					httppost.addHeader(header,headers.get(header));
				}
			}
			System.out.println("executing request " + httppost.getURI());
			CloseableHttpResponse response = httpclient.execute(httppost);
			try {
				HttpEntity entity = response.getEntity();
				if (entity != null) {
					// System.out.println("--------------------------------------");
					// System.out.println("Response content: " +
					// EntityUtils.toString(entity, "UTF-8"));
					// System.out.println("--------------------------------------");
					result = EntityUtils.toString(entity, "UTF-8");
				}
			} finally {
				response.close();
			}
		} catch (ClientProtocolException e) {
			e.printStackTrace();
		} catch (UnsupportedEncodingException e1) {
			e1.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		} finally {
			// 关闭连接,释放资源
			try {
				httpclient.close();
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
		System.out.println("result==" + result);
		return result;




	}
	/**
	 * 上下文初始化
	 * @return
	 */
	public static SSLContext getSSLContext() {
		long time1 = System.currentTimeMillis();
		if (sslContext == null) {
			try {
				KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
				kmf.init(getkeyStore(), KEY_STORE_PASS.toCharArray());
				KeyManager[] keyManagers = kmf.getKeyManagers();

				TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance("SunX509");
				trustManagerFactory.init(getTrustStore());
				TrustManager[] trustManagers = trustManagerFactory.getTrustManagers();

				sslContext = SSLContext.getInstance("TLS");
				sslContext.init(keyManagers, trustManagers, new SecureRandom());
				HttpsURLConnection.setDefaultHostnameVerifier(new HostnameVerifier() {
					@Override
					public boolean verify(String hostname, SSLSession session) {
						return true;
					}
				});
			} catch (FileNotFoundException e) {
				e.printStackTrace();
			} catch (NoSuchAlgorithmException e) {
				e.printStackTrace();
			} catch (IOException e) {
				e.printStackTrace();
			} catch (UnrecoverableKeyException e) {
				e.printStackTrace();
			} catch (KeyStoreException e) {
				e.printStackTrace();
			} catch (KeyManagementException e) {
				e.printStackTrace();
			}
		}
		long time2 = System.currentTimeMillis();
		System.out.println("SSLContext 初始化时间：" + (time2 - time1));
		return sslContext;
	}

	//加载客户端证书库
	public static KeyStore getkeyStore() {
		KeyStore keySotre = null;
		try {
			keySotre = KeyStore.getInstance("PKCS12");
			FileInputStream fis = new FileInputStream(new File(KEY_STORE_FILE));
			keySotre.load(fis, KEY_STORE_PASS.toCharArray());
			fis.close();
		} catch (KeyStoreException e) {
			e.printStackTrace();
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (CertificateException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
		return keySotre;
	}

	//加载信任证书库
	public static KeyStore getTrustStore() throws IOException {
		KeyStore trustKeyStore = null;
		FileInputStream fis = null;
		try {
			trustKeyStore = KeyStore.getInstance("JKS");
			fis = new FileInputStream(new File(TRUST_STORE_FILE));
			trustKeyStore.load(fis, TRUST_STORE_PASS.toCharArray());
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (KeyStoreException e) {
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (CertificateException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		} finally {
			fis.close();
		}
		return trustKeyStore;
	}

}
```

run完结果

```
executing request https://127.0.0.1:8443/TestSSL/sslServlet
result==cmd=[zhou], data=[kunkun]
共检测到[1]个客户端证书
客户端证书 [1]： 
校验结果：true
证书详细：
[
[
  Version: V3
  Subject: CN=client, OU=sumscope, O=sumscope, L=Pudong, ST=Shanghai, C=com
  Signature Algorithm: SHA256withRSA, OID = 1.2.840.113549.1.1.11

  Key:  Sun RSA public key, 2048 bits
  modulus: 16775184541376789980523623342157723954719879848605626458780041512544850767818975195253889935241588670263189667341419658862928229950159207498066656362984889917601750105654672212149569612807331033127443866093913247604639379344621875867943324118265775115824160851544482528831309458633614251377617519609195178303513692379018910515389447851932236476603717122243366112417500572908519281892184337160131730224759584827467024143664316437412505569454987380992889241893627651231456070296281468279466090975020412575289124857131625044428797709550742288520643080956106113202333752358761022055028393305469474684700736903343742291057
  public exponent: 65537
  Validity: [From: Wed Nov 02 10:55:30 CST 2016,
               To: Thu Nov 02 10:55:30 CST 2017]
  Issuer: CN=client, OU=sumscope, O=sumscope, L=Pudong, ST=Shanghai, C=com
  SerialNumber: [    799d5436]

Certificate Extensions: 1
[1]: ObjectId: 2.5.29.14 Criticality=false
SubjectKeyIdentifier [
KeyIdentifier [
0000: 99 A8 3D 21 07 80 28 F4   A4 1F 0D 2A 3B ED 52 BA  ..=!..(....*;.R.
0010: 4C F1 49 AB                                        L.I.
]
]

]
  Algorithm: [SHA256withRSA]
  Signature:
0000: 16 AA 53 C7 34 63 14 A9   FE 2F B2 75 01 96 7D 4A  ..S.4c.../.u...J
0010: 64 8C 49 6C 60 36 9D 2F   65 18 50 8F 44 06 DF E9  d.Il`6./e.P.D...
0020: 70 B4 E7 BF 8D F4 AC 4B   41 7B FB 7F CB 00 4A D7  p......KA.....J.
0030: A3 6F 51 B6 E9 42 CB 9E   44 05 E5 45 46 3C 25 00  .oQ..B..D..EF<%.
0040: 28 57 FC D0 9D AF 30 F0   C6 1A FD 49 00 3D 97 1E  (W....0....I.=..
0050: 7D AB 07 29 E3 27 DF 1A   75 4B B4 88 51 1A 31 F6  ...).'..uK..Q.1.
0060: 15 4E 9D 9B EC 11 A6 C1   FD 8C 96 0B 21 DC 41 2E  .N..........!.A.
0070: 8F EA 71 B2 2B 61 DE 87   7A 7C FA 5A 2F 83 65 9B  ..q.+a..z..Z/.e.
0080: 1C AA 8C 2F 58 48 13 31   E0 A1 0F 76 95 E8 D9 02  .../XH.1...v....
0090: 17 75 2A 0F 71 0C DF 1D   65 41 55 2B 04 8B B4 A7  .u*.q...eAU+....
00A0: 83 9D F0 05 F8 79 61 1A   43 11 F7 AD D4 20 B0 22  .....ya.C.... ."
00B0: 1E A4 C0 1C AE B9 92 62   DA CB 89 DB C8 79 BA E9  .......b.....y..
00C0: 37 A8 D9 FF 07 CE 20 70   29 3C D4 7B 82 D3 52 F9  7..... p)<....R.
00D0: 8E 5A 25 22 B7 1C 77 BF   DF 91 7A B9 5A 42 5D 6C  .Z%"..w...z.ZB]l
00E0: D4 A3 E7 15 A5 44 43 B1   DC A0 2E D4 DD 8D 61 D1  .....DC.......a.
00F0: 61 A0 FC 01 C4 44 37 8B   8A 55 0C D1 5D 86 4B 12  a....D7..U..].K.

]
```


代码:https://github.com/kun10/SSLDemo
