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
		System.out.println("返回："+res);
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