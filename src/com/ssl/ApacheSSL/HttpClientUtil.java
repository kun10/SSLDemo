package com.ssl.ApacheSSL;

import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.NameValuePair;
import org.apache.http.client.HttpClient;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.conn.scheme.Scheme;
import org.apache.http.conn.ssl.SSLSocketFactory;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.util.EntityUtils;

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.security.KeyStore;
import java.util.*;

/**
 * Apache库HttpClient模拟SSL Post请求
 *
 */
public class HttpClientUtil {

    private static final String KEY_STORE_TYPE_JKS = "jks";
    private static final String KEY_STORE_TYPE_P12 = "PKCS12";
    private static final String SCHEME_HTTPS = "https";
    private static final int HTTPS_PORT = 8443;
    private static final String HTTPS_URL = "https://localhost:8443/TestSSL/sslServlet";
    private static final String KEY_STORE_CLIENT_PATH = "e:\\cer\\client.p12";
    private static final String KEY_STORE_TRUST_PATH = "e:\\cer\\client.truststore";
    private static final String KEY_STORE_PASSWORD = "134679";
    private static final String KEY_STORE_TRUST_PASSWORD = "121314";

    public static void main(String[] args){
        String url=HTTPS_URL;
        Map params=new HashMap();
        params.put("cmd","test");
        params.put("data","֤��1");
        String charset="utf-8";
        doSSLPost( url, params,  charset);
    }

    private static void doSSLPost(String url, Map<String, String> map, String charset) {
        HttpClient httpClient = new DefaultHttpClient();
        String result = null;
        try {
            KeyStore keyStore = KeyStore.getInstance(KEY_STORE_TYPE_P12);
            KeyStore trustStore = KeyStore.getInstance(KEY_STORE_TYPE_JKS);
            InputStream ksIn = new FileInputStream(KEY_STORE_CLIENT_PATH);
            InputStream tsIn = new FileInputStream(new File(KEY_STORE_TRUST_PATH));
            try {
                keyStore.load(ksIn, KEY_STORE_PASSWORD.toCharArray());
                trustStore.load(tsIn, KEY_STORE_TRUST_PASSWORD.toCharArray());
            } finally {
                try {
                    ksIn.close();
                } catch (Exception ignore) {
                }
                try {
                    tsIn.close();
                } catch (Exception ignore) {
                }
            }
            SSLSocketFactory socketFactory = new SSLSocketFactory(keyStore, KEY_STORE_PASSWORD, trustStore);
            Scheme sch = new Scheme(SCHEME_HTTPS, HTTPS_PORT, socketFactory);
            httpClient.getConnectionManager().getSchemeRegistry().register(sch);
            HttpPost httpPost = new HttpPost(url);
            //���ò���
            if (map != null) {
                List<NameValuePair> list = new ArrayList<NameValuePair>();
                Iterator iterator = map.entrySet().iterator();
                while (iterator.hasNext()) {
                    Map.Entry<String, String> elem = (Map.Entry<String, String>) iterator.next();
                    list.add(new BasicNameValuePair(elem.getKey(), elem.getValue()));
                }
                httpPost.setEntity(new UrlEncodedFormEntity(list, charset));
            }
            HttpResponse response = httpClient.execute(httpPost);
            if (response != null) {
                HttpEntity resEntity = response.getEntity();
                if (resEntity != null) {
                    result = EntityUtils.toString(resEntity, charset);
                }
            }
            System.out.println("result={" + result + "}");
        }catch(Exception e){
            e.printStackTrace();
        } finally {
            httpClient.getConnectionManager().shutdown();
        }
    }
}