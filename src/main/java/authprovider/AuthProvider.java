
package authprovider;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLSession;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.lang.StringUtils;
import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPut;
import org.apache.http.client.methods.HttpRequestBase;
import org.apache.http.conn.ssl.SSLSocketFactory;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.HttpClientBuilder;
import org.json.JSONException;
import org.json.JSONObject;

public class AuthProvider extends HttpServlet {
	private Logger logger = Logger.getLogger("DockerAuth");



	@Override
	public void doGet(HttpServletRequest req, HttpServletResponse resp)
			throws IOException {
		try {
			doGetIntern(req, resp);
		} catch (Exception e) {
			logger.log(Level.SEVERE, "", e);
			throw new RuntimeException(e);
		}
	}
		
	private static final String HYDRA_ENDPOINT = getProperty("HYDRA_ENDPOINT");

	private void doGetIntern(HttpServletRequest req, HttpServletResponse resp)
				throws IOException, KeyManagementException, UnrecoverableKeyException, UnsupportedOperationException, JSONException, NoSuchAlgorithmException, KeyStoreException {
		int i = req.getRequestURI().indexOf(req.getServletPath());
		if (i<0)
			throw new IllegalArgumentException("ServletPath: "+req.getServletPath()+", Request URI: "+req.getRequestURI());
		
		String action = req.getRequestURI().substring(i+req.getServletPath().length());
		Map<Object,List<Object>> paramMap = new HashMap<Object,List<Object>>();
		for (Object key : req.getParameterMap().keySet()) {
			paramMap.put(key, Arrays.asList(((Object[])req.getParameterMap().get(key))));
		}
		if ("/login".equalsIgnoreCase(action)) {
			logger.info(paramMap.toString());
			String loginChallenge = req.getParameter("login_challenge");
			if (StringUtils.isEmpty(loginChallenge)) throw new IllegalArgumentException("missing login_challenge request parameter.");
			// GET "https://localhost:9001/oauth2/auth/requests/login/"+loginChallenge
			// see the javascript example here:
			// https://github.com/ory/hydra-login-consent-node/blob/322b7f631bb8c58c9998cd5f130ced0ea9496465/routes/login.js
			// this provides add'l info, esp. 'skip', which tells us not to prompt the user to log in
			HttpGet get = new HttpGet(HYDRA_ENDPOINT+"/oauth2/auth/requests/login/"+loginChallenge);
			JSONObject getResult = executeRequest(get, 200);
			logger.info("Login request returned "+getResult);
			boolean skip = false;
			if (getResult.has("skip")) skip = getResult.getBoolean("skip");
			
			String requestBody = null;
			if (skip) {
				requestBody = "{\"subject\":\"user-name\"}";
			} else {
				requestBody = "{\"subject\":\"user-name\",\"remember\":true,\"remember_for\":3600}";
			}
			HttpPut put = new HttpPut(HYDRA_ENDPOINT+"/oauth2/auth/requests/login/"+loginChallenge+"/accept"); //... or +"/reject"
			HttpEntity httpEntity = new StringEntity(requestBody, ContentType.APPLICATION_JSON);
			put.setEntity(httpEntity);
			JSONObject result = executeRequest(put, 200);
			if (StringUtils.isEmpty( result.getString("redirect_to"))) throw new IllegalStateException("No redirect_to in "+result);
			resp.setHeader("Location", result.getString("redirect_to"));
			resp.setStatus(302);
			logger.info("Redirecting to "+result.getString("redirect_to"));
		} else if ("/consent".equalsIgnoreCase(action)) {
			logger.info(paramMap.toString());
			String consentChallenge = req.getParameter("consent_challenge");
			if (StringUtils.isEmpty(consentChallenge)) throw new IllegalArgumentException("missing consent_challenge request parameter.");

			
			HttpGet get = new HttpGet(HYDRA_ENDPOINT+"/oauth2/auth/requests/consent/"+consentChallenge);
			JSONObject getResult = executeRequest(get, 200);
			logger.info("Consent request returned "+getResult);
			JSONObject putBody = new JSONObject();
			putBody.put("grant_scope", getResult.get("requested_scope"));
			HttpPut put = new HttpPut(HYDRA_ENDPOINT+"/oauth2/auth/requests/consent/"+consentChallenge+"/accept");  //... or +"/reject"
			logger.info("Putting to URL: "+put.getURI()+", body: "+putBody.toString());
			HttpEntity httpEntity = new StringEntity(putBody.toString(), ContentType.APPLICATION_JSON);
			put.setEntity(httpEntity);
			JSONObject putResult = executeRequest(put, 200);
			if (StringUtils.isEmpty(putResult.getString("redirect_to"))) throw new IllegalStateException("No redirect_to in "+putResult);
			resp.setHeader("Location", putResult.getString("redirect_to"));
			resp.setStatus(302);			
			logger.info("Redirecting to "+putResult.getString("redirect_to"));
		} else {
			resp.setStatus(404);
		}
	}
	
	
	private static void checkHttpResponseCode(HttpResponse response, int expected) throws IOException {
		if (expected!=response.getStatusLine().getStatusCode()) {
			InputStream inputStream = response.getEntity().getContent();
			StringBuffer result = new StringBuffer();
			try {
				BufferedReader rd = new BufferedReader(
						new InputStreamReader(inputStream));

				String line = "";
				while ((line = rd.readLine()) != null) {
					result.append(line);
				}
			} finally {
				inputStream.close();
			}
			throw new RuntimeException("Expected "+expected+" but received "+
					response.getStatusLine().getStatusCode()+" Response body: "+result.toString());	
		}
	}
	
	
	private static JSONObject getResponseBodyAsJson(HttpResponse response) throws UnsupportedOperationException, IOException, JSONException {
		InputStream inputStream = response.getEntity().getContent();
		StringBuffer result = new StringBuffer();
		try {
			BufferedReader rd = new BufferedReader(
					new InputStreamReader(inputStream));

			String line = "";
			while ((line = rd.readLine()) != null) {
				result.append(line);
			}
		} finally {
			inputStream.close();
		}
		return new JSONObject(result.toString());
	}
	
	private static HttpClient getHttpClient() throws KeyManagementException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException {
		org.apache.http.conn.ssl.TrustStrategy acceptingTrustStrategy = new org.apache.http.conn.ssl.TrustStrategy() {
			public boolean isTrusted(X509Certificate[] chain, String authType) throws CertificateException {
				return true;
			}};
	    		
	    SSLSocketFactory sf = new SSLSocketFactory(acceptingTrustStrategy);
	    
	    HostnameVerifier hostnameVerifier = new HostnameVerifier() {

			public boolean verify(String hostname, SSLSession session) {
				return true;
			}};
	    
		return HttpClientBuilder.create().setSSLSocketFactory(sf).setSSLHostnameVerifier(hostnameVerifier).build();
	}
	public JSONObject executeRequest(final HttpRequestBase request, final int expecteResponseCode) throws UnsupportedOperationException, IOException, JSONException, KeyManagementException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException {		
		HttpResponse response = getHttpClient().execute(request);
		checkHttpResponseCode(response, expecteResponseCode);
		return getResponseBodyAsJson(response);
	}

	private static boolean missing(String s) {
		return StringUtils.isEmpty(s) || "null".equals(s);
	}


	public static String getProperty(String key) {
		return getProperty(key, true);
	}
	public static String getProperty(String key, boolean required) {
		{
			String commandlineOption = System.getProperty(key);
			if (!missing(commandlineOption)) return commandlineOption;
		}
		{
			String environmentVariable = System.getenv(key);
			if (!missing(environmentVariable)) return environmentVariable;
		}
		if (required) throw new RuntimeException("Cannot find value for "+key);
		return null;
	}
}
