
package authprovider;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;


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
		
	private void doGetIntern(HttpServletRequest req, HttpServletResponse resp)
				throws IOException {
		int i = req.getRequestURI().indexOf(req.getServletPath());
		if (i<0)
			throw new IllegalArgumentException("ServletPath: "+req.getServletPath()+", Request URI: "+req.getRequestURI());
		
		String action = req.getRequestURI().substring(i+req.getServletPath().length());
		Map<Object,List<Object>> paramMap = new HashMap<Object,List<Object>>();
		for (Object key : req.getParameterMap().keySet()) {
			paramMap.put(key, Arrays.asList(((Object[])req.getParameterMap().get(key))));
		}
		if ("/login".equalsIgnoreCase(action)) {
			logger.log(Level.INFO, paramMap.toString());
			resp.setStatus(307);			
		} else if ("/consent".equalsIgnoreCase(action)) {
			logger.log(Level.INFO, paramMap.toString());
			resp.setStatus(307);			
		} else {
			resp.setStatus(404);			
		}

	}
}
