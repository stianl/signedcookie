package no.furry;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

/**
 * @author Stian
 */
public class CookieFilter implements javax.servlet.Filter {

    public static final String SESSION_COOKIE_NAME = "FURRY_SESSION";
    final char[] HEX_CHARS = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
    private final static String secretKey = "whatever";

    public void destroy() {
    }

    /*
     * /<context>/login?user=admin&password=admin123 will issue signed cookie
     * /<context>/logout will remove the cookie ("session")
     *
     * Any other request will return a 403 forbidden if the cookie is not present or invalid.
     * If the cookie is present and valid the filter chain will be continued (a 404 will be issued if no resource/servlet is found)
     */
    public void doFilter(javax.servlet.ServletRequest req, javax.servlet.ServletResponse resp, javax.servlet.FilterChain chain) throws javax.servlet.ServletException, IOException {
        HttpServletRequest request = (HttpServletRequest) req;
        Cookie[] cookies = request.getCookies();
        if (request.getServletPath().startsWith("/logout")) {
            if (cookies != null)
                for (Cookie cookie : cookies) {
                    if (cookie.getName().equals(SESSION_COOKIE_NAME)) {
                        Cookie sessionCookie = new Cookie(SESSION_COOKIE_NAME, "");
                        sessionCookie.setMaxAge(0);
                        ((HttpServletResponse) resp).addCookie(sessionCookie);
                        resp.getWriter().write("LOGOUT OK");
                        return;
                    }
                }
        }
        if (request.getServletPath().startsWith("/login")) {
            String user = request.getParameter("user");
            if (user != null && request.getParameter("password") != null) {
                if (user.equals("admin") && request.getParameter("password").equals("admin123")) {
                    try {
                        ((HttpServletResponse) resp).addCookie(new Cookie(SESSION_COOKIE_NAME, sign(secretKey, user) + "-" + user));
                        resp.getWriter().write("LOGIN OK");
                        return;
                    } catch (NoSuchAlgorithmException e) {
                        throw new ServletException(e);
                    } catch (InvalidKeyException e) {
                        throw new ServletException(e);
                    }
                } else {
                    resp.getWriter().write("LOGIN FAILED");
                    ((HttpServletResponse) resp).sendError(HttpServletResponse.SC_FORBIDDEN);
                }
            }
        } else {
            try {
                if (cookies != null)
                    for (Cookie cookie : cookies) {
                        if (cookie.getName().equals(SESSION_COOKIE_NAME)) {
                            String cookieValue = cookie.getValue();
                            String signed = cookieValue.substring(0, cookieValue.indexOf("-"));
                            String data = cookieValue.substring(cookieValue.indexOf("-") + 1);
                            String signedMessage = sign(secretKey, data);
                            if (signedMessage.equals(signed)) {
                                System.out.println("it is ok - please go on");
                                chain.doFilter(req, resp);
                                return;
                            }
                        }
                    }

            } catch (NoSuchAlgorithmException e) {
                throw new ServletException(e);
            } catch (InvalidKeyException e) {
                throw new ServletException();
            }
        }
        ((HttpServletResponse) resp).sendError(HttpServletResponse.SC_FORBIDDEN);
    }

    private String sign(String key, String message) throws NoSuchAlgorithmException, InvalidKeyException, UnsupportedEncodingException {
        Mac mac = Mac.getInstance("HmacSHA1");
        SecretKeySpec secretKeySpec = new SecretKeySpec(key.getBytes(), "HmacSHA1");
        mac.init(secretKeySpec);
        byte[] result = mac.doFinal(message.getBytes("UTF-8"));
        int len = result.length;
        char[] hexChars = new char[len * 2];

        for (int charIndex = 0, startIndex = 0; charIndex < hexChars.length; ) {
            int bite = result[startIndex++] & 0xff;
            hexChars[charIndex++] = HEX_CHARS[bite >> 4];
            hexChars[charIndex++] = HEX_CHARS[bite & 0xf];
        }
        return new String(hexChars);
    }

    public void init(javax.servlet.FilterConfig config) throws javax.servlet.ServletException {

    }

}