package lingxi.signature;

import org.apache.commons.codec.binary.Hex;

import java.util.*;
import javax.crypto.Mac;
import java.net.URLEncoder;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.io.UnsupportedEncodingException;
import java.security.NoSuchAlgorithmException;

public class Helper {

    public static String randomString() {
        return randomString(8);
    }

    public static String time() {
        return String.valueOf(System.currentTimeMillis()).substring(0, 10);
    }

    public static String randomString(int length) {
        String base = "abcdefghijklmnopqrstuvwxyz0123456789";
        Random random = new Random();
        StringBuffer sb = new StringBuffer();

        for (int i = 0; i < length; i++) {
            int number = random.nextInt(base.length());
            sb.append(base.charAt(number));
        }

        return sb.toString();
    }

    public static String sha256(String string, String key) throws NoSuchAlgorithmException, UnsupportedEncodingException, InvalidKeyException {
        Mac sha256_HMAC = Mac.getInstance("HmacSHA256");
        SecretKeySpec secret_key = new SecretKeySpec(key.getBytes("UTF-8"), "HmacSHA256");
        sha256_HMAC.init(secret_key);

        return Hex.encodeHexString(sha256_HMAC.doFinal(string.getBytes("UTF-8")));
    }

    public static String createQueryLink(Map<String, String> parameters) throws UnsupportedEncodingException {
        String queryLink = "";
        for (Map.Entry<String, String> entry : parameters.entrySet()) {
            queryLink += entry.getKey() + "=" + URLEncoder.encode(String.valueOf(entry.getValue()), "utf-8") + "&";
        }

        return queryLink.substring(0, queryLink.length() - 1);
    }

}
