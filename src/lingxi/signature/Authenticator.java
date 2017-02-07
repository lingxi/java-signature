package lingxi.signature;

import org.json.simple.JSONArray;
import org.json.simple.JSONObject;

import java.util.*;
import java.security.InvalidKeyException;
import java.io.UnsupportedEncodingException;
import java.security.NoSuchAlgorithmException;

public class Authenticator {

    private String apiKey;

    private String apiSecret;

    private String apiKeyName;

    Authenticator(String apiKey, String apiSecret) {
        this.apiKey = apiKey;
        this.apiSecret = apiSecret;
        this.apiKeyName = "api_key";
    }

    Authenticator(String apiKey, String apiSecret, String apiKeyName) {
        this.apiKey = apiKey;
        this.apiSecret = apiSecret;
        this.apiKeyName = apiKeyName;
    }

    HashMap getAuthParams(HashMap<Object, Object> parameters) throws UnsupportedEncodingException, InvalidKeyException, NoSuchAlgorithmException {
        parameters.put("stamp", String.valueOf(System.currentTimeMillis()).substring(0, 10));
        parameters.put("noncestr", Helper.randomString());
        parameters.put(this.getApiKeyName(), this.getApiKey());

        return this.generateAuthParameters(parameters);
    }

    private HashMap generateAuthParameters(HashMap<Object, Object> parameters) throws UnsupportedEncodingException, InvalidKeyException, NoSuchAlgorithmException {
        SortedMap<String, String> sortedMap = new TreeMap<>();

        for (Map.Entry<Object, Object> entry : parameters.entrySet()) {
            Object value = entry.getValue();
            String key = entry.getKey().toString();

            // 普通数字字符串不为空
            if (value == null || value == "") {
                continue;
            }

            // 不为空的 Map，转化为 json
            if (value instanceof Map && ! ((Map) value).isEmpty()) {
                String tmp = JSONObject.toJSONString(((Map) value));
                parameters.put(key, tmp);
                sortedMap.put(key, tmp);
                continue;
            }

            // 转化 List 为 json
            if (value instanceof List && ! ((List) value).isEmpty()) {
                String tmp = JSONArray.toJSONString(((List) value));
                parameters.put(key, tmp);
                sortedMap.put(key, tmp);
                continue;
            }

            // 最后向 map 里面添加普通字符
            sortedMap.put(key, value.toString());
        }

        String queryLink = "";
        for (Map.Entry<String, String> entry : sortedMap.entrySet()) {
            queryLink += entry.getKey() + "=" + entry.getValue() + "&";
        }

        queryLink = Helper.createQueryLink(sortedMap);

        parameters.put("signature", Helper.sha256(queryLink, this.getApiSecret()));

        return parameters;
    }

    public String getApiKey() {
        return apiKey;
    }

    public void setApiKey(String apiKey) {
        this.apiKey = apiKey;
    }

    public String getApiSecret() {
        return apiSecret;
    }

    public void setApiSecret(String apiSecret) {
        this.apiSecret = apiSecret;
    }

    public String getApiKeyName() {
        return apiKeyName;
    }

    public void setApiKeyName(String apiKeyName) {
        this.apiKeyName = apiKeyName;
    }
}
