package lingxi.signature;

import lingxi.signature.exception.SignatureTimestampException;
import lingxi.signature.exception.SignatureValueException;
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

    final private int TIME_EXPIRED = 600;

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

    Boolean attempt(HashMap<Object, Object> parameters) throws UnsupportedEncodingException, SignatureValueException, NoSuchAlgorithmException, InvalidKeyException, SignatureTimestampException {
        return this.verify(parameters);
    }

    boolean verify(HashMap<Object, Object> parameters) throws SignatureTimestampException, SignatureValueException, UnsupportedEncodingException, InvalidKeyException, NoSuchAlgorithmException {
        // 检查时间是否过期
        this.checkTimestampInValid(parameters);

        // 检查签名是否正确
        this.checkSignatureValue(parameters);

        return true;
    }

    private void checkSignatureValue(HashMap<Object, Object> parameters) throws SignatureValueException, UnsupportedEncodingException, InvalidKeyException, NoSuchAlgorithmException {
        if (! parameters.containsKey("signature")) {
            throw new SignatureValueException("签名错误");
        }

        String requestSignature = parameters.get("signature").toString();

        if (! requestSignature.equals(this.generateAuthParameters(parameters).get("signature").toString())) {
            throw new SignatureValueException("签名错误");
        }
    }

    private void checkTimestampInValid(HashMap<Object, Object> parameters) throws SignatureTimestampException {
        if (! parameters.containsKey("stamp")) {
            throw new SignatureTimestampException("请求时间过期，请重新请求");
        }

        int requestTime = Integer.valueOf(parameters.get("stamp").toString());
        int now = Integer.valueOf(Helper.time());

        if (now - requestTime > TIME_EXPIRED) {
            throw new SignatureTimestampException("请求时间过期，请重新请求");
        }
    }

    HashMap getAuthParams(HashMap<Object, Object> parameters) throws UnsupportedEncodingException, InvalidKeyException, NoSuchAlgorithmException {
        parameters.put("stamp", Helper.time());
        parameters.put("noncestr", Helper.randomString());
        parameters.put(this.getApiKeyName(), this.getApiKey());

        return this.generateAuthParameters(parameters);
    }

    private HashMap generateAuthParameters(HashMap<Object, Object> parameters) throws UnsupportedEncodingException, InvalidKeyException, NoSuchAlgorithmException {
        SortedMap<String, String> sortedMap = new TreeMap<>();

        for (Map.Entry<Object, Object> entry : parameters.entrySet()) {
            Object value = entry.getValue();
            String key = entry.getKey().toString();

            // 过滤一些字段和值为空的数据
            if (key.equals("signature") || value == null || value.equals("")) {
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

        String queryLink = Helper.createQueryLink(sortedMap);

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
