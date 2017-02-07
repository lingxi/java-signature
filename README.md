# 灵析 API 签名包

> 目前 java 版本不包括 HTTP 请求部分

### 依赖

手动下载 jar 包

[Apache Commons 的 Hex](https://commons.apache.org/proper/commons-codec/download_codec.cgi)

[Json-Simple](https://code.google.com/archive/p/json-simple/)

### 基本用法

获取请求的验证数据

```java
package lingxi.signature;

import java.util.*;

public class Main {

    public static void main(String[] args) {
        Authenticator auther = new Authenticator("your-key", "your-secret");

        // 请求参数
        HashMap<Object, Object> data = new HashMap<>();

        // 数组参数使用 ArrayList
        List<Integer> ids = new ArrayList<>();
        i.add(1);
        i.add(2);
        i.add(3);

        // HashMap 参数
        HashMap<Object, Object> m = new HashMap<>();
        m.put("key1", "value");
        m.put("key2", "value");
        m.put("key3", i);

        // 普通分页参数
        data.put("page", 2);
        data.put("per_page", 3);

        try {
            HashMap query = auther.getAuthParams(data);

            System.out.println("http://api.lingxi.com/v1/test/auth?" + Helper.createQueryLink(query));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

```

### 签名验证

```java
try {
    HashMap<Object, Object> data1 = new HashMap<>();
    data1.put("key", "secret");

    if (auther.attempt(data1)) {
        // passed, do you want...        
    }
} catch (SignatureTimestampException | SignatureValueException e) {
    System.out.println(e.getMessage());
} catch (Exception e) {
    e.printStackTrace();
}
```
