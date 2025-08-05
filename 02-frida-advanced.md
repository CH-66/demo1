# Frida 进阶技术

## Java层Hook技术

### 1. Hook构造函数

```javascript
Java.perform(function() {
    var String = Java.use("java.lang.String");
    
    // Hook String构造函数
    String.$init.overload('java.lang.String').implementation = function(str) {
        console.log("[*] String构造函数被调用，参数: " + str);
        return this.$init(str);
    };
});
```