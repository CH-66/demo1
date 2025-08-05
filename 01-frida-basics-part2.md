## 7. Frida 进阶技术

### 7.1. Java 层 Hook

#### 7.1.1. Hook 构造函数

```javascript
Java.perform(function () {
    var MyClass = Java.use("com.example.app.MyClass");
    MyClass.$init.implementation = function (arg1, arg2) {
        console.log("MyClass constructor called with: " + arg1 + ", " + arg2);
        return this.$init(arg1, arg2);
    };
});
```

#### 7.1.2. Hook 内部类和匿名类

```javascript
Java.perform(function () {
    var OuterClass = Java.use("com.example.app.OuterClass$InnerClass");
    // Hook 内部类的方法

    var AnonymousClass = Java.use("com.example.app.MainActivity$1");
    // Hook 匿名类的方法
});
```

#### 7.1.3. 主动调用 Java 方法

```javascript
Java.perform(function () {
    var MyClass = Java.use("com.example.app.MyClass");
    var instance = MyClass.$new(); // 创建实例
    var result = instance.myMethod("hello");
    console.log("Result: " + result);
});
```

### 7.2. Native 层 Hook

#### 7.2.1. Hook 导出函数

```javascript
Interceptor.attach(Module.getExportByName("libnative.so", "my_function"), {
    onEnter: function (args) {
        console.log("my_function called with: " + args[0].toInt32());
    },
    onLeave: function (retval) {
        console.log("my_function returned: " + retval.toInt32());
    }
});
```

#### 7.2.2. Hook 未导出函数（基于地址）

```javascript
var baseAddr = Module.findBaseAddress("libnative.so");
var funcAddr = baseAddr.add(0x1234); // 函数在 so 中的偏移

Interceptor.attach(funcAddr, {
    // ...
});
```

### 7.3. 内存操作

#### 7.3.1. 搜索内存

```javascript
Memory.scan(Process.getModuleByName("libnative.so").base, Process.getModuleByName("libnative.so").size, "48 65 6c 6c 6f", {
    onMatch: function (address, size) {
        console.log("Found 'Hello' at: " + address);
        return 'stop';
    },
    onComplete: function () {
        console.log("Scan complete");
    }
});
```

#### 7.3.2. 读写内存

```javascript
var addr = ptr(0x12345678);
console.log(Memory.readUtf8String(addr));

Memory.writeUtf8String(addr, "Goodbye");
```

### 7.4. Stalker 的使用

```javascript
var threadId = Process.getCurrentThreadId();
Stalker.follow(threadId, {
    events: {
        call: true,
        ret: false,
        exec: false,
        block: false,
        compile: false
    },
    onReceive: function (events) {
        console.log(Stalker.parse(events));
    }
});
```

## 8. Frida 实战脚本集合

### 8.1. SSL Pinning 绕过

一个通用的 SSL Pinning 绕过脚本，适用于多种常见的实现方式。

[查看脚本](https://codeshare.frida.re/@pcipolloni/universal-android-ssl-pinning-bypass-with-frida/)

### 8.2. 加密算法 Hook

Hook `javax.crypto.Cipher` 来捕获加密和解密的密钥和数据。

[查看脚本](https://codeshare.frida.re/@muzzz/dump-javax-crypto-cipher-secretkey/)

### 8.3. 反调试绕过

针对常见的反调试技术，如检测 `frida-server`、`TracerPid` 等。

[查看脚本](https://codeshare.frida.re/@liangxiaoyi/anti-anti-frida/)

### 8.4. DUMP Dex 文件

在内存中 dump 出应用程序的 Dex 文件，用于静态分析。

[查看脚本](https://github.com/hluwa/frida-dexdump)