## 9. Frida 调试技巧

### 9.1. 使用 `console.log`

最简单直接的调试方式，可以输出变量、对象和函数调用的信息。

```javascript
console.log(JSON.stringify(some_object)); // 打印对象
console.log(Java.use('android.util.Log').getStackTraceString(Java.use('java.lang.Exception').$new())); // 打印调用栈
```

### 9.2. 在 Chrome DevTools 中调试

Frida 支持 Chrome DevTools 协议，可以在 Chrome 浏览器中进行断点调试。

```bash
frida -U -f com.example.app -l a.js --debug
```

然后在 Chrome 中打开 `chrome://inspect` 即可看到你的设备和进程。

### 9.3. r2frida

`r2frida` 是一个将 Frida 与 [radare2](https://github.com/radareorg/radare2) 集成的插件，提供了更强大的逆向分析和调试功能。

安装：

```bash
r2pm -i r2frida
```

使用：

```bash
r2 frida://<pid|spawn|attach>/<device-id>
```

## 10. 常见问题与解决方案

*   **`frida-server` 版本不匹配**：确保 PC 上的 `frida-tools` 和设备上的 `frida-server` 版本一致。
*   **无法附加到进程**：检查 `frida-server` 是否正常运行，以及设备是否开启了 USB 调试和允许模拟点击。
*   **脚本报错 `access violation`**：通常是内存访问错误，检查地址和指针是否有效。

## 11. 推荐资源

*   [Frida 官方文档](https://frida.re/docs/home/)
*   [Frida CodeShare](https://codeshare.frida.re/)
*   [Awesome Frida](https://github.com/dweinstein/awesome-frida)

---

希望本教程能帮助你快速入门 Frida，并开启你的逆向工程之旅！