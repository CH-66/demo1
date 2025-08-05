# Frida 基础入门教程

## 1. Frida 是什么？

Frida 是一款功能强大的动态插桩工具，可以帮助我们深入探索和控制应用程序的行为。它支持多种平台，包括 Windows、macOS、Linux、iOS 和 Android，并提供了 Python、JavaScript 等多种语言的绑定。

通过 Frida，我们可以实现以下功能：

*   **Hooking**：拦截和修改函数调用，观察或篡改应用程序的内部状态。
*   **代码注入**：在目标进程中执行自定义的 JavaScript 代码。
*   **内存操作**：搜索、读取和写入目标进程的内存。
*   **反调试和反监控**：绕过应用程序的安全检测机制。

## 2. 安装 Frida

### 2.1. 安装 Frida 工具

首先，我们需要在 PC 上安装 Frida 的命令行工具。推荐使用 Python 的包管理器 `pip` 进行安装：

```bash
pip install frida-tools
```

安装完成后，可以通过以下命令验证是否安装成功：

```bash
frida --version
```

### 2.2. 在移动设备上运行 frida-server

要在移动设备上使用 Frida，需要在设备上运行 `frida-server`。首先，从 Frida 的 [GitHub Releases](https://github.com/frida/frida/releases) 页面下载与设备架构相匹配的 `frida-server`。

下载完成后，将其推送到设备的 `/data/local/tmp` 目录下，并授予执行权限：

```bash
adb push frida-server /data/local/tmp/
adb shell "chmod 755 /data/local/tmp/frida-server"
```

然后，在 `adb shell` 中以后台方式运行 `frida-server`：

```bash
adb shell "/data/local/tmp/frida-server &"
```

## 3. Frida 的基本概念

在使用 Frida 之前，我们需要了解一些基本概念：

*   **Session**：Frida 与目标进程的交互会话。每个会话都有一个唯一的标识符。
*   **Script**：我们编写的 JavaScript 代码，用于在目标进程中执行。
*   **Stalker**：Frida 的代码跟踪引擎，可以记录和分析函数的执行流程。
*   **Interceptor**：Frida 的函数拦截器，用于 Hooking。

## 4. 第一个 Frida 脚本

让我们从一个简单的例子开始，编写一个脚本来 Hook 安卓应用程序中的 `Toast` 消息。

```javascript
// a.js
Java.perform(function () {
    var Toast = Java.use("android.widget.Toast");
    Toast.makeText.overload('android.content.Context', 'java.lang.CharSequence', 'int').implementation = function (context, text, duration) {
        console.log("Toast message: " + text);
        return this.makeText(context, text, duration);
    };
});
```

这个脚本的含义是：

1.  `Java.perform`：确保在 Java 虚拟机环境准备就绪后执行我们的代码。
2.  `Java.use`：获取 `android.widget.Toast` 类的引用。
3.  `Toast.makeText.overload(...)`：选择要 Hook 的 `makeText` 方法的重载版本。
4.  `.implementation`：替换原始方法的实现。
5.  `console.log`：在 Frida 的控制台输出日志。
6.  `return this.makeText(...)`：调用原始方法，确保应用程序正常运行。

## 5. 运行 Frida 脚本

### 5.1. 查看进程列表

在运行脚本之前，我们需要找到目标应用程序的进程 ID 或包名。可以使用 `frida-ps` 命令查看当前正在运行的进程：

```bash
frida-ps -Ua
```

*   `-U`：连接到 USB 设备。
*   `-a`：显示应用程序的详细信息，包括包名。

### 5.2. 附加到进程

找到目标进程后，使用 `frida` 命令附加到该进程，并加载我们的脚本：

```bash
frida -U -f com.example.app -l a.js
```

*   `-f com.example.app`：启动并附加到指定的应用程序。
*   `-l a.js`：加载名为 `a.js` 的脚本。

### 5.3. 恢复应用程序

附加成功后，应用程序会处于暂停状态。在 Frida 的交互式控制台中输入 `%resume` 来恢复应用程序的运行：

```
[USB::com.example.app]-> %resume
```

现在，当应用程序显示 `Toast` 消息时，我们就能在 Frida 的控制台中看到相应的日志了。

## 6. 总结

本教程介绍了 Frida 的基本概念、安装方法和使用流程。通过一个简单的例子，我们学习了如何编写和运行 Frida 脚本来 Hook 安卓应用程序。Frida 的功能远不止于此，在后续的教程中，我们将深入学习更多高级技巧，探索 Frida 在逆向工程和安全分析中的应用。