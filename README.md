# 常见运维问题列表

移动
adb命令列表

工控
工控协议名与公司名对照表
根据流量判断流量类型

windows
主机信息搜集，各个系统版本
脚本
systeminfo
net指令集
netstat指令集
windows日志

linux
日志分析

缺少windows日志分析工具
加密解密脚本python

ps脚本执行权限
命令执行权限
要解决这类问题，通常的做法是，用管理员权限启动PS命令行，将执行权限修改为RemoteSigned或者Unrestricted：
Set-ExecutionPolicy RemoteSigned

Get-History | Format-List -Property *

2、CMD查看命令记录
方法1、使用F7快捷键
 方法2、使用上下键，或者F3,F8查询
 方法3、使用DOSKEY/HISTORY
 
 
3、powershell查看历史执行记录
 
iptable各种命令
 
tcpdump指令集

比如pptp协议在wireshark中的缩写和术语


遍历注册表的工具，打印相关目录
查看安全日志
net相关指令
脚本合并文件相关命令
clickhouse命令
启动项在注册表的路径
流量拼成文件
各种web后台弱口令
微信号怎么查
常见魔数头
ios各种路径
U盘在注册表中的路径
注册表启动项的路径
Windows下使用ping命令扫描C段：
for /l %i in (1,1,255) do @ping 192.168.64.%i -w 1 -n 1|find /i "ttl="
Linux 下使用ping命令扫描C段：
for k in $( seq 1 255);do ping -c 1 192.168.99.$k|grep "ttl"|awk -F "[ :]+" '{print $4}'; done
Iptables转发规则命令表和解析
iptable -t nat -L （转发规则）
windows host文件路径：C:\Windows\System32\drivers\etc
Powershell编码
蚁剑、冰蝎特征区别
自带安卓工具
serachmyfile 按时间搜索工具
wireshark使用文件

计算机基本信息
/proc/version
/proc/cpuinfo
/proc/meminfo
/lib/ld*

tcpdump常用命令
python服务器
python -m SimpleHTTPServer 9000
Python3 -m http.server 8080

powershell ie首次不可用
配置ie选项-》安全-〉本地internet-》站点-〉高级-》添加about:security_powershell.exe
Windows安装时间注册表项：HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\InstallDate
wmic os get installdate
网卡在注册表 信息：\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\ \HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\Tcpip\Parameters\Interfaces\


手机姿势：
获取imei号：通过手机设置about emulated device选项来查看
或者：通过adb shell service call iphonesubinfo 1获取

获取apk在/data/app/
获取apk数据在/data/data
安卓短信数据库提取在/data/data/com.android.providers.telephoney/databases/
获取via浏览器数据在/data/data/浏览器名

常见加密方式
AES、DES、3DES
RSA、DSA、ECC
MD5、SHA1、HMAC

Java写安卓解密项目，在main里需要全部static
linux改密码：
Ro改为RW single init=/bin/bash
centos6直接加1

常见文件头
S7和modbus以及modbus/tcp的指令集







