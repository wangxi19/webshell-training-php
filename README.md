# 集成环境 引用自

`https://www.github.com/c0ny1/upload-labs`

# Resources references

`https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload`

# Some common bypass techniques in php

## 1.文件名截断方式

%00    0x00, 如 ".php%00.jpg" ".php\x00.jpg"

## 2.不流行的后缀名 以及大小写欺骗

".phpt",".php5",".php4",".php3",".php2",".html",".htm",".phtml",".pht",".pHp",".pHp5",".pHp4",".pHp3",".pHp2" 等等

## 3.空白符欺骗, 末尾加.

".php " ".php." 等等. 操作系统保存文件的时候, 会自动清除末尾的.

## 4.上传 .htaccess 文件，修改增加可执行文件后缀

".htaccess files provide a way to make configuration changes on a per-directory basis."
You can read more here : https://httpd.apache.org/docs/2.4/en/howto/htaccess.html

```
.htaccess
# Say all file with extension .php16 will execute php
AddType application/x-httpd-php .php16         
# Active specific encoding (you will see why after :D)																									 
php_value zend.multibyte 1                    
# Detect if the file have unicode content
php_value zend.detect_unicode 1                            
# Display php errors|
php_value display_errors 1
```

### 4.2上传 .htaccess 文件 突破 exif_imagetype() 限制

The first trick here is to find a way to bypass image checker. How would it be possible to send our .htaccess to pass through exif_imagetype() protection. 
The first think is to read the php doc to understand the function : 
http://php.net/manual/en/function.exif-imagetype.php

16	IMAGETYPE_XBM

Ok but what is a xbm file ? Look at wikipedia my dear : https://en.wikipedia.org/wiki/X_BitMap
“In computer graphics, the X Window System used X BitMap (XBM), a plain text binary image format, for storing cursor and icon bitmaps used in the X GUI."
And there is an example :
```
#define test_width 16
#define test_height 7
static char test_bits[] = {
0x13, 0x00, 0x15, 0x00, 0x93, 0xcd, 0x55, 0xa5, 0x93, 0xc5, 0x00, 0x80,
0x00, 0x60 };
```

#### 修改 .htaccess 文件内容为

```
.htaccess
#define width 1337                          # Define the width wanted by the code (and say we are a legit xbitmap file lol)
#define height 1337                         # Define the height								     
																									 
# Say all file with extension .php16 will execute php
AddType application/x-httpd-php .php16         
# Active specific encoding (you will see why after :D)																									 
php_value zend.multibyte 1                    
# Detect if the file have unicode content
php_value zend.detect_unicode 1                            
# Display php errors|
php_value display_errors 1
```                                                      

### 4.3突破上传 .htaccess 文件前缀名为空限制 

更改为 ..htaccess

## 5.Bypass the anti-PHP protection

修改php文件编码 从utf8 变为utf16

## 6.Idiotic Regex filter bypass

using double extension like shell.jpg.php

## 7.by adding a semi-colon or colon character after the forbidden extension and before the permitted one

in IIS6 and previous version: "webshell.asp;.jpg".  in php: "webshell.php:.jpg"

# Exam-Solution

### 1. 文件后缀在客户端js验证, 

先把.php文件改为.jpg文件, 再用burpsuite 截断请求后修改文件后缀为.php文件改为

### 2. 服务端验证的multipart/form-data 中的Content-Type, 必须为 image/jpg image/png image/gif, 

这个简单, 文件名直接为 .php, 再把请求的Content-Type 改为image/jpg 即可. 或者生成一个图片webshell也可

### 3. 服务端 a. 移除文件末尾的'.' b.提取文件后缀名 c.把文件后缀转化为小写 d.移除后缀名中::$DATA e.去除后缀名的末尾空格, 再黑名单验证是否为 .php .asp .aspx .jsp... 

用burpsuite 截断请求, 把文件后缀名从.jpg 改为 .php3即可

### 4. 黑名单, 可以上传任意除黑名单外的文件

首先随便上传一个shell.php，使用抓包工具(比如:burpsuite)，将文件后缀修改为：shell.php:.jpg
此时，会在upload目录下生成一个名为shell.php的空文件
然后，修改数据包文件名为：shell.<<<，
这里在move_uploaded_file($temp_file, '../../upload/shell.<<<')
类似与正则匹配，匹配到.../../upload/shell.php文件，
然后会将此次上传的文件数据写入到shell.php文件中，这样就成功写入我们的小马了。

when running PHP on windows, the “>”, “<”, and double quote '"' characters respectively convert to “?”, “*”, and “.”
so shell.<<< is converted to shell.***

### 5. 黑名单, 并且随机生成文件名

使用大小写绕过. 如 `webshell.PhTml`

### 6. 黑名单, 并且随机生成文件名

使用空白符绕过. 如 `webshell.php `

### 7. 黑名单

使用缺省的后缀. 如 `webshell.php.`

### 8. 黑名单

使用NTFS ASD的漏洞 绕过. `webshell.php::$data`

### 9. 黑名单

手法同4

### 10. 服务端会替换 'php' 'html' 等关键字为空

利用服务器替换漏洞, 构造如下文件名 `webshell.pphphp`

### 11. 白名单 生成随机文件名 但是上传路径可控

URI 上传路径 利用 %00截断 如 `../upload/aa.php%00`, %00 对应url编码 就是二进制00

### 12

multipart/form-data 中的上传路径 利用 二进制00 截断, 用burpsuite 进行二进制编辑, 在路径 `../upload/aa.php` 后面加个二进制 00

### 13

gif 图片webshell: 在webshell最开始加一行 `GIF89a`
jpg 和 png 则用Windows cmd命令 `copy normal.jpg/b + shell.php/a = webshell.jpg`, normal.jpg 文件不宜过大

### 14

同13

### 15

同13

### 16

上传的图片被重新渲染后保存的. (通过网页GET的图片内容可以发现). 利用工具生成一个经过图片渲染后 还存在webshell脚本的图片

### 17

查看提示, 发现需代码审计. 服务端是先以我们上传的文件名保存, 后再重命名.
使用程序开多个线程不停的上传 `webshell.php`.上传足够快足够多的话, `webshell.php`就能存在更长的时间`骚操作`

### 18

审计源码. 服务端先验证后缀名白名单, 发现 '7Z'存在白名单中. 然后移动文件到我们制定的文件名. 最后重命名文件
解决方法类似17. 利用多线程不停的上传 `webshell.php.7Z`, Apache解析漏洞, 遇到不认识的后缀名, 会向前解析后缀, 就得到 .php。
所以访问 `webshell.php.7Z` 和访问 `webshell.php`  是一样的, 都当成php代码

### 19

类似 12. 在第二个multipart/form-data 中 把文件保存的名字构造为 `webshell.php.jpg` .php和 .jpg 中间插入二进制00 进行截断, 
保存后的文件名就为 webshell.php

### 20 审计源码 发现如果上传的save_name 本身为array的话, 不会再对他进行 . 分割, 保存的文件名为 array[0].array[last]

在multipart/form-data 中把save_name 构造为 array, 再对array[0]的名字使用 00截断
```
------------------------boundary
Content-Disposition: form-data; name="save_name[]"

webshell.php{末尾是二进制00,肉眼不可见}
------------------------boundary
png
```
由于只对array[last]进行了白名单检查, 当保存文件的时候, array[0].array[last] 字符串被 webshell.php 后面的00截断
