# readme

#### Point

200

#### 参考链接

https://github.com/ctfs/write-ups-2015/tree/master/32c3-ctf-2015/pwn/readme-200

#### 亮点

- LIBC_FATAL_STDERR_=1

#### 考点

- 栈溢出
- SSPI

#### 步骤

- 利用栈溢出覆盖__libc_argv[0]为`0x400d20`, 并且覆盖之后的一个环境变量指针为`0x00600d20 `
- 设置环境变量`LIBC_FATAL_STDERR_=1`，触发SSPI，并将服务器的错误信息显示到客户端终端上