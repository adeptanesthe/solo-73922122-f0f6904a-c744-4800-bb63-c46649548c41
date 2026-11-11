# 内置多层示例

`multilayer-demo.tar` 是 `docker save` 格式的单镜像归档，由
`app/sample.py` 在内存中确定性生成（也可重新生成）：

```bash
python3 app/sample.py examples/multilayer-demo.tar
```

它包含 4 个层，覆盖以下合并规则；四层刻意采用全部受支持的编码，并共用同一条分块读取与校验流程：

| 层 | 编码 | 示例内容 |
| --- | --- | --- |
| L1 | 未压缩 tar | `usr/bin/passwd`、`usr/bin/sudo` 为 SUID；`usr/bin/wall` 为 SGID |
| L2 | 拼接 gzip（两个成员，边界落在 tar 头中间） | whiteout 删除低层 `passwd`，同层新增安全版 `passwd`；`sudo` 改为 0755；新增 SUID `ping` |
| L3 | xz | `opt/tools/legacy/` 使用 opaque whiteout；`var/lib/cache/` 从目录被换成 SGID 普通文件 |
| L4 | bzip2 | `usr/local/bin/oldtool` 从普通文件被换成目录，子项 `wrapper` 为 SUID；符号链接不被跟随 |

压缩层会被完整读到压缩流结束并校验结束状态与校验和；拼接的 gzip 成员按同一条解压字节流处理。任一层截断、CRC 错误或在 tar 结束标记后夹带数据，整个扫描都会以 400 失败并注明层号。

最终应报告 5 个文件：2 个 SUID、3 个 SGID。
