#!/bin/sh
# 启动 sing-box，由 sing-box 监听云平台唯一端口
exec ./sing-box run -c config.json
