# iptables-AutoBan
根据规则自动分析日志文件，并 ban 符合条件的 IP 的小脚本

# 使用方式
1. 执行`ln -s <日志文件所在目录> log`创建日志目录的软连接
1. crontab 添加任务：`*/10 * * * * <脚本所在路径>/run.sh`
