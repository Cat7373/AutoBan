# AutoBan
根据规则自动分析日志文件，并 ban 符合条件的 IP 的小脚本

# 使用方式
1. 确保已卸载`iptables`和已安装`nftables`
1. 执行`ln -s <app1 的日志文件所在目录> log/app1`创建 app1 的日志目录的软连接
1. 执行`ln -s <app2 的日志文件所在目录> log/app2`创建 app2 的日志目录的软连接
1. 执行`ln -s <app3 的日志文件所在目录> log/app3`创建 app3 的日志目录的软连接
1. crontab 添加任务：`0 */6 * * * <脚本所在路径>/run.sh`

# 添加 App
1. 编辑`conf.py`，在`logs`中按照自带的两个`app`的规则添加即可
