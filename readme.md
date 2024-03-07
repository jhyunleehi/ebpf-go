


```
root@Good:~# cat .profile 
export PATH=$PATH:/usr/local/go/bin

root@Good:~# mkdir -p /root/vscode_data
root@Good:~# chmod 777 /root/vscode_data

root@Good:~/go/src/ebpf# cat code.sh
code --no-sandbox --user-data-dir=/root/vscode_dat

```