Web 路径扫描
---

## Usage
_参数说明__

* __-u__ : 紧跟一个链接,可以带路径.
* __--urllist__: 跟着一个url列表文件
* __--pathlist__: 跟着字典文件路径 
* __-v__: 实时显示结果信息
* __-o__: 将结果保存到文件中
* __--thread__ : 指定线程数量,默认是 10
```
# python3 webDirScan.py -u http://example.com/abc/ --pathlist dict.txt -v
# python3 webDirScan.py --urllist /example/urllist.txt --pathlist dict.txt -v --thread 20
```

## Feture

* 支持多线程扫描
* 支持递归扫描,扫描到的路径将会加入到队列中继续扫描
* 支持自定义扫描路径