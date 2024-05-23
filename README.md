**Introduction**

```
Hidedump:a lsassdump tools that may bypass EDR
achieve：hook WriteAll+duplication
```



**Use**

```
hidedump.exe [opt] filename
opt==1:save the Encrypted dumpfile
opt==2:Decrypt the dumpfile and save the decrypted file as sec.dump

example
hidedump.exe 1 tmp.bin
hidedump.exe 2 tmp.bin
```

![1](1.png)



**More information**

```
https://mp.weixin.qq.com/s?__biz=MzkyNTUyNDMyOA==&mid=2247487133&idx=1&sn=814bb99d366f7db1d19c6ab8d72731cb&chksm=c1c4069af6b38f8c767ee8b499680de41ab2ce407eb1283b360b61960ba3c30b263c246e91ec#rd
```



**tip**

The project is no longer update for bypass, only to provide you with ideas
