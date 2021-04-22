# 基于区块链上的隐私竞拍系统

## 项目详细描述
多个竞拍者参与投标，保证投标金额隐私，经过比较选出最大或最小竞价，允许泄露各方投标的大小关系；每个竞拍者均可作为验证方，验证竞拍过程

## 隐私要求
* 投标密文格式及加密正确性
* 比较过程正确性
* 混淆正确性
* 解密正确性

## 程序功能
* 参数生成：生成用于整个竞拍流程的加密参数，生成文件`parameters.txt`
* 竞拍功能：读取参与者的竞拍金额，与另一竞拍参与者的竞拍金额进行加密对比，并生成隐私要求的证明，最后输出比较结果
* 验证功能：验证某个竞拍参与者的证明，并输出验证结果

## 使用方法
* 命令格式: `./sBid <para1> <para2> <para3> <para4>`
* 参数生成：`<para1>`置0，无需`<para2>`,`<para3>`,`<para4>`参数
* 竞拍功能：`<para1>`为竞拍参与者的唯一编号，`<para2>`为另一竞拍参与者的唯一编号，`<para3>`为当前竞拍轮数，无需`<para4>`参数
* 验证功能：`<para1>`置0，`<para2>`为将要验证的竞拍参与者的唯一编号，`<para3>`为另一竞拍参与者的唯一编号，`<para4>`为将要验证的竞拍轮数

## 必要文件
* 参数生成：无
* 竞拍功能：
    * 第一轮
        * 加密参数文件`parameters.txt`
        * 十进制明文金额数文件`plaintext_int${code}.txt`或二进制明文金额数文件`plaintext${code}.txt`
        * 注：
            1. `${code}`为竞拍参与者的唯一编号，
            2. 程序优先读取二进制明文金额数文件，不存在二进制明文金额数文件时才会读取十进制明文金额数文件中的金额，且会生成二进制明文金额数文件
    * 第二轮及之后轮次
        * 加密参数文件`parameters.txt`
        * 十进制明文金额数文件`plaintext_int${code}.txt`或二进制明文金额数文件`plaintext${code}.txt`
        * 公钥文件`pk${code}.txt`
        * 私钥文件`sk${code}.txt`
* 验证功能：
    * 密文文件：
        * 被验方的加密密文文件`ciphertext${code}.txt`
        * 另一方的加密密文文件`ciphertext${code_opponent}.txt`
        * 比较结果文件`cipherCR${code_big}.txt`
        * 被验方的混淆结果文件`cipherSR${code}.txt`
        * 另一方的混淆结果文件`cipherSR${code_opponent}.txt`
        * 注：
            1. `${code}`为竞拍参与者的唯一编号
            2. `${code_opponent}`为另一竞拍参与者的唯一编号
            3. `${code_big}`为两个竞拍参与者的唯一编号中值更大的唯一编号
    * 证明文件：
        * 加密正确性证明文件`proveCipher${code}.txt`
        * 比较正确性证明文件`proveCompare${code}.txt`
        * 混淆正确性证明文件`proveCompare${code}.txt`
        * 解密正确性证明文件`proveCompare${code}.txt`