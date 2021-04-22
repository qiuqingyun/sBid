#pragma once
#include "../2paraGen/paraGen.h"
#include "../2cipherGen/cipherGen.h"
#include "../2compare/compare.h"
#include "../2shuffle/shuffle.h"
#include "../2decrypt/decrypt.h"
extern G_q G;               // group used for the Pedersen commitment
extern G_q H;               // group used for the the encryption
extern ElGamal El;         // The class for encryption and decryption
extern Network net;
class SBid {
private:
	ifstream ist;
	ofstream ost;
	array<string, 2> codes;//自己和对方的编号，第一个是自己的，第二个是对方的
	string codeBig, codeSmall;
	string pkFileName;
	string coCode;
	array<ZZ, 32> plaintext;//竞价二进制明文
	array<Cipher_elg, 32> ciphertext;    //密文
	array<ZZ, 32> ran_1;//加密的随机数
	array<Cipher_elg, 32> cipherAns;	 //经过两轮混淆的密文
	array<ZZ, 32> dk_1;    //自己的解密份额
	array<ZZ, 32> dk_2;  //对方的解密份额]
	CipherGen* cipherGen;
	ZZ ranZero;
	string ans[2] = { "FAIL","PASS" };
	bool bigMe;
	ZZ mod;
	ZZ ord;
	ZZ gen_h;
	ZZ gen_g;
	ZZ sk, pk;
	int plaintext_int;
	int cipherNum = 32;
	int pBits = 100;
	int qBits = 90;

	//读取群的参数并生成群
	void readParameters();
	//设置初始化ElGamal
	void creatElGamal();
	//加密并生成证明
	void ciphertextOp();
	//验证加密
	void ciphertextVerify();
	//比较并生成证明
	void compareOp();
	//验证比较
	void compareVerify();
	//混淆并生成证明
	void shuffleOp();
	//验证混淆
	void shuffleVerify();
	//解密并生成证明
	void decryptOp();
	//验证解密
	void decryptVerify();

public:
	//生成参数
	void parametersGen();
	//竞拍准备操作
	void prepare(array<int, 2> codes_in);
	//开始竞标
	void bid();
	//验证
	void verify();
};