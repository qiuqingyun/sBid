#pragma once
#include "../2paraGen/paraGen.h"
#include "../2cipherGen/cipherGen.h"
#include "../2compare/compare.h"
#include "../2shuffle/shuffle.h"
extern G_q G;               // group used for the Pedersen commitment
extern G_q H;               // group used for the the encryption
extern ElGamal El;         // The class for encryption and decryption
extern Network net;
//A 00111000100001101100100001110110 948357238 第11,13位不同
//B 00111000100100101100100001110110 949143670
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
	void readParameters() {
		string fileName = "parameters.txt";
		ist.open(fileName, ios::in);
		if (!ist)
		{
			cout << "Can't open " << fileName << endl;
			exit(1);
		}
		ist >> mod;
		ist >> ord;
		ist >> gen_h;
		ist >> gen_g;
		ist.close();
		H = G_q(gen_h, ord, mod); //生成元h 阶数q 模数p
		G = G_q(gen_h, ord, mod);
		H.set_g(gen_g);
		G.set_g(gen_g);
	}
	//设置初始化ElGamal
	void creatElGamal() {
		El.set_group(H);
		string fileName = "pk" + codes[0] + ".txt";
		ist.open(fileName, ios::in);
		if (!ist)
		{//生成公私钥
			cout << fileName << " does not exist, a new key will be generated" << endl;
			ZZ x = RandomBnd(H.get_ord());//随机生成私钥
			El.set_sk(x);//生成公钥
			//输出公私钥
			ost.open(fileName, ios::out);
			if (!ost)
			{
				cout << "Can't create " << fileName << endl;
				exit(1);
			}
			ost << El.get_pk_1() << endl;
			ost.close();
			fileName = "sk" + codes[0] + ".txt";
			ost.open(fileName, ios::out);
			if (!ost)
			{
				cout << "Can't create " << fileName << endl;
				exit(1);
			}
			ost << El.get_sk() << endl;
			ost.close();
		}
		else
		{//读取公私钥
			string sk_str, pk_str;
			getline(ist, pk_str);
			conv(pk, pk_str.c_str());
			ist.close();
			fileName = "sk" + codes[0] + ".txt";
			ist.open(fileName, ios::in);
			if (!ist)
			{
				cout << "Can't open " << fileName << endl;
				exit(1);
			}
			getline(ist, sk_str);
			conv(sk, sk_str.c_str());
			El.set_key(sk, pk);
			ist.close();
		}
		//将生成的公钥传递给对方
		string pk_1, pk_2;
		stringstream ss;
		ss << El.get_pk_1();
		ss >> pk_1;
		if (bigMe) {
			net.mSend(pk_1);
			net.mReceive(pk_2);
		}
		else {
			net.mReceive(pk_2);
			net.mSend(pk_1);
		}
		fileName = "pk" + codes[1] + ".txt";
		ost.open(fileName, ios::out);
		if (!ost)
		{
			cout << "Can't create " << fileName << endl;
			exit(1);
		}
		ost << pk_2 << endl;
		ost.close();
		//生成主公钥
		El.keyGen(pk_2);
		//输出主公钥
		int suffixFlag = (codes[0] < codes[1]);
		coCode = codes[!suffixFlag] + "-" + codes[suffixFlag];
		fileName = "pk" + coCode + ".txt";
		pkFileName = fileName;
		ost.open(fileName, ios::out);
		if (!ist)
		{
			cout << "Can't create " << fileName << endl;
			exit(1);
		}
		ost << El.get_pk() << endl;
		ost.close();
	}

	//加密并生成证明
	void ciphertextOp() {
		CipherGen* cipherGen = new CipherGen(codes, bigMe);
		cipherGen->gen(ciphertext, plaintext, ranZero, ran_1);//生成密文( h^r , g^m × y^r )
		cipherGen->prove();//生成密文证明
	}
	//验证加密
	void ciphertextVerify() {
		CipherGen* cipherVerify = new CipherGen(codes, bigMe);
		bool flag = cipherVerify->verify();
		cout << "[" << codes[0] << "] - " << "ciphertext results: " << ans[flag] << endl;
	}
	//比较并生成证明
	void compareOp() {
		Compare compare(codes, plaintext, ciphertext, ran_1, ranZero, bigMe);
		compare.compare();
		compare.prove();
	}
	//验证比较
	void compareVerify() {
		Compare compare(codes, ciphertext, bigMe);
		bool flag = compare.verify();
		cout << "[" << codes[0] << "] - " << "compare results: " << ans[flag] << endl;
	}
	//混淆并生成证明
	void shuffleOp() {
		Shuffle prover(codes, coCode);
		prover.creatProver(bigMe);
		prover.shuffle();
		prover.prove();
	}
	//验证混淆
	void shuffleVerify() {
		Shuffle verifier(codes, coCode);
		verifier.creatVerifier();
		bool flag = verifier.verify();
		cout << "[" << codes[0] << "] - " << "shuffle results: " << ans[flag] << endl;
	}
	//读取经过两轮混淆的密文
	void readCipherShuffled() {
		string fileName = "cipherSR" + codeBig + ".txt";
		ist.open(fileName, ios::in);
		if (!ist) {
			cout << "Can't open " << fileName << endl;
			exit(1);
		}
		for (int i = 0; i < cipherNum; i++) {
			ist >> cipherAns[i];
		}
		ist.close();
	}
	//创建解密份额
	void createDk() {
		string fileName = "dk" + codes[0] + ".txt";
		ost.open(fileName, ios::out);
		if (!ost) {
			cout << "Can't create " << fileName << endl;
			exit(1);
		}
		stringstream ss;
		for (int i = 0; i < cipherNum; i++) {
			ZZ u = cipherAns[i].get_u();
			dk_1[i] = PowerMod(u, sk, mod);
			ost << dk_1[i] << endl;
			ss << dk_1[i] << ";";
		}
		ost.close();

		string cipher_1, cipher_2;
		ss >> cipher_1;
		if (bigMe) {//大号先接收再发送
			net.mReceive(cipher_2);
			net.mSend(cipher_1);
		}
		else {//小号先发送再接收
			net.mSend(cipher_1);
			net.mReceive(cipher_2);
		}
		vector<string> ciphertext_2_str;
		net.deserialization(cipher_2, ciphertext_2_str);
		//保存
		fileName = "dk" + codes[1] + ".txt";
		ost.open(fileName, ios::out);
		if (!ost)
		{
			cout << "Can't create " << fileName << endl;
			exit(1);
		}
		for (int i = 0; i < cipherNum; i++)
			ost << ciphertext_2_str[i] << endl;
		ost.close();
	}
	//读取对方的解密份额
	void readDk() {
		string fileName = "dk" + codes[1] + ".txt";
		ist.open(fileName, ios::in);
		if (!ist) {
			cout << "Can't open " << fileName << endl;
			exit(1);
		}
		for (int i = 0; i < cipherNum; i++) {
			ist >> dk_2[i];
		}
		ist.close();
	}


public:
	//生成参数
	void parametersGen() {
		ParaGen paraGen;
		paraGen.parametersGen(pBits, qBits);
	}
	//竞拍准备操作
	void prepare(array<int, 2> codes_in) {
		codes[0] = to_string(codes_in[0]);//自己的编号
		codes[1] = to_string(codes_in[1]);//对方的编号
		codeBig = (stoi(codes[0]) > stoi(codes[1])) ? codes[0] : codes[1];
		codeSmall = (stoi(codes[0]) < stoi(codes[1])) ? codes[0] : codes[1];
		bigMe = codes_in[0] > codes_in[1];
		int port = 20200;
		if (bigMe)
			port += codes_in[0];
		else
			port += codes_in[1];
		net.init(codes[0], bigMe, port);
		readParameters();
		creatElGamal();
		ciphertextOp();
	}
	//开始竞标
	void bid() {
		compareOp();
		shuffleOp();
		decrypt();
	}
	//解密并输出结果,0为(小号)等于(大号)，1为(小号)小于(大号)，2为(小号)大于(大号)
	void decrypt() {
		readCipherShuffled();
		createDk();
		readDk();
		//ZZ dk, dk_inv;
		int result = 0, flag = 0;
		for (int i = 0; i < cipherNum; i++)
		{
			ZZ dk = MulMod(dk_1[i], dk_2[i], mod);//加法同态
			ZZ dk_inv = InvMod(dk, mod);//取逆
			ZZ ans = El.get_m(MulMod(cipherAns[i].get_v(), dk_inv, mod));//解密
			if (ans == 0)
			{//大号胜
				cout << "[" << codes[0] << "] - " << "No." << codeSmall << " WIN" << endl;
				return;
			}
			else if (ans == 1)
			{//平局
				flag++;
			}
		}
		if (flag == cipherNum)
			cout << "[" << codes[0] << "] - " << "DRAW" << endl;
		else
			cout << "[" << codes[0] << "] - " << "No." << codeBig << " WIN" << endl;
	}
	//验证
	void verify() {
		cout << "[" << codes[0] << "] - " << "=====Verify=====" << endl;
		ciphertextVerify();
		compareVerify();
		shuffleVerify();

		cout << "[" << codes[0] << "] - " << "======OVER======" << endl;
	}

};