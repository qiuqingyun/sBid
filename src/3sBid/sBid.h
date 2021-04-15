#pragma once
#include "../2shuffle/shuffle.h"
#include "../2paraGen/paraGen.h"
extern G_q G;               // group used for the Pedersen commitment
extern G_q H;               // group used for the the encryption
extern ElGamal El;         // The class for encryption and decryption
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
	bitset<32> plaintext;//竞价二进制明文
	array<Cipher_elg, 32> ciphertext;    //密文
	array<Cipher_elg, 32> ciphertext_2;  //对方的密文
	array<Cipher_elg, 32> cipherAns;	 //经过两轮混淆的密文
	array<Cipher_elg, 33> Wj;
	array<Cipher_elg, 32> compareResults;//比较结果密文
	array<ZZ, 32> dk_1;    //自己的解密份额
	array<ZZ, 32> dk_2;  //对方的解密份额
	array<ZZ, 32> ans;    //总解密份额
	ZZ mod;
	ZZ ord;
	ZZ gen_h;
	ZZ gen_g;
	ZZ sk, pk;
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
		//TODO:将生成的公钥传递给对方
		//生成主公钥
		fileName = "pk" + codes[1] + ".txt";
		ist.open(fileName, ios::in);
		if (!ist)
		{
			cout << "Can't open " << fileName << endl;
			exit(1);
		}
		string pk_2_str;
		ist >> pk_2_str;
		ist.close();
		El.keyGen(pk_2_str);
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
	//读取明文
	void readPlaintext() {
		string fileName = "plaintext" + codes[0] + ".txt";
		ist.open(fileName, ios::in);
		if (!ist) {
			cout << "Can't open " << fileName << endl;
			exit(1);
		}
		ist >> plaintext;
		ist.close();
	}
	//生成密文
	void createCipher() {
		string fileName = "ciphertext" + codes[0] + ".txt";
		ost.open(fileName, ios::out);
		if (!ost) {
			cout << "Can't create " << fileName << endl;
			exit(1);
		}
		for (int i = cipherNum - 1; i >= 0; i--)
		{//逆序读入
			ZZ r = RandomBnd(ord);							    //随机数r，也被称作临时密钥
			Cipher_elg temp = El.encrypt_g(ZZ(plaintext[i]), r);//得到(u,v)密文组，u = h^r，v = g^m×y^r，y为公钥
			ciphertext[cipherNum - i - 1] = temp;			    //顺序读入
			ost << temp << endl;								//输出密文
		}
		ost.close();
	}
	//读取对方的密文
	void readCipher() {
		string fileName = "ciphertext" + codes[1] + ".txt";
		ist.open(fileName, ios::in);
		if (!ist) {
			cout << "Can't open " << fileName << endl;
			exit(1);
		}
		for (int i = 0; i < cipherNum; i++) {
			ist >> ciphertext_2[i];
		}
		ist.close();
	}
	//读取经过两轮混淆的密文
	void readCipherShuffled() {
		codeBig = (codes[0] > codes[1]) ? codes[0] : codes[1];
		codeSmall = (codes[0] < codes[1]) ? codes[0] : codes[1];
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
		for (int i = 0; i < cipherNum; i++) {
			ZZ u = cipherAns[i].get_u();
			dk_1[i] = PowerMod(u, sk, mod);
			ost << dk_1[i] << endl;
		}
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
	~SBid() {

	}
	//生成参数
	void parametersGen() {
		ParaGen paraGen;
		paraGen.parametersGen(pBits, qBits);
	}
	//竞拍准备操作
	void prepare(array<int, 2> codes_in) {
		codes[0] = to_string(codes_in[0]);//自己的编号
		codes[1] = to_string(codes_in[1]);//对方的编号
		readParameters();
		creatElGamal();
		readPlaintext();
		createCipher();
	}
	void bid() {
		compare();
		shuffleOp();
		prepareDecrypt();
		decrypt();
	}
	//从高到低逐位比较
	void compare() {
		readCipher();
		clock_t tstart = clock();
		string fileName = "cipherCR" + codes[0] + ".txt";
		ost.open(fileName, ios::out);
		if (!ost)
		{
			cout << "Can't create " << fileName << endl;
			exit(1);
		}
		Cipher_elg a, b, aPb, aTb, twoTaTb, minus2TaTb, b_minus, aMbM1;
		ZZ r = RandomBnd(ord);
		Cipher_elg ONE = El.encrypt_g(ZZ(1), r);//g^0
		r = RandomBnd(ord);
		Wj[0] = El.encrypt_g(ZZ(0), r);//g^0
		Cipher_elg Wj_sum = Wj[0];
		for (int i = 0; i < cipherNum; i++) {
			a = ciphertext[i];
			b = ciphertext_2[i];
			aPb = a * b;//a+b
			aTb = Cipher_elg::expo(b, ZZ(plaintext[cipherNum - i - 1]));//a*b 明文参与
			twoTaTb = Cipher_elg::expo(aTb, ZZ(2));//2*a*b
			minus2TaTb = Cipher_elg::inverse(twoTaTb);//-2*a*b
			Wj[i + 1] = aPb * minus2TaTb;//a+b-2*a*b
			Wj_sum = Wj_sum * Wj[i];
			b_minus = Cipher_elg::inverse(b);//-b
			aMbM1 = a * b_minus * ONE;//a-b+1
			compareResults[i] = aMbM1 * Wj_sum;
			ost << compareResults[i] << endl;
		}
		ost.close();
		clock_t  tstop = clock();
		double ttime = (tstop - tstart) / (double)CLOCKS_PER_SEC * 1000;
		cout << "[" << codes[0] << "] - " << "compare " << ttime << " ms" << endl;
	}
	//混淆并生成证明
	void shuffleOp() {
		Shuffle prover(codes, coCode);
		prover.creatProver();
		prover.shuffle();
		prover.prove();

	}
	//验证混淆
	void shuffleVerify() {
		Shuffle verifier(codes, coCode);
		verifier.creatVerifier();
		verifier.verify();
	}
	//解密准备
	void prepareDecrypt() {
		readCipherShuffled();
		createDk();
	}
	//解密并输出结果,0为(小号)等于(大号)，1为(小号)小于(大号)，2为(小号)大于(大号)
	void decrypt() {
		readDk();
		ZZ dk, dk_inv;
		int result;
		for (int i = 0; i < cipherNum; i++)
		{
			dk = MulMod(dk_1[i], dk_2[i], mod);//加法同态
			dk_inv = InvMod(dk, mod);//取逆
			ans[i] = El.get_m(MulMod(cipherAns[i].get_v(), dk_inv, mod));//解密
			if (ans[i] == 0)
			{//大号胜
				cout << "[" << codes[0] << "] - " << "No." << codeBig << " WIN" << endl;
				return;
			}
			else if (ans[i] == 1)
				continue;
			else
			{//小号胜
				cout << "[" << codes[0] << "] - " << "No." << codeSmall << " WIN" << endl;
				return;
			}
		}
		cout << "[" << codes[0] << "] - " << "DRAW" << endl;
	}
};