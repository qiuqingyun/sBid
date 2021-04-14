#pragma once
#include "../2shuffle/shuffle.h"
#include "../2paraGen/paraGen.h"
extern G_q G;               // group used for the Pedersen commitment
extern G_q H;               // group used for the the encryption
extern ElGamal El;         // The class for encryption and decryption
//A 00111000100001101100100001110110 948357238
//B 00111000100101101100100001110110 949405814
class SBid {
private:
	ifstream ist;
	ofstream ost;
	array<string, 2> codes;//自己和对方的编号，第一个是自己的，第二个是对方的
	string pkFileName;
	string coCode;
	bitset<32> plaintext;//竞价二进制明文
	array<Cipher_elg, 32> ciphertext;    //原始输入的密文
	ZZ mod;
	ZZ ord;
	ZZ gen_h;
	ZZ gen_g;
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
				cout << "Can't creat " << fileName << endl;
				exit(1);
			}
			ost << El.get_pk_1() << endl;
			ost.close();
			fileName = "sk" + codes[0] + ".txt";
			ost.open(fileName, ios::out);
			if (!ost)
			{
				cout << "Can't creat " << fileName << endl;
				exit(1);
			}
			ost << El.get_sk() << endl;
			ost.close();
		}
		else
		{//读取公私钥
			ZZ sk, pk;
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
			cout << "Can't creat " << fileName << endl;
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
			cout << "Can't creat " << fileName << endl;
			exit(1);
		}
		for (int i = 0; i < cipherNum; i++)
		{
			ZZ m;
			ZZ r = RandomBnd(ord);						//随机数r，也被称作临时密钥
			conv(m, plaintext[i]);						//明文m
			m = PowerMod(H.get_g().get_val(), m, mod);  //g^m
			//cout << m <<" | "<< H.get_g().get_val()<< endl;
			Cipher_elg temp = El.encrypt(m, r);			//得到(u,v)密文组，u = h^r，v = g^m×y^r，y为公钥
			ciphertext[i] = temp;
			ost << temp << endl;
		}
		ost.close();
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
		readParameters();
		creatElGamal();
		readPlaintext();
		createCipher();
	}
	//TODO:比较

	//混淆
	void shuffleOp() {
		Shuffle prover(coCode);
		prover.creatProver();
		prover.shuffle();
		prover.prove();
		
	}
	void shuffleOp2() {
		//test
		Shuffle verifier(coCode);
		verifier.creatVerifier();
		verifier.verify();
	}

	//TODO:解密
};