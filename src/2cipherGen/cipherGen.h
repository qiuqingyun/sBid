#pragma once
#include "../global.h"
#include "../1commitment/commitment.h"
extern G_q G;               // group used for the Pedersen commitment
extern G_q H;               // group used for the the encryption
extern ElGamal El;         // The class for encryption and decryption
extern Network net;

class CipherGen {
private:
	ifstream ist;
	ofstream ost;
	array<string, 2> codes;//自己和对方的编号，第一个是自己的，第二个是对方的
	array<ZZ, 32> plaintext;//竞价二进制明文
	array<Cipher_elg, 32> ciphertext;    //密文
	array<ZZ, 32> ran_1;
	Cipher_elg ciphertextZero;
	ZZ ranZero;
	int plaintext_int;
	int cipherNum = 32;
	bool bigMe;
	ZZ mod;
	ZZ ord;
	Mod_p g;
	Mod_p h;
	Mod_p y;
	SHA256 sha;

	//读取明文
	void readPlaintext() {
		bitset<32> plaintext_inv;
		string fileName = "plaintext" + codes[0] + ".txt";
		ist.open(fileName, ios::in);
		if (!ist) {
			fileName = "plaintext_int" + codes[0] + ".txt";
			ist.open(fileName, ios::in);
			if (!ist) {
				cout << "Can't open " << fileName << endl;
				exit(1);
			}
			ist >> plaintext_int;
			cout << "[" << codes[0] << "] - " << "Amount: " << plaintext_int << endl;
			plaintext_inv = plaintext_int;
			ist.close();
			fileName = "plaintext" + codes[0] + ".txt";
			ost.open(fileName, ios::out);
			if (!ost) {
				cout << "Can't create " << fileName << endl;
				exit(1);
			}
			ost << plaintext_inv << endl;
			ost.close();
		}
		else {
			ist >> plaintext_inv;
			ist.close();
			cout << "[" << codes[0] << "] - " << "Amount: " << plaintext_inv.to_ulong() << endl;
		}
		for (int i = 0; i < cipherNum; i++)
			plaintext[i] = ZZ(plaintext_inv[cipherNum - i - 1]);
	}
	//生成密文并读取对方生成的密文
	void createCipher() {
		string fileName = "ciphertext" + codes[0] + ".txt";
		ost.open(fileName, ios::out);
		if (!ost) {
			cout << "Can't create " << fileName << endl;
			exit(1);
		}
		stringstream ss;
		for (int i = 0; i < cipherNum; i++)
		{
			ran_1[i] = RandomBnd(ord);								 //随机数r，也被称作临时密钥
			Cipher_elg temp = El.encrypt_g(ZZ(plaintext[i]), ran_1[i]);//得到(u,v)密文组，u = h^r，v = g^m×y^r，y为公钥
			ciphertext[i] = temp;									 //顺序读入
			ost << temp << endl;										 //输出密文
			ss << temp << ";";
		}
		//加密0
		ranZero = RandomBnd(ord);					  //随机数r
		ciphertextZero = El.encrypt_g(ZZ(0), ranZero);//得到(h^r,y^r)密文组
		ost << ciphertextZero << endl;							
		ss << ciphertextZero << ";";
		ost.close();
		//读取对方生成的密文
		string cipher;
		if (bigMe) {
			net.mSend(ss.str());
			net.mReceive(cipher);
		}
		else {
			net.mReceive(cipher);
			net.mSend(ss.str());
		}
		vector<string> ciphertext_2_str;
		net.deserialization(cipher, ciphertext_2_str);
		fileName = "ciphertext" + codes[1] + ".txt";
		ost.open(fileName, ios::out);
		if (!ost)
		{
			cout << "Can't create " << fileName << endl;
			exit(1);
		}
		for (int i = 0; i < ciphertext_2_str.size(); i++)
			ost << ciphertext_2_str[i] << endl;
		ost.close();
	}

public:
	CipherGen(array<string, 2> codes, bool bigMe) :codes(codes), bigMe(bigMe) {
		SetSeed(to_ZZ((long)time(0) + (long)clock()));
		y = El.get_pk();
		mod = El.get_group().get_mod();
		ord = El.get_group().get_ord();
		g = El.get_group().get_g();
		h = El.get_group().get_gen();
	}
	//生成密文( h^r , g^m × y^r )
	void gen(array<Cipher_elg, 32>& Ciphertext, array<ZZ, 32>& Plaintext, ZZ& RanZero, array<ZZ, 32> &Ran) {
		readPlaintext();
		createCipher();
		//createZeroCipher();
		Ciphertext = ciphertext;
		Plaintext = plaintext;
		RanZero = ranZero;
		Ran = ran_1;
		//return ciphertext;
	}
	//生成证明
	void prove() {
		clock_t tstart = clock();
		string fileName = "proveCipher" + codes[0] + ".txt";
		Commitment com(codes, plaintext, ciphertext, ran_1, bigMe, fileName);
		com.cipherCommit();

		clock_t tstop = clock();
		double ttime = (tstop - tstart) / (double)CLOCKS_PER_SEC * 1000;
		cout << "[" << codes[0] << "] - " << "prove ciphertext " << ttime << " ms" << endl;
	}
	//验证证明
	bool verify() {
		clock_t tstart = clock();
		bool flag = true;
		//读入密文
		string fileName = "ciphertext" + codes[0] + ".txt";
		ist.open(fileName, ios::in);
		if (!ist) {
			cout << "Can't open " << fileName << endl;
			exit(1);
		}
		for (int i = 0; i < cipherNum; i++) {
			ist >> ciphertext[i];
		}
		ist.close();
		//读入证明
		fileName = "proveCipher" + codes[0] + ".txt";
		Commitment com(codes, ciphertext, bigMe, fileName);
		flag &= com.cipherCheck();

		clock_t tstop = clock();
		double ttime = (tstop - tstart) / (double)CLOCKS_PER_SEC * 1000;
		cout << "[" << codes[0] << "] - " << "verify ciphertext " << ttime << " ms" << endl;
		return flag;
	}
};