#pragma once
#include "../global.h"
extern ElGamal El;         // The class for encryption and decryption
extern Network net;

class Commitment {
private:
	ifstream ist;
	ofstream ost;
	array<string, 2> codes;//自己和对方的编号，第一个是自己的，第二个是对方的
	string round;//当前轮数
	array<ZZ, 32> plaintext;//竞价二进制明文
	ZZ plaintext_s;
	array<ZZ, 32> plaintext_1;//自己的二进制明文
	array<ZZ, 32> plaintext_round2;
	array<Cipher_elg, 32> ciphertext;	   //参与commit的密文
	array<Cipher_elg, 32> ciphertext_1;    //自己的密文
	array<Cipher_elg, 32> ciphertext_2;    //对方的密文或上一轮自己的密文
	array<Cipher_elg, 32> ciphertext_round2;
	array<Cipher_elg, 32> ciphertext_round3;
	array<ZZ, 32> ran;
	array<ZZ, 32> ran_1;
	array<ZZ, 32> ran_2;//上一轮的随机数
	array<ZZ, 32> ran_round2;
	array<Mod_p, 32> base1;
	array<Mod_p, 32> base2;
	Cipher_elg cipherZero_1;//自己的0加密密文
	Cipher_elg cipherZero_2;//对方的0加密密文
	array<ZZ, 32> c2;
	array<ZZ, 32> dk;
	ZZ ranZero;
	int cipherNum = 32;
	ZZ mod;
	ZZ ord;
	Mod_p g;
	Mod_p h;
	Mod_p y;//主公钥
	Mod_p y_1;//上一轮的主公钥
	Mod_p y1;//个人公钥
	Mod_p x1;//私钥
	SHA256 sha;
	bool bigMe;
	string fileName;
	//sigma协议承诺
	void sigma();
	//sigma协议检验
	bool checkSigma();

	//表示证明
	void indicates();
	//表示证明检验
	bool indicatesCheck();

	//离散对数证明
	void discreteLogarithm(int flag);
	//离散对数证明检验
	bool discreteLogarithmCheck(int flag);

	//线性等式证明
	void linearEquation(int flag);
	//线性等式证明检验
	bool linearEquationCheck(int flag);

	//等式证明
	void equation();
	//线性等式证明检验
	bool equationCheck();

	//比较正确性前置证明
	void compareCommit0();
	//比较正确性前置证明验证
	bool compareCommitCheck0();

	//比较正确性第一轮证明
	void compareCommit1();
	//比较正确性第一轮证明验证
	bool compareCommitCheck1();

	//比较正确性第二轮证明
	void compareCommit2();
	//比较正确性第二轮证明验证
	bool compareCommitCheck2();

	//比较正确性第三轮证明
	void compareCommit3();
	//比较正确性第三轮证明验证
	bool compareCommitCheck3();

	//比较正确性第四轮证明
	void compareCommit4();
	//比较正确性第四轮证明验证
	bool compareCommitCheck4();

	//比较正确性第五轮证明
	void compareCommit5();
	//比较正确性第五轮证明验证
	bool compareCommitCheck5();


public:
	//密文一致性证明
	Commitment(array<string, 2> codes, string round, array<ZZ, 32> plaintext, array<Cipher_elg, 32> ciphertext_1, array<Cipher_elg, 32> ciphertext_2, array<ZZ, 32> ran_1, array<ZZ, 32> ran_2, Mod_p y_1, bool bigMe, string fileName);
	//加密正确性证明
	Commitment(array<string, 2> codes, string round, array<ZZ, 32> plaintext, array<Cipher_elg, 32> ciphertext, array<ZZ, 32> ran, bool bigMe, string fileName);
	//比较正确性证明
	Commitment(array<string, 2> codes, string round, array<ZZ, 32> plaintext_1, array<Cipher_elg, 32> ciphertext_1, array<Cipher_elg, 32> ciphertext_2, array<ZZ, 32> ran_1, Cipher_elg cipherZero_1, Cipher_elg cipherZero_2, ZZ ranZero, bool bigMe, string fileName);
	//解密正确性证明
	Commitment(array<string, 2> codes, string round, array<ZZ, 32> c2, array<ZZ, 32> dk, bool bigMe, string fileName);
	//验证
	Commitment(array<string, 2> codes, string round, array<Cipher_elg, 32> ciphertext, bool bigMe, string fileName);
	//验证
	Commitment(array<string, 2> codes, string round, array<Cipher_elg, 32> ciphertext_1, array<Cipher_elg, 32> ciphertext_2, Mod_p y, Mod_p y_1, bool bigMe, string fileName);
	//验证
	Commitment(array<string, 2> codes, string round, bool bigMe, string fileName);
	//比较正确性证明
	void compareCommit();
	//比较正确性证明验证
	bool compareCheck(Cipher_elg cipherZero);

	void cipherCommit();
	bool cipherCheck();

	void decryptCommit();
	bool decryptCheck();

	void ciphertextConsistencyCommit() {
		ost.open(fileName, ios::out);
		if (!ost)
		{
			cout << "[" << codes[0] << "] - " << "Can't create " << fileName << endl;
			exit(1);
		}
		ost << mod << endl;
		ost << ord << endl;
		ost << g << endl;
		ost << h << endl;
		array< ZZ, 32> c, s1, s2, s3, s4;
		array< Mod_p, 32> t;
		for (int i = 0; i < cipherNum; i++) {
			//生成随机数v1,v2,v3,v4
			ZZ v1 = RandomBnd(ord);
			ZZ v2 = v1;
			ZZ v3 = RandomBnd(ord);
			ZZ v4 = RandomBnd(ord);
			t[i] = g.expo(v1) * g.expo(v2) * y.expo(v3) * y_1.expo(v4);//g^v1 × y^v2
			stringstream ss;
			ss << g << y << y_1 << t[i] << ciphertext_1[i].get_v() << ciphertext_2[i].get_v();//hash( g, y1, y2, t, c1, c2 )
			ZZ hashValue = sha.hash(ss.str(), mod, ord);
			c[i] = hashValue;//hash挑战
			s1[i] = SubMod(v1, MulMod(c[i], plaintext[i], mod - 1), mod - 1);//v1-cm1
			s2[i] = SubMod(v2, MulMod(c[i], plaintext[i], mod - 1), mod - 1);//v2-cm2
			s3[i] = SubMod(v3, MulMod(c[i], ran_1[i], mod - 1), mod - 1);//v3-cr1
			s4[i] = SubMod(v4, MulMod(c[i], ran_2[i], mod - 1), mod - 1);//v4-cr2
		}
		//0 c
		for (int i = 0; i < cipherNum; i++)
			ost << c[i] << endl;
		//1 t
		for (int i = 0; i < cipherNum; i++)
			ost << t[i] << endl;
		//2 s1
		for (int i = 0; i < cipherNum; i++)
			ost << s1[i] << endl;
		//3 s2
		for (int i = 0; i < cipherNum; i++)
			ost << s2[i] << endl;
		//4 s3
		for (int i = 0; i < cipherNum; i++)
			ost << s3[i] << endl;
		//5 s4
		for (int i = 0; i < cipherNum; i++)
			ost << s4[i] << endl;
		ost.close();
	}
	bool ciphertextConsistencyCheck() {
		bool ans = true;
		ist.open(fileName, ios::in);
		if (!ist)
		{
			cout << "[" << codes[0] << "] - " << "Can't open " << fileName << endl;
			exit(1);
		}
		string container;
		array< ZZ, 32> c, s1, s2, s3, s4;
		array< Mod_p, 32> t;
		ist >> mod;
		ist >> ord;
		ist >> container;
		g.toModP(container, mod);
		ist >> container;
		h.toModP(container, mod);
		//0 c
		for (int i = 0; i < cipherNum; i++)
			ist >> c[i];
		//1 t
		for (int i = 0; i < cipherNum; i++)
		{
			ist >> container;
			t[i].toModP(container, mod);
		}
		//2 s1
		for (int i = 0; i < cipherNum; i++)
			ist >> s1[i];
		//3 s2
		for (int i = 0; i < cipherNum; i++)
			ist >> s2[i];
		//4 s3
		for (int i = 0; i < cipherNum; i++)
			ist >> s3[i];
		//5 s4
		for (int i = 0; i < cipherNum; i++)
			ist >> s4[i];
		ist.close();
		for (int i = 0; i < cipherNum; i++) {
			Mod_p x = Mod_p(ciphertext_1[i].get_v() * ciphertext_2[i].get_v(), mod);
			Mod_p temp = g.expo(s1[i]) * g.expo(s2[i]) * y.expo(s3[i]) * y_1.expo(s4[i]) * x.expo(c[i]);
			stringstream ss;
			ss << g << y << y_1 << t[i] << ciphertext_1[i].get_v() << ciphertext_2[i].get_v();//hash( g, y1, y2, t, c1, c2 )
			ZZ hashValue = sha.hash(ss.str(), mod, ord);
			ans &= (temp == t[i]);
			ans &= (s1[i] == s2[i]);
			ans &= (c[i] == hashValue);
		}
		return ans;
	}

};