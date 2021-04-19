#pragma once
#include "../global.h"
extern G_q G;               // group used for the Pedersen commitment
extern G_q H;               // group used for the the encryption
extern ElGamal El;         // The class for encryption and decryption
extern Network net;

class CipherGen {
private:
	ifstream ist;
	ofstream ost;
	array<string, 2> codes;//自己和对方的编号，第一个是自己的，第二个是对方的
	bitset<32> plaintext;//竞价二进制明文
	array<Cipher_elg, 32> ciphertext;    //密文
	array<ZZ, 32> ran;
	int plaintext_int;
	int cipherNum = 32;
	bool bigMe;
	ZZ mod;
	ZZ ord;
	Mod_p g;
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
			plaintext[i] = plaintext_inv[cipherNum - i - 1];
		/*for (int i = 0; i < cipherNum; i++)
			cout << plaintext_inv[i];
		cout << endl;
		for (int i = 0; i < cipherNum; i++)
			cout << plaintext[i];
		cout << endl;*/
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
			ran[i] = RandomBnd(ord);								 //随机数r，也被称作临时密钥
			Cipher_elg temp = El.encrypt_g(ZZ(plaintext[i]), ran[i]);//得到(u,v)密文组，u = h^r，v = g^m×y^r，y为公钥
			ciphertext[i] = temp;									 //顺序读入
			ost << temp << endl;										 //输出密文
			ss << temp << ";";
		}
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
		for (int i = 0; i < cipherNum; i++)
			ost << ciphertext_2_str[i] << endl;
		ost.close();
	}
	//sigma协议
	void sigma() {
		array< ZZ, 32> c, s1, s2, s3;
		array< Mod_p, 32> t1, t2;
		for (int i = 0; i < cipherNum; i++) {
			//生成三个随机数v1,v2,v3
			ZZ v1 = RandomBnd(ord);
			ZZ v2 = RandomBnd(ord);
			ZZ v3 = RandomBnd(ord);
			//生成两个承诺t1,t2
			Mod_p c1 = Mod_p(ciphertext[i].get_v(), mod);
			t1[i] = g.expo(v1) * y.expo(v2);//g^v1 × y^v2
			t2[i] = g.expo(MulMod(ZZ(plaintext[i]), v1, mod)) * y.expo(v3);//g^(m×v1) × y^v3
			stringstream ss;
			ss << g << y << t1[i] << t2[i] << c1;//hash( g, y, t1, t2, c1 )
			ZZ hashValue = sha.hash(ss.str(), El.get_group());
			c[i] = hashValue;//hash挑战
			//生成三个响应s1,s2,s3
			s1[i] = AddMod(MulMod(plaintext[i], c[i], mod - 1), v1, mod - 1);//s1=m×c+v1
			s2[i] = AddMod(MulMod(ran[i], c[i], mod - 1), v2, mod - 1);//s2=r×c+v2
			s3[i] = AddMod(MulMod(SubMod(c[i], s1[i], mod - 1), ran[i], mod - 1), v3, mod - 1);//s3=r×(c-s1)+v3

			/*//生成两个承诺t1,t2
			Mod_p temp1 = g.expo(v1);//g^v1
			Mod_p temp2 = y.expo(v2);//y^v2
			t1[i] = temp1 * temp2;//g^v1 × y^v2
			Mod_p temp3 = temp1.expo(ZZ(plaintext[i]));//g^(m×v1)
			Mod_p temp4 = y.expo(v3);//y^v3
			t2[i] = temp3 * temp4;//g^(m×v1) × y^v3
			stringstream ss;
			//string hash_in_str;
			ss << g << y << t1[i] << t2[i] << ciphertext[i].get_v();
			ZZ hashValue = sha.hash(ss.str(), El.get_group());//hash( g, y, t1, t2, c1 )
			c[i] = hashValue;
			//生成三个响应s1,s2,s3
			//s1=m×c+v1
			ZZ temp5 = MulMod(plaintext[i], c[i], mod - 1);
			s1[i] = AddMod(temp5, v1, mod - 1);
			//s2=r×c+v2
			ZZ temp6 = MulMod(ran[i], c[i], mod - 1);
			s2[i] = AddMod(temp6, v2, mod - 1);
			//s3=r×(c-s1)+v3
			ZZ temp7 = SubMod(c[i], s1[i], mod - 1);
			ZZ temp8 = MulMod(temp7, ran[i], mod - 1);
			s3[i] = AddMod(temp8, v3, mod - 1);*/
		}
		//0 c
		for (int i = 0; i < cipherNum; i++)
			ost << c[i] << endl;
		//1 t1
		for (int i = 0; i < cipherNum; i++)
			ost << t1[i] << endl;
		//2 t2
		for (int i = 0; i < cipherNum; i++)
			ost << t2[i] << endl;
		//3 s1
		for (int i = 0; i < cipherNum; i++)
			ost << s1[i] << endl;
		//4 s2
		for (int i = 0; i < cipherNum; i++)
			ost << s2[i] << endl;
		//5 s3
		for (int i = 0; i < cipherNum; i++)
			ost << s3[i] << endl;
	}
	//sigma协议检验
	bool checkSigma() {
		array< ZZ, 32> c, s1, s2, s3;
		array< Mod_p, 32> t1, t2;
		string container;
		bool flag = true;
		//0 c
		for (int i = 0; i < cipherNum; i++)
			ist >> c[i];
		//1 t1
		for (int i = 0; i < cipherNum; i++)
		{
			ist >> container;
			t1[i].toModP(container, mod);
		}
		//2 t2
		for (int i = 0; i < cipherNum; i++)
		{
			ist >> container;
			t2[i].toModP(container, mod);
		}
		//3 s1
		for (int i = 0; i < cipherNum; i++)
			ist >> s1[i];
		//4 s2
		for (int i = 0; i < cipherNum; i++)
			ist >> s2[i];
		//5 s3
		for (int i = 0; i < cipherNum; i++)
			ist >> s3[i];
		//检验
		for (int i = 0; flag && (i < cipherNum); i++) {
			Mod_p c1 = Mod_p(ciphertext[i].get_v(), mod);
			Mod_p temp1 = c1.expo(c[i]) * t1[i];//c1^c × t1
			Mod_p temp2 = g.expo(s1[i]) * y.expo(s2[i]);//g^s1 × y^s2
			Mod_p temp3 = c1.expo(SubMod(c[i], s1[i], mod - 1)) * t2[i];//c1^(c-s1) × t2
			Mod_p temp4 = g.expo(ZZ(0)) * y.expo(s3[i]);//g^0 × y^s3
			stringstream ss;
			ss << g << y << t1[i] << t2[i] << c1;//hash( g, y, t1, t2, c1 )
			ZZ hashValue = sha.hash(ss.str(), El.get_group());
			flag &= (temp1 == temp2);
			flag &= (temp3 == temp4);
			flag &= (c[i] == hashValue);
		}
		return flag;
	}
public:
	CipherGen(array<string, 2> codes, bool bigMe) :codes(codes), bigMe(bigMe) {
		SetSeed(to_ZZ((long)time(0) + (long)clock()));
		y = El.get_pk();
		mod = El.get_group().get_mod();
		ord = El.get_group().get_ord();
		g = El.get_group().get_g();
	}
	//生成密文( h^r , g^m × y^r )
	array<Cipher_elg, 32> gen() {
		readPlaintext();
		createCipher();
		return ciphertext;
	}
	//生成证明
	void prove() {
		string fileName = "proveCipher" + codes[0] + ".txt";
		ost.open(fileName, ios::out);
		if (!ost)
		{
			cout << "Can't create " << fileName << endl;
			exit(1);
		}
		sigma();
		ost.close();
	}
	bool verify() {
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
		ist.open(fileName, ios::in);
		if (!ist)
		{
			cout << "Can't open " << fileName << endl;
			exit(1);
		}
		flag &= checkSigma();
		ist.close();
		return flag;
	}
};