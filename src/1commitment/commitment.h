#pragma once
#include "../global.h"
extern G_q G;               // group used for the Pedersen commitment
extern G_q H;               // group used for the the encryption
extern ElGamal El;         // The class for encryption and decryption
extern Network net;

class Commitment {
private:
	ifstream ist;
	ofstream ost;
	array<string, 2> codes;//自己和对方的编号，第一个是自己的，第二个是对方的
	bitset<32> plaintext;//竞价二进制明文
	array<Cipher_elg, 32> ciphertext;    //密文
	array<ZZ, 32> ran;
	int cipherNum = 32;
	bool bigMe;
	string fileName;
	ZZ mod;
	ZZ ord;
	Mod_p g;
	Mod_p h;
	Mod_p y;
	SHA256 sha;
	//sigma协议承诺
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
	//加密正确性P1承诺
	void indicates() {
		array< ZZ, 32> c, s1, s2;
		array< Mod_p, 32> t;
		for (int i = 0; i < cipherNum; i++) {
			//生成两个随机数v1,v2
			ZZ v1 = RandomBnd(ord);
			ZZ v2 = RandomBnd(ord);
			//生成一个承诺t
			Mod_p c1 = Mod_p(ciphertext[i].get_v(), mod);
			t[i] = g.expo(v1) * y.expo(v2);//g^v1 × y^v2
			stringstream ss;
			ss << g << y << t[i] << c1;//hash( g, y, t, c1 )
			ZZ hashValue = sha.hash(ss.str(), El.get_group());
			c[i] = hashValue;//hash挑战
			//生成三个响应s1,s2,s3
			s1[i] = SubMod(v1, MulMod(plaintext[i], c[i], mod - 1), mod - 1);//s1=v1-m×c
			s2[i] = SubMod(v2, MulMod(ran[i], c[i], mod - 1), mod - 1);//s2=v2-r×c
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
	}
	//加密正确性P1检验
	bool indicatesCheck() {
		array< ZZ, 32> c, s1, s2;
		array< Mod_p, 32> t;
		string container;
		bool flag = true;
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
		//检验
		for (int i = 0; flag && (i < cipherNum); i++) {
			Mod_p c1 = Mod_p(ciphertext[i].get_v(), mod);
			Mod_p temp = g.expo(s1[i]) * y.expo(s2[i]) * c1.expo(c[i]);//g^s1 × y^s2 × c1^c
			stringstream ss;
			ss << g << y << t[i] << c1;//hash( g, y, t, c1 )
			ZZ hashValue = sha.hash(ss.str(), El.get_group());
			flag &= (temp == t[i]);
			flag &= (c[i] == hashValue);
		}
		return flag;
	}
	//加密正确性P2承诺
	void discreteLogarithm() {
		array< ZZ, 32> c, s;
		array< Mod_p, 32> t;
		for (int i = 0; i < cipherNum; i++) {
			//生成随机数v
			ZZ v = RandomBnd(ord);
			//生成承诺t
			Mod_p c2 = Mod_p(ciphertext[i].get_u(), mod);
			t[i] = h.expo(v);//h^v
			stringstream ss;
			ss << h << t[i] << c2;//hash( h, t, c2 )
			ZZ hashValue = sha.hash(ss.str(), El.get_group());
			c[i] = hashValue;//hash挑战
			//生成响应s
			s[i] = SubMod(v, MulMod(ran[i], c[i], mod - 1), mod - 1);//s=v-r×c
		}
		//0 c
		for (int i = 0; i < cipherNum; i++)
			ost << c[i] << endl;
		//1 t
		for (int i = 0; i < cipherNum; i++)
			ost << t[i] << endl;
		//2 s
		for (int i = 0; i < cipherNum; i++)
			ost << s[i] << endl;

	}
	//加密正确性P2检验
	bool discreteLogarithmCheck() {
		array< ZZ, 32> c, s;
		array< Mod_p, 32> t;
		string container;
		bool flag = true;
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
			ist >> s[i];
		//检验
		for (int i = 0; flag && (i < cipherNum); i++) {
			Mod_p c2 = Mod_p(ciphertext[i].get_u(), mod);
			Mod_p temp = h.expo(s[i]) * c2.expo(c[i]);//h^s × c2^c
			stringstream ss;
			ss << h << t[i] << c2;//hash( h, t, c2 )
			ZZ hashValue = sha.hash(ss.str(), El.get_group());
			flag &= (temp == t[i]);
			flag &= (c[i] == hashValue);
		}
		return flag;
	}
	//加密正确性P3承诺
	void linearEquation() {
		array< ZZ, 32> c, s1, s2, s3;
		array< Mod_p, 32> t, x;
		for (int i = 0; i < cipherNum; i++) {
			x[i] = Mod_p(MulMod(ciphertext[i].get_u(), ciphertext[i].get_v(), mod), mod);
			//生成随机数v1,v2,v3
			ZZ v1 = RandomBnd(ord);
			ZZ v2 = RandomBnd(ord);
			ZZ v3 = v2;
			//生成承诺t
			t[i] = g.expo(v1) * y.expo(v2) * h.expo(v3);//g^v1 × y^v2 × h^v3
			stringstream ss;
			ss << h << y << g << t[i] << x[i];//hash( h, y, g, t, x )
			ZZ hashValue = sha.hash(ss.str(), El.get_group());
			c[i] = hashValue;//hash挑战
			//生成响应s
			s1[i] = SubMod(v1, MulMod(ZZ(plaintext[i]), c[i], mod - 1), mod - 1);//s1=v1-m×c
			s2[i] = SubMod(v2, MulMod(ran[i], c[i], mod - 1), mod - 1);//s2=v2-r×c
			s3[i] = SubMod(v3, MulMod(ran[i], c[i], mod - 1), mod - 1);//s3=v3-r×c

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

	}
	//加密正确性P3检验
	bool linearEquationCheck() {
		array< ZZ, 32> c, s1, s2, s3;
		array< Mod_p, 32> t, x;
		string container;
		bool flag = true;
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
		//检验
		for (int i = 0; flag && (i < cipherNum); i++) {
			x[i] = Mod_p(MulMod(ciphertext[i].get_u(), ciphertext[i].get_v(), mod), mod);
			Mod_p temp = g.expo(s1[i]) * y.expo(s2[i]) * h.expo(s3[i]) * x[i].expo(c[i]);//g^s1 × y^s2 × h^s3 × x^c
			stringstream ss;
			ss << h << y << g << t[i] << x[i];//hash( h, y, g, t, x )
			ZZ hashValue = sha.hash(ss.str(), El.get_group());
			flag &= (temp == t[i]);
			flag &= (c[i] == hashValue);
		}
		return flag;
	}
	//void encript
	
public:
	Commitment(array<string, 2> codes, bitset<32> plaintext, array<Cipher_elg, 32> ciphertext, array<ZZ, 32> ran, bool bigMe,string fileName) :codes(codes), plaintext(plaintext), ciphertext(ciphertext), ran(ran), bigMe(bigMe), fileName(fileName){
		mod = El.get_group().get_mod();
		ord = El.get_group().get_ord();
		g = El.get_group().get_g();
		h = El.get_group().get_gen();
		y = El.get_pk();
	}
	void commit(int flag) {
		//sha = new SHA256;
		ost.open(fileName, ios::out);
		if (!ost)
		{
			cout << "Can't create " << fileName << endl;
			exit(1);
		}
		switch (flag)
		{
			case 0:
				sigma();
				indicates();//表示证明
				discreteLogarithm();//离散对数证明
				linearEquation();//线性等式证明
				break;
			case 1:
				indicates();//表示证明
				discreteLogarithm();//离散对数证明
				linearEquation();//线性等式证明
				break;
			default:
				break;
		}
		ost.close();
		//delete sha;
	}
	bool check(int flag) {
		//sha = new SHA256;
		bool ans = true;
		ist.open(fileName, ios::in);
		if (!ist)
		{
			cout << "Can't open " << fileName << endl;
			exit(1);
		}
		switch (flag)
		{
			case 0:
				ans &= checkSigma();
				break;
			case 1:
				break;
			default:
				break;
		}
		ans &= indicatesCheck();
		ans &= discreteLogarithmCheck();
		ans &= linearEquationCheck();
		ist.close();
		//delete sha;
		return ans;
	}
};