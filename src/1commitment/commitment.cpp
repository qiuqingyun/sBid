#include "commitment.h"

//加密正确性证明
Commitment::Commitment(array<string, 2> codes, array<ZZ, 32> plaintext, array<Cipher_elg, 32> ciphertext, array<ZZ, 32> ran, bool bigMe, string fileName) :codes(codes), plaintext(plaintext), ciphertext(ciphertext), ran(ran), bigMe(bigMe), fileName(fileName) {
	mod = El.get_group().get_mod();
	ord = El.get_group().get_ord();
	g = El.get_group().get_g();
	h = El.get_group().get_gen();
	y = El.get_pk();
}
//比较正确性证明
Commitment::Commitment(array<string, 2> codes, array<ZZ, 32> plaintext_1, array<Cipher_elg, 32> ciphertext_1, array<Cipher_elg, 32> ciphertext_2, array<ZZ, 32> ran_1, Cipher_elg cipherZero_1, Cipher_elg cipherZero_2, ZZ ranZero, bool bigMe, string fileName) :codes(codes), plaintext_1(plaintext_1), ciphertext_1(ciphertext_1), ciphertext_2(ciphertext_2), ran_1(ran_1), cipherZero_1(cipherZero_1), cipherZero_2(cipherZero_2), ranZero(ranZero), bigMe(bigMe), fileName(fileName) {
	mod = El.get_group().get_mod();
	ord = El.get_group().get_ord();
	g = El.get_group().get_g();
	h = El.get_group().get_gen();
	y = El.get_pk();
}
//解密正确性证明
Commitment::Commitment(array<string, 2> codes, array<ZZ, 32> c2, array<ZZ, 32> dk, bool bigMe, string fileName) :codes(codes), c2(c2), dk(dk), bigMe(bigMe), fileName(fileName) {
	mod = El.get_group().get_mod();
	ord = El.get_group().get_ord();
	g = El.get_group().get_g();
	h = El.get_group().get_gen();
	y = El.get_pk();
	y1 = El.get_pk_1();
	x1 = Mod_p(El.get_sk(), mod);
}
//验证
Commitment::Commitment(array<string, 2> codes, array<Cipher_elg, 32> ciphertext, bool bigMe, string fileName) :codes(codes), ciphertext(ciphertext), bigMe(bigMe), fileName(fileName) {}
//验证
Commitment::Commitment(array<string, 2> codes, bool bigMe, string fileName) :codes(codes), bigMe(bigMe), fileName(fileName) {}
//比较正确性证明
void Commitment::compareCommit() {
	ost.open(fileName, ios::out);
	if (!ost)
	{
		cout << "Can't create " << fileName << endl;
		exit(1);
	}
	ost << mod << endl;
	ost << ord << endl;
	ost << g << endl;
	ost << h << endl;
	ost << y << endl;
	compareCommit0();
	compareCommit1();
	compareCommit2();
	compareCommit3();
	compareCommit4();
	compareCommit5();
	ost.close();
}
//比较正确性证明验证
bool Commitment::compareCheck(Cipher_elg cipherZero) {
	bool ans = true;
	ist.open(fileName, ios::in);
	if (!ist)
	{
		cout << "Can't open " << fileName << endl;
		exit(1);
	}
	string container;
	ist >> mod;
	ist >> ord;
	ist >> container;
	g.toModP(container, mod);
	ist >> container;
	h.toModP(container, mod);
	ist >> container;
	y.toModP(container, mod);
	ans &= compareCommitCheck0();
	ans &= compareCommitCheck1();
	ans &= compareCommitCheck2();
	ans &= compareCommitCheck3();
	ans &= compareCommitCheck4();
	ans &= compareCommitCheck5();
	ost.close();
	return ans;
}

void Commitment::cipherCommit() {
	ost.open(fileName, ios::out);
	if (!ost)
	{
		cout << "Can't create " << fileName << endl;
		exit(1);
	}
	ost << mod << endl;
	ost << ord << endl;
	ost << g << endl;
	ost << h << endl;
	ost << y << endl;

	sigma();
	indicates();//表示证明
	discreteLogarithm(2);//离散对数证明
	linearEquation(1);//线性等式证明

	ost.close();
}
bool Commitment::cipherCheck() {
	bool ans = true;
	ist.open(fileName, ios::in);
	if (!ist)
	{
		cout << "Can't open " << fileName << endl;
		exit(1);
	}
	string container;
	ist >> mod;
	ist >> ord;
	ist >> container;
	g.toModP(container, mod);
	ist >> container;
	h.toModP(container, mod);
	ist >> container;
	y.toModP(container, mod);

	ans &= checkSigma();
	ans &= indicatesCheck();
	ans &= discreteLogarithmCheck(2);
	ans &= linearEquationCheck(1);
	ist.close();
	return ans;
}

void Commitment::decryptCommit() {
	ost.open(fileName, ios::out);
	if (!ost)
	{
		cout << "Can't create " << fileName << endl;
		exit(1);
	}
	ost << mod << endl;
	ost << ord << endl;
	ost << g << endl;
	ost << h << endl;
	ost << y << endl;

	for (int i = 0; i < cipherNum; i++) {
		ran[i] = x1.get_val();//x1
		ciphertext[i] = Cipher_elg(y1.get_val(), dk[i], mod);
		base1[i] = Mod_p(c2[i], mod);
		base2[i] = h;
		ost << ciphertext[i] << endl;
		ost << base1[i] << endl;
		ost << base2[i] << endl;
	}
	equation();

	ost.close();
}
bool Commitment::decryptCheck() {
	bool ans = true;
	ist.open(fileName, ios::in);
	if (!ist)
	{
		cout << "Can't open " << fileName << endl;
		exit(1);
	}
	string container;
	ist >> mod;
	ist >> ord;
	ist >> container;
	g.toModP(container, mod);
	ist >> container;
	h.toModP(container, mod);
	ist >> container;
	y.toModP(container, mod);

	for (int i = 0; i < cipherNum; i++) {
		ist >> ciphertext[i];
		ist >> container;
		base1[i].toModP(container, mod);
		ist >> container;
		base2[i].toModP(container, mod);
	}

	ans &= equationCheck();
	ist.close();
	return ans;
}

//sigma协议承诺
void Commitment::sigma() {
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
bool Commitment::checkSigma() {
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

//表示证明
void Commitment::indicates() {
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
//表示证明检验
bool Commitment::indicatesCheck() {
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

//离散对数证明
void Commitment::discreteLogarithm(int flag) {
	array< ZZ, 32> c, s;
	array< Mod_p, 32> t;
	for (int i = 0; i < cipherNum; i++) {
		//生成随机数v
		ZZ v = RandomBnd(ord);
		//生成承诺t
		Mod_p c2;
		ZZ hashValue;
		switch (flag)
		{
			case 1: {
				c2 = Mod_p(ciphertext[i].get_v(), mod);

				t[i] = y.expo(v);//y^v
				stringstream ss;
				ss << y << t[i] << c2;//hash( y, t, c2 )
				hashValue = sha.hash(ss.str(), El.get_group());
				break;
			}
			case 2: {
				c2 = Mod_p(ciphertext[i].get_u(), mod);

				t[i] = h.expo(v);//h^v
				stringstream ss;
				ss << h << t[i] << c2;//hash( h, t, c2 )
				hashValue = sha.hash(ss.str(), El.get_group());
				break;
			}
			case 3: {
				c2 = Mod_p(ciphertext[i].get_v(), mod);

				t[i] = base1[i].expo(v);//y^v
				stringstream ss;
				ss << base1[i] << t[i] << c2;//hash( y, t, c2 )
				hashValue = sha.hash(ss.str(), El.get_group());
				break;
			}
			case 4: {
				c2 = Mod_p(ciphertext[i].get_u(), mod);

				t[i] = base2[i].expo(v);//h^v
				stringstream ss;
				ss << base2[i] << t[i] << c2;//hash( h, t, c2 )
				hashValue = sha.hash(ss.str(), El.get_group());
				break;
			}
			default:
				break;
		}
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
//离散对数证明检验
bool Commitment::discreteLogarithmCheck(int flag) {
	array< ZZ, 32> c, s;
	array< Mod_p, 32> t;
	string container;
	bool ans = true;
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
		Mod_p c2, temp;
		ZZ hashValue;
		switch (flag)
		{
			case 1: {
				c2 = Mod_p(ciphertext[i].get_v(), mod);
				temp = y.expo(s[i]) * c2.expo(c[i]);//y^s × c2^c
				stringstream ss;
				ss << y << t[i] << c2;//hash( y, t, c2 )
				hashValue = sha.hash(ss.str(), El.get_group());
				break;
			}
			case 2: {
				c2 = Mod_p(ciphertext[i].get_u(), mod);
				temp = h.expo(s[i]) * c2.expo(c[i]);//h^s × c2^c
				stringstream ss;
				ss << h << t[i] << c2;//hash( h, t, c2 )
				hashValue = sha.hash(ss.str(), El.get_group());
				break;
			}
			case 3: {
				c2 = Mod_p(ciphertext[i].get_v(), mod);
				temp = base1[i].expo(s[i]) * c2.expo(c[i]);//y^s × c2^c
				stringstream ss;
				ss << base1[i] << t[i] << c2;//hash( y, t, c2 )
				hashValue = sha.hash(ss.str(), El.get_group());
				break;
			}
			case 4: {
				c2 = Mod_p(ciphertext[i].get_u(), mod);
				temp = base2[i].expo(s[i]) * c2.expo(c[i]);//h^s × c2^c
				stringstream ss;
				ss << base2[i] << t[i] << c2;//hash( h, t, c2 )
				hashValue = sha.hash(ss.str(), El.get_group());
				break;
			}
			default:
				break;
		}
		ans &= (temp == t[i]);
		ans &= (c[i] == hashValue);
	}
	return ans;
}

//线性等式证明
void Commitment::linearEquation(int flag) {
	array< ZZ, 32> c, s1, s2, s3;
	array< Mod_p, 32> t, x;
	for (int i = 0; i < cipherNum; i++) {
		ZZ hashValue, v1, v2, v3;
		x[i] = Mod_p(MulMod(ciphertext[i].get_u(), ciphertext[i].get_v(), mod), mod);
		//生成随机数v1,v2,v3
		v1 = RandomBnd(ord);
		v2 = RandomBnd(ord);
		v3 = v2;
		if (flag == 1) {
			//生成承诺t
			t[i] = g.expo(v1) * y.expo(v2) * h.expo(v3);//g^v1 × y^v2 × h^v3
			stringstream ss;
			ss << h << y << g << t[i] << x[i];//hash( h, y, g, t, x )
			hashValue = sha.hash(ss.str(), El.get_group());
			c[i] = hashValue;//hash挑战
			//生成响应s
			s1[i] = SubMod(v1, MulMod(plaintext[i], c[i], mod - 1), mod - 1);//s1=v1-m×c
			s2[i] = SubMod(v2, MulMod(ran[i], c[i], mod - 1), mod - 1);//s2=v2-r×c
			s3[i] = SubMod(v3, MulMod(ran[i], c[i], mod - 1), mod - 1);//s3=v3-r×c
			//cout << "\ns1: " << s1[i] << "\ns2: " << s2[i] << "\ns3: " << s3[i] << endl;
		}
		else {
			//生成承诺t
			t[i] = y.expo(v1) * g.expo(v2) * base2[i].expo(v3);//g^v1 × y^v2 × h^v3
			stringstream ss;
			ss << base2[i] << y << g << t[i] << x[i];//hash( h, y, g, t, x )
			hashValue = sha.hash(ss.str(), El.get_group());
			c[i] = hashValue;//hash挑战
			//生成响应s
			s1[i] = SubMod(v1, MulMod(ran[i], c[i], mod - 1), mod - 1);//s1=v1-m×c
			s2[i] = SubMod(v2, MulMod(plaintext[i], c[i], mod - 1), mod - 1);//s2=v2-r×c
			s3[i] = SubMod(v3, MulMod(plaintext[i], c[i], mod - 1), mod - 1);//s3=v3-r×c
		}
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
//线性等式证明检验
bool Commitment::linearEquationCheck(int flag) {
	array< ZZ, 32> c, s1, s2, s3;
	array< Mod_p, 32> t, x;
	string container;
	bool ans = true;
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
	for (int i = 0; ans && (i < cipherNum); i++) {
		x[i] = Mod_p(MulMod(ciphertext[i].get_u(), ciphertext[i].get_v(), mod), mod);
		Mod_p temp;
		ZZ hashValue;
		if (flag == 1) {
			temp = g.expo(s1[i]) * y.expo(s2[i]) * h.expo(s3[i]) * x[i].expo(c[i]);//g^s1 × y^s2 × h^s3 × x^c
			stringstream ss;
			ss << h << y << g << t[i] << x[i];//hash( h, y, g, t, x )
			hashValue = sha.hash(ss.str(), El.get_group());
		}
		else {
			temp = y.expo(s1[i]) * g.expo(s2[i]) * base2[i].expo(s3[i]) * x[i].expo(c[i]);//g^s1 × y^s2 × h^s3 × x^c
			stringstream ss;
			ss << base2[i] << y << g << t[i] << x[i];//hash( h, y, g, t, x )
			hashValue = sha.hash(ss.str(), El.get_group());
		}
		ans &= (temp == t[i]);
		ans &= (s2[i] == s3[i]);
		ans &= (c[i] == hashValue);
	}
	return ans;
}

//等式证明
void Commitment::equation() {
	array< ZZ, 32> c, s;
	array< Mod_p, 32> t1, t2;
	for (int i = 0; i < cipherNum; i++) {
		Mod_p c1 = Mod_p(ciphertext[i].get_v(), mod);
		Mod_p c2 = Mod_p(ciphertext[i].get_u(), mod);
		//生成随机数v
		ZZ v = RandomBnd(ord);
		//生成承诺t
		t1[i] = base1[i].expo(v);//y^v
		t2[i] = base2[i].expo(v);//h^v
		stringstream ss;
		ss << base2[i] << base1[i] << t1[i] << t2[i] << c1 << c2;//hash( h, y, t1, t2, c1, c2 )
		ZZ hashValue = sha.hash(ss.str(), El.get_group());
		c[i] = hashValue;//hash挑战
		//生成响应s
		s[i] = SubMod(v, MulMod(ran[i], c[i], mod - 1), mod - 1);//s2=v-r×c
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
	//3 s
	for (int i = 0; i < cipherNum; i++)
		ost << s[i] << endl;
}
//线性等式证明检验
bool Commitment::equationCheck() {
	array< ZZ, 32> c, s;
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
	//3 s
	for (int i = 0; i < cipherNum; i++)
		ist >> s[i];

	//检验
	for (int i = 0; flag && (i < cipherNum); i++) {
		Mod_p c1 = Mod_p(ciphertext[i].get_v(), mod);
		Mod_p c2 = Mod_p(ciphertext[i].get_u(), mod);
		Mod_p temp1 = base1[i].expo(s[i]) * c1.expo(c[i]);//y^s × c1^c
		Mod_p temp2 = base2[i].expo(s[i]) * c2.expo(c[i]);//h^s × c2^c
		stringstream ss;
		ss << base2[i] << base1[i] << t1[i] << t2[i] << c1 << c2;//hash( h, y, t1, t2, c1, c2 )
		ZZ hashValue = sha.hash(ss.str(), El.get_group());
		flag &= (temp1 == t1[i]);
		flag &= (temp2 == t2[i]);
		flag &= (c[i] == hashValue);
	}
	return flag;
}

//比较正确性前置证明
void Commitment::compareCommit0() {
	cipherNum = 1;
	ciphertext[0] = cipherZero_1;
	ran[0] = ranZero;
	base1[0] = y;
	base2[0] = h;
	ost << ciphertext[0] << endl;
	discreteLogarithm(1);
	discreteLogarithm(2);
	equation();
}
//比较正确性前置证明验证
bool Commitment::compareCommitCheck0() {
	bool ans = true;
	cipherNum = 1;
	base1[0] = y;
	base2[0] = h;
	ist >> ciphertext[0];
	ans &= discreteLogarithmCheck(1);
	ans &= discreteLogarithmCheck(2);
	ans &= equationCheck();
	//cout << "round0: " << ans << endl;
	return ans;
}

//比较正确性第一轮证明
void Commitment::compareCommit1() {
	plaintext_s = RandomBnd(ord);//随机数S
	//plaintext_s = 1;
	plaintext[0] = plaintext_s;
	ran[0] = RandomBnd(ord);//随机数rs
	ciphertext[0] = El.encrypt_g(plaintext[0], ran[0]);//E(s)
	ost << ciphertext[0] << endl;
	indicates();
	discreteLogarithm(2);
	linearEquation(1);
}
//比较正确性第一轮证明验证
bool Commitment::compareCommitCheck1() {
	bool ans = true;
	cipherNum = 1;
	ist >> ciphertext[0];
	ans &= indicatesCheck();
	ans &= discreteLogarithmCheck(2);
	ans &= linearEquationCheck(1);
	//cout << "round1: " << ans << endl;
	return ans;
}

//比较正确性第二轮证明
void Commitment::compareCommit2() {
	ZZ s = plaintext[0];
	ZZ rs = ran[0];
	Cipher_elg Es = ciphertext[0];
	cipherNum = 32;
	for (int i = 0; i < cipherNum; i++) {
		plaintext[i] = AddMod(plaintext_1[i], s, mod);//s+b
		ran[i] = AddMod(ran_1[i], rs, mod);//rs+rb
		ciphertext[i] = Es * ciphertext_1[i];//E(s) * E(b)
		ciphertext_round2[i] = ciphertext[i];
		plaintext_round2[i] = plaintext[i];
		ran_round2[i] = ran[i];
		ost << ciphertext[i] << endl;
	}
	indicates();
	discreteLogarithm(2);
	linearEquation(1);
}
//比较正确性第二轮证明验证
bool Commitment::compareCommitCheck2() {
	bool ans = true;
	cipherNum = 32;
	for (int i = 0; i < cipherNum; i++)
		ist >> ciphertext[i];
	ans &= indicatesCheck();
	ans &= discreteLogarithmCheck(2);
	ans &= linearEquationCheck(1);
	//cout << "round2: " << ans << endl;
	return ans;
}

//比较正确性第三轮证明
void Commitment::compareCommit3() {
	cipherNum = 32;
	for (int i = 0; i < cipherNum; i++) {
		ran[i] = plaintext[i];//s+b
		ciphertext[i] = Cipher_elg::expo(ciphertext_2[i], ran[i]);//E(a)^(s+b)
		ciphertext_round3[i] = ciphertext[i];
		base1[i] = Mod_p(ciphertext_2[i].get_v(), mod);//h1
		base2[i] = Mod_p(ciphertext_2[i].get_u(), mod);//h^ra
		ost << ciphertext[i] << endl;
		ost << base1[i] << endl;
		ost << base2[i] << endl;
	}
	discreteLogarithm(3);
	discreteLogarithm(4);
	equation();
}
//比较正确性第三轮证明验证
bool Commitment::compareCommitCheck3() {
	bool ans = true;
	string container;
	for (int i = 0; i < cipherNum; i++) {
		ist >> ciphertext[i];
		ist >> container;
		base1[i].toModP(container, mod);
		ist >> container;
		base2[i].toModP(container, mod);
	}
	ans &= discreteLogarithmCheck(3);
	ans &= discreteLogarithmCheck(4);
	ans &= equationCheck();
	//cout << "round3: " << ans << endl;
	return ans;
}

//比较正确性第四轮证明
void Commitment::compareCommit4() {
	for (int i = 0; i < cipherNum; i++) {
		ciphertext[i] = Cipher_elg(ciphertext_round2[i].get_v(), ciphertext_round3[i].get_u(), mod);
		plaintext[i] = plaintext_round2[i];//rb+rs
		ran[i] = ran_round2[i];//b+s
		ost << ciphertext[i] << endl;
	}
	linearEquation(2);
}
//比较正确性第四轮证明验证
bool Commitment::compareCommitCheck4() {
	bool ans = true;
	for (int i = 0; i < cipherNum; i++) {
		ist >> ciphertext[i];
	}
	ans &= linearEquationCheck(2);
	//cout << "round4: " << ans << endl;
	return ans;
}

//比较正确性第五轮证明
void Commitment::compareCommit5() {
	for (int i = 0; i < cipherNum; i++) {
		Cipher_elg temp = ciphertext_2[i] * cipherZero_2;
		ran[i] = plaintext_s;//s
		ciphertext[i] = Cipher_elg::expo(temp, ran[i]);//E(a)*E(ra')^(s)
		base1[i] = Mod_p(temp.get_v(), mod);//h1
		base2[i] = Mod_p(temp.get_u(), mod);//h^ra
		ost << ciphertext[i] << endl;
		ost << base1[i] << endl;
		ost << base2[i] << endl;
	}
	discreteLogarithm(3);
	discreteLogarithm(4);
	equation();
}
//比较正确性第五轮证明验证
bool Commitment::compareCommitCheck5() {
	bool ans = true;
	string container;
	for (int i = 0; i < cipherNum; i++) {
		ist >> ciphertext[i];
		ist >> container;
		base1[i].toModP(container, mod);
		ist >> container;
		base2[i].toModP(container, mod);
	}
	ans &= discreteLogarithmCheck(3);
	ans &= discreteLogarithmCheck(4);
	ans &= equationCheck();
	//cout << "round5: " << ans << endl;
	return ans;
}