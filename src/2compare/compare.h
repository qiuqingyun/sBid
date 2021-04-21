#pragma once
#include "../global.h"
extern G_q G;               // group used for the Pedersen commitment
extern G_q H;               // group used for the the encryption
extern ElGamal El;         // The class for encryption and decryption
extern Network net;

class Compare {
private:
	ifstream ist;
	ofstream ost;
	array<string, 2> codes;//自己和对方的编号，第一个是自己的，第二个是对方的
	array<ZZ, 32> plaintext;//竞价二进制明文
	array<Cipher_elg, 32> ciphertext;    //密文
	array<Cipher_elg, 32> ciphertext_2;  //对方的密文
	array<Cipher_elg, 33> Wj;
	array<Cipher_elg, 32> compareResults;//比较结果密文
	array<ZZ, 32> ran_1;
	Cipher_elg cipherZero;
	Cipher_elg cipherZero_2;
	ZZ ranZero;
	int cipherNum = 32;
	bool bigMe;
	ZZ mod;
	ZZ ord;
	Mod_p g;
	Mod_p h;
	Mod_p y;
	SHA256 sha;
	//读取对方的密文
	void readCipher() {
		string fileName = "ciphertext" + codes[1] + ".txt";
		ist.open(fileName, ios::in);
		if (!ist) {
			cout << "Can't open " << fileName << endl;
			exit(1);
		}
		for (int i = 0; i < cipherNum; i++)
			ist >> ciphertext_2[i];
		string temp;
		for (int i = 0; i < cipherNum; i++)
			ist >> temp;
		ist >> cipherZero_2;//读取对方的0密文
		ist.close();
		fileName = "ciphertext" + codes[0] + ".txt";
		ist.open(fileName, ios::in);
		if (!ist) {
			cout << "Can't open " << fileName << endl;
			exit(1);
		}
		for (int i = 0; i < cipherNum; i++)
			ist >> temp;
		ist >> cipherZero;//读取自己的0密文
		ist.close();
	}
	//从高到低逐位比较
	void cmp() {
		if (bigMe) {//大号进行比较操作，并将结果发送给小号
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
			stringstream ss;

			for (int i = 0; i < cipherNum; i++) {
				a = ciphertext[i];
				b = ciphertext_2[i];
				aPb = a * b;//a+b
				aTb = Cipher_elg::expo(b, ZZ(plaintext[i]));//a*b 明文参与
				twoTaTb = Cipher_elg::expo(aTb, ZZ(2));//2*a*b
				minus2TaTb = Cipher_elg::inverse(twoTaTb);//-2*a*b
				Wj[i + 1] = aPb * minus2TaTb;//a+b-2*a*b
				Wj_sum = Wj_sum * Wj[i];
				b_minus = Cipher_elg::inverse(b);//-b
				aMbM1 = a * b_minus * ONE;//a-b+1
				compareResults[i] = aMbM1 * Wj_sum;
				ost << compareResults[i] << endl;
				ss << compareResults[i] << ";";
			}
			ost.close();
			clock_t  tstop = clock();
			double ttime = (tstop - tstart) / (double)CLOCKS_PER_SEC * 1000;
			cout << "[" << codes[0] << "] - " << "compare " << ttime << " ms" << endl;
			string CR;
			ss >> CR;
			net.mSend(CR);
		}
		else {//小号接收比较结果
			string CR;
			net.mReceive(CR);
			vector<string> CR_str;
			net.deserialization(CR, CR_str);
			string fileName = "cipherCR" + codes[1] + ".txt";
			ost.open(fileName, ios::out);
			if (!ost)
			{
				cout << "Can't create " << fileName << endl;
				exit(1);
			}
			for (int i = 0; i < cipherNum; i++)
				ost << CR_str[i] << endl;
			ost.close();
		}
	}

public:
	Compare(array<string, 2> codes, array<ZZ, 32> plaintext, array<Cipher_elg, 32> ciphertext, array<ZZ, 32> ran_1, ZZ ranZero, bool bigMe) :codes(codes), plaintext(plaintext), ciphertext(ciphertext), ran_1(ran_1), ranZero(ranZero), bigMe(bigMe) {
		SetSeed(to_ZZ((long)time(0) + (long)clock()));
		y = El.get_pk();
		mod = El.get_group().get_mod();
		ord = El.get_group().get_ord();
		g = El.get_group().get_g();
		h = El.get_group().get_gen();
	}
	Compare(array<string, 2> codes,array<Cipher_elg, 32> ciphertext, bool bigMe) :codes(codes), ciphertext(ciphertext), bigMe(bigMe) {
		//SetSeed(to_ZZ((long)time(0) + (long)clock()));
		y = El.get_pk();
		mod = El.get_group().get_mod();
		ord = El.get_group().get_ord();
		g = El.get_group().get_g();
		h = El.get_group().get_gen();
	}
	//比较
	void compare() {
		readCipher();
		cmp();
	}
	//生成证明
	void prove() {
		clock_t tstart = clock();
		string fileName = "proveCompare" + codes[0] + ".txt";
		ost.open(fileName, ios::out);
		if (!ost)
		{
			cout << "Can't create " << fileName << endl;
			exit(1);
		}
		//TODO:生成证明
		Commitment com(codes, plaintext, ciphertext, ciphertext_2, ran_1, cipherZero, cipherZero_2, ranZero, bigMe, fileName);
		com.compareCommit();

		ost.close();
		clock_t tstop = clock();
		double ttime = (tstop - tstart) / (double)CLOCKS_PER_SEC * 1000;
		cout << "[" << codes[0] << "] - " << "prove compare " << ttime << " ms" << endl;
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
		ist >> cipherZero;
		ist.close();
		//读入证明
		fileName = "proveCompare" + codes[0] + ".txt";
		ist.open(fileName, ios::in);
		if (!ist)
		{
			cout << "Can't open " << fileName << endl;
			exit(1);
		}

		//TODO:验证证明
		Commitment com(codes, ciphertext, bigMe, fileName);
		flag &= com.compareCheck(cipherZero);

		ist.close();
		clock_t tstop = clock();
		double ttime = (tstop - tstart) / (double)CLOCKS_PER_SEC * 1000;
		cout << "[" << codes[0] << "] - " << "verify compare " << ttime << " ms" << endl;
		return flag;
	}
};