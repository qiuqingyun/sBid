#include "cipherGen.h"

CipherGen::CipherGen(array<string, 2> codes, string round, bool bigMe) :codes(codes), round(round), bigMe(bigMe) {
	SetSeed(to_ZZ((long)time(0) + (long)clock()));
	y = El.get_pk();
	mod = El.get_group().get_mod();
	ord = El.get_group().get_ord();
	g = El.get_group().get_g();
	h = El.get_group().get_gen();
}
//生成密文( h^r , g^m × y^r )
void CipherGen::gen(array<Cipher_elg, 32>& Ciphertext, array<ZZ, 32>& Plaintext, ZZ& RanZero, array<ZZ, 32>& Ran) {
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
void CipherGen::prove() {
	clock_t tstart = clock();
	string fileName = "proveCipher" + codes[0] + "-R" + round + ".txt";
	//生成证明
	Commitment com(codes, round, plaintext, ciphertext, ran_1, bigMe, fileName);
	com.cipherCommit();//生成本轮密文正确性证明
	//交换证明
	/*string fileName1 = "proveCipher" + codes[1] + "-R" + round + ".txt";
	if (bigMe) {
		net.fSend(fileName);
		net.fReceive(fileName1);
	}
	else {
		net.fReceive(fileName1);
		net.fSend(fileName);
	}*/
	if (stoi(round) > 1) {
		//读入上一轮的公钥,密文
		fileName = "ciphertext" + codes[0] + "-R" + to_string(stoi(round) - 1) + ".txt";
		ist.open(fileName, ios::in);
		if (!ist) {
			cout << "Can't open " << fileName << endl;
			exit(1);
		}
		string container;
		ist >> container;
		y_1.toModP(container, mod);
		for (int i = 0; i < cipherNum; i++) {
			ist >> ciphertext_2[i];
		}
		ist.close();
		//读入上一轮的随机数
		fileName = "ran" + codes[0] + "-R" + to_string(stoi(round) - 1) + ".txt";
		ist.open(fileName, ios::in);
		if (!ist) {
			cout << "Can't open " << fileName << endl;
			exit(1);
		}
		for (int i = 0; i < cipherNum; i++) {
			ist >> ran_2[i];
		}
		ist.close();
		//生成证明
		fileName = "proveConsistency" + codes[0] + "-R" + round + ".txt";
		Commitment com2(codes, round, plaintext, ciphertext, ciphertext_2, ran_1, ran_2, y_1, bigMe, fileName);
		com2.ciphertextConsistencyCommit();
		//交换证明
		/*fileName1 = "proveConsistency" + codes[1] + "-R" + round + ".txt";
		if (bigMe) {
			net.fSend(fileName);
			net.fReceive(fileName1);
		}
		else {
			net.fReceive(fileName1);
			net.fSend(fileName);
		}*/
	}

	clock_t tstop = clock();
	double ttime = (tstop - tstart) / (double)CLOCKS_PER_SEC * 1000;
	cout << "[" << codes[0] << "] - " << "prove ciphertext " << ttime << " ms" << endl;
}
//验证证明
bool CipherGen::verify() {
	clock_t tstart = clock();
	int index = 0;
	/*if (!vMode)
		index = 1;*/

	bool flag = true;
	//读入密文
	string fileName = "ciphertext" + codes[index] + "-R" + round + ".txt";
	ist.open(fileName, ios::in);
	if (!ist) {
		cout << "Can't open " << fileName << endl;
		exit(1);
	}
	string container;
	ist >> container;
	y.toModP(container, H.get_mod());
	for (int i = 0; i < cipherNum; i++) {
		ist >> ciphertext[i];
	}
	ist.close();
	//读入证明
	fileName = "proveCipher" + codes[index] + "-R" + round + ".txt";
	Commitment com(codes, round, ciphertext, bigMe, fileName);
	flag &= com.cipherCheck();

	if (stoi(round) > 1) {
		//读入上一轮的公钥,密文
		fileName = "ciphertext" + codes[index] + "-R" + to_string(stoi(round) - 1) + ".txt";
		ist.open(fileName, ios::in);
		if (!ist) {
			cout << "Can't open " << fileName << endl;
			exit(1);
		}
		ist >> container;
		y_1.toModP(container, mod);
		for (int i = 0; i < cipherNum; i++) {
			ist >> ciphertext_2[i];
		}
		ist.close();
		fileName = "proveConsistency" + codes[index] + "-R" + round + ".txt";
		Commitment com2(codes, round, ciphertext, ciphertext_2, y, y_1, bigMe, fileName);
		flag &= com2.ciphertextConsistencyCheck();//生成本轮密文正确性证明
	}

	clock_t tstop = clock();
	double ttime = (tstop - tstart) / (double)CLOCKS_PER_SEC * 1000;
	cout << "[" << codes[0] << "] - " << "verify ciphertext " << ttime << " ms" << endl;
	return flag;
}
//读取明文
void CipherGen::readPlaintext() {
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
void CipherGen::createCipher() {
	string fileName = "ciphertext" + codes[0] + "-R" + round + ".txt";
	ost.open(fileName, ios::out);
	if (!ost) {
		cout << "Can't create " << fileName << endl;
		exit(1);
	}
	stringstream ss;
	ost << El.get_pk() << endl;//输出主密钥
	ss << El.get_pk() << ";";
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
	fileName = "ciphertext" + codes[1] + "-R" + round + ".txt";
	ost.open(fileName, ios::out);
	if (!ost)
	{
		cout << "Can't create " << fileName << endl;
		exit(1);
	}
	for (int i = 0; i < ciphertext_2_str.size(); i++)
		ost << ciphertext_2_str[i] << endl;
	ost.close();
	//保存随机数，下一轮生成密文一致性证明使用
	fileName = "ran" + codes[0] + "-R" + round + ".txt";
	ost.open(fileName, ios::out);
	if (!ost)
	{
		cout << "Can't create " << fileName << endl;
		exit(1);
	}
	for (int i = 0; i < ran_1.size(); i++)
		ost << ran_1[i] << endl;
	ost.close();
}