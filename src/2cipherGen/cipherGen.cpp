#include "cipherGen.h"

CipherGen::CipherGen(array<string, 2> codes, string round, bool bigMe) :codes(codes), round(round), bigMe(bigMe) {
	SetSeed(to_ZZ((long)time(0) + (long)clock()));
	y = El.get_pk();
	mod = El.get_group().get_mod();
	ord = El.get_group().get_ord();
	g = El.get_group().get_g();
	h = El.get_group().get_gen();
}

CipherGen::CipherGen(array<string, 2> codes) :codes(codes) {
	SetSeed(to_ZZ((long)time(0) + (long)clock()));
	y = El.get_pk();
	mod = El.get_group().get_mod();
	ord = El.get_group().get_ord();
	g = El.get_group().get_g();
	h = El.get_group().get_gen();
}

//��ȡ���Ĳ���˽�й�Կ���ܣ���������
void CipherGen::chainPrepare() {
	readPlaintext();
	//��������ʮ���ƽ���������
	string fileName = filesPath + "cipherAmount" + codes[0] + ".txt";
	ost.open(fileName, ios::out);
	if (!ost) {
		cout << "[" << codes[0] << "] - " << "Can't create " << fileName << endl;
		exit(1);
	}
	Cipher_elg cipher_amount = El.encrypt(amount);
	ost << cipher_amount << endl;//�������
	ost.close();
	net.fSend(fileName);
}
//��������( h^r , g^m �� y^r )
void CipherGen::gen(array<Cipher_elg, 32>& Ciphertext, array<ZZ, 32>& Plaintext, ZZ& RanZero, array<ZZ, 32>& Ran) {
	readPlaintext();
	createCipher();
	Ciphertext = ciphertext;
	Plaintext = plaintext;
	RanZero = ranZero;
	Ran = ran_1;
	//return ciphertext;
}
//��ȡ����
void CipherGen::readPlaintext() {
	int plaintext_int;
	bitset<32> plaintext_inv;
	//��ȡ���Ľ��
	string fileName = filesPath + "plaintext_int" + codes[0] + ".txt";
	ist.open(fileName, ios::in);
	waitFile(fileName, ist);
	if (!ist) {
		cout << "[" << codes[0] << "] - " << "Can't open " << fileName << endl;
		exit(1);
	}
	ist >> plaintext_int;
	amount = ZZ(plaintext_int);
	cout << "[" << codes[0] << "] - " << "Amount: " << amount << endl;
	plaintext_inv = plaintext_int;
	ist.close();
	//fileName = "plaintext" + codes[0] + ".txt";
	//��ת������ֵ
	for (int i = 0; i < cipherNum; i++) {
		plaintext[i] = ZZ(plaintext_inv[cipherNum - i - 1]);
		//cout << plaintext[i];
	}
	//cout << endl;
}
//�������Ĳ���ȡ�Է����ɵ�����
void CipherGen::createCipher() {
	string fileName = filesPath + "ciphertext" + codes[0] + "-R" + round + ".txt";
	ost.open(fileName, ios::out);
	if (!ost) {
		cout << "[" << codes[0] << "] - " << "Can't create " << fileName << endl;
		exit(1);
	}
	stringstream ss;
	ost << El.get_pk() << endl;//�������Կ
	ss << El.get_pk() << ";";
	for (int i = 0; i < cipherNum; i++)
	{
		ran_1[i] = RandomBnd(ord);								 //�����r��Ҳ��������ʱ��Կ
		Cipher_elg temp = El.encrypt_g(ZZ(plaintext[i]), ran_1[i]);//�õ�(u,v)�����飬u = h^r��v = g^m��y^r��yΪ��Կ
		ciphertext[i] = temp;									 //˳�����
		ost << temp << endl;										 //�������
		ss << temp << ";";
	}
	//����0
	ranZero = RandomBnd(ord);					  //�����r
	ciphertextZero = El.encrypt_g(ZZ(0), ranZero);//�õ�(h^r,y^r)������
	ost << ciphertextZero << endl;
	ss << ciphertextZero << ";";
	ost.close();
	//��ȡ�Է����ɵ�����
	string cipher;
	//NOTE: ��java�������ȷ��ͺ����
	string fileName1 = filesPath + "ciphertext" + codes[1] + "-R" + round + ".txt";
	if (bigMe) {
		net.fSend(fileName);
		net.fReceive(fileName1);
	}
	else {
		net.fReceive(fileName1);
		net.fSend(fileName);
	}
	/*
	vector<string> ciphertext_2_str;
	net.deserialization(cipher, ciphertext_2_str);
	fileName = filesPath + "ciphertext" + codes[1] + "-R" + round + ".txt";
	ost.open(fileName, ios::out);
	if (!ost)
	{
		cout << "[" << codes[0] << "] - " << "Can't create " << fileName << endl;
		exit(1);
	}
	for (int i = 0; i < ciphertext_2_str.size(); i++)
		ost << ciphertext_2_str[i] << endl;
	ost.close();*/
	//�������������һ����������һ����֤��ʹ��
	fileName = filesPath + "ran" + codes[0] + "-R" + round + ".txt";
	ost.open(fileName, ios::out);
	if (!ost)
	{
		cout << "[" << codes[0] << "] - " << "Can't create " << fileName << endl;
		exit(1);
	}
	for (int i = 0; i < ran_1.size(); i++)
		ost << ran_1[i] << endl;
	ost.close();
}
//����֤��
void CipherGen::prove() {
	//����֤��
	string fileName = filesPath + "proveCipher" + codes[0] + "-R" + round + ".txt";
	Commitment com(codes, round, plaintext, ciphertext, ran_1, bigMe, fileName);
	com.cipherCommit();//���ɱ���������ȷ��֤��
	//����֤��
	string fileName1 = filesPath + "proveCipher" + codes[1] + "-R" + round + ".txt";
	//NOTE: ��java�������ȷ��ͺ����
	if (bigMe) {
		net.fSend(fileName);
		net.fReceive(fileName1);
	}
	else {
		net.fReceive(fileName1);
		net.fSend(fileName);
	}
}
//����֤��
void CipherGen::proveConsistency(string lastFinishRoundMe, string lastFinishRoundOp) {
	//��������һ����֤��
	if (lastFinishRoundMe.compare("0") != 0) {
		//������һ�β��뾺�����ɵ�����
		string fileName = filesPath + "ciphertext" + codes[0] + "-R" + lastFinishRoundMe + ".txt";
		ist.open(fileName, ios::in);
		if (!ist) {
			cout << "[" << codes[0] << "] - " << "Can't open " << fileName << endl;
			exit(1);
		}
		string container;
		ist >> container;
		y_1.toModP(container, mod);
		for (int i = 0; i < cipherNum; i++) {
			ist >> ciphertext_2[i];
		}
		ist.close();
		//������һ�ֵ������
		fileName = filesPath + "ran" + codes[0] + "-R" + lastFinishRoundMe + ".txt";
		ist.open(fileName, ios::in);
		if (!ist) {
			cout << "[" << codes[0] << "] - " << "Can't open " << fileName << endl;
			exit(1);
		}
		for (int i = 0; i < cipherNum; i++) {
			ist >> ran_2[i];
		}
		ist.close();
		//����֤��
		fileName = filesPath + "proveConsistency" + codes[0] + "-R" + round + ".txt";
		Commitment com2(codes, round, plaintext, ciphertext, ciphertext_2, ran_1, ran_2, y_1, bigMe, fileName);
		com2.ciphertextConsistencyCommit();
		//����֤��
		//NOTE: ��java�������ȷ��ͺ����
		net.fSend(fileName);
	}
	if (lastFinishRoundOp.compare("0") != 0) {
		string fileName = filesPath + "ciphertext" + codes[1] + "-R" + lastFinishRoundOp + ".txt";
		net.fReceive(fileName);
		fileName = filesPath + "proveConsistency" + codes[1] + "-R" + round + ".txt";
		net.fReceive(fileName);
	}
}
//��֤֤��
bool CipherGen::verify() {
	int index = 0;
	if (!vMode)
		index = 1;

	bool flag = true;
	//��������
	string fileName = filesPath + "ciphertext" + codes[index] + "-R" + round + ".txt";
	ist.open(fileName, ios::in);
	waitFile(fileName, ist);
	if (!ist) {
		cout << "[" << codes[0] << "] - " << "Can't open " << fileName << endl;
		exit(1);
	}
	string container;
	ist >> container;
	y.toModP(container, H.get_mod());
	for (int i = 0; i < cipherNum; i++) {
		ist >> ciphertext[i];
	}
	ist.close();
	//����֤��
	fileName = filesPath + "proveCipher" + codes[index] + "-R" + round + ".txt";
	Commitment com(codes, round, ciphertext, bigMe, fileName);
	flag &= com.cipherCheck();
	return flag;
}
//��֤֤��
bool CipherGen::verifyConsistency(string lastFinishRoundOp) {
	//����һ������֤
	int index = 0;
	if (!vMode)
		index = 1;

	bool flag = true;
	if (lastFinishRoundOp.compare("0") != 0) {
		//��ȡ�Է���һ�β��뾺�����ɵ�����
		string fileName = filesPath + "ciphertext" + codes[index] + "-R" + lastFinishRoundOp + ".txt";
		ist.open(fileName, ios::in);
		if (!ist) {
			cout << "[" << codes[0] << "] - " << "Can't open " << fileName << endl;
			exit(1);
		}
		string container;
		ist >> container;
		y_1.toModP(container, mod);
		for (int i = 0; i < cipherNum; i++) {
			ist >> ciphertext_2[i];
		}
		ist.close();
		//����֤��
		fileName = filesPath + "proveConsistency" + codes[index] + "-R" + round + ".txt";
		Commitment com2(codes, round, ciphertext, ciphertext_2, y, y_1, bigMe, fileName);
		flag &= com2.ciphertextConsistencyCheck();//���ɱ���������ȷ��֤��
	}
	return flag;
}
