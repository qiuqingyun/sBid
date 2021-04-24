#include "compare.h"

Compare::Compare(array<string, 2> codes, string round, array<ZZ, 32> plaintext, array<Cipher_elg, 32> ciphertext, array<ZZ, 32> ran_1, ZZ ranZero, bool bigMe) :codes(codes), round(round), plaintext(plaintext), ciphertext(ciphertext), ran_1(ran_1), ranZero(ranZero), bigMe(bigMe) {
	SetSeed(to_ZZ((long)time(0) + (long)clock()));
	y = El.get_pk();
	mod = El.get_group().get_mod();
	ord = El.get_group().get_ord();
	g = El.get_group().get_g();
	h = El.get_group().get_gen();
}
Compare::Compare(array<string, 2> codes, string round, array<Cipher_elg, 32> ciphertext, bool bigMe) :codes(codes), round(round), ciphertext(ciphertext), bigMe(bigMe) {
	//SetSeed(to_ZZ((long)time(0) + (long)clock()));
	y = El.get_pk();
	mod = El.get_group().get_mod();
	ord = El.get_group().get_ord();
	g = El.get_group().get_g();
	h = El.get_group().get_gen();
}
//�Ƚ�
void Compare::compare() {
	readCipher();
	cmp();
}
//����֤��
void Compare::prove() {
	clock_t tstart = clock();
	string fileName = "proveCompare" + codes[0] + "-R" + round + ".txt";
	//����֤��
	Commitment com(codes, round, plaintext, ciphertext, ciphertext_2, ran_1, cipherZero, cipherZero_2, ranZero, bigMe, fileName);
	com.compareCommit();
	//����֤��
	/*string fileName1 = "proveCompare" + codes[1] + "-R" + round + ".txt";
	if (bigMe) {
		net.fSend(fileName);
		net.fReceive(fileName1);
	}
	else {
		net.fReceive(fileName1);
		net.fSend(fileName);
	}*/

	clock_t tstop = clock();
	double ttime = (tstop - tstart) / (double)CLOCKS_PER_SEC * 1000;
	cout << "[" << codes[0] << "] - " << "prove compare " << ttime << " ms" << endl;
}
//��֤֤��
bool Compare::verify() {
	clock_t tstart = clock();
	int index = 0;
	/*if (!vMode)
		index = 1;*/
	bool flag = true;
	//��������
	string fileName = "ciphertext" + codes[index] + "-R" + round + ".txt";
	ist.open(fileName, ios::in);
	if (!ist) {
		cout << "Can't open " << fileName << endl;
		exit(1);
	}
	string container;
	ist >> container;
	for (int i = 0; i < cipherNum; i++) {
		ist >> ciphertext[i];
	}
	ist >> cipherZero;
	ist.close();
	//����֤��
	fileName = "proveCompare" + codes[index] + "-R" + round + ".txt";
	ist.open(fileName, ios::in);
	if (!ist)
	{
		cout << "Can't open " << fileName << endl;
		exit(1);
	}

	//��֤֤��
	Commitment com(codes, round, ciphertext, bigMe, fileName);
	flag &= com.compareCheck(cipherZero);

	ist.close();
	clock_t tstop = clock();
	double ttime = (tstop - tstart) / (double)CLOCKS_PER_SEC * 1000;
	cout << "[" << codes[0] << "] - " << "verify compare " << ttime << " ms" << endl;
	return flag;
}
//��ȡ�Է�������
void Compare::readCipher() {
	string fileName = "ciphertext" + codes[1] + "-R" + round + ".txt";
	ist.open(fileName, ios::in);
	if (!ist) {
		cout << "Can't open " << fileName << endl;
		exit(1);
	}
	string temp;
	ist >> temp;
	for (int i = 0; i < cipherNum; i++)
		ist >> ciphertext_2[i];
	ist >> cipherZero_2;//��ȡ�Է���0����
	ist.close();
	fileName = "ciphertext" + codes[0] + "-R" + round + ".txt";
	ist.open(fileName, ios::in);
	if (!ist) {
		cout << "Can't open " << fileName << endl;
		exit(1);
	}
	ist >> temp;
	for (int i = 0; i < cipherNum; i++)
		ist >> temp;
	ist >> cipherZero;//��ȡ�Լ���0����
	ist.close();
}
//�Ӹߵ�����λ�Ƚ�
void Compare::cmp() {
	if (bigMe) {//��Ž��бȽϲ���������������͸�С��
		//clock_t tstart = clock();
		string fileName = "cipherCR" + codes[0] + "-R" + round + ".txt";
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
			aTb = Cipher_elg::expo(b, ZZ(plaintext[i]));//a*b ���Ĳ���
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
		/*clock_t  tstop = clock();
		double ttime = (tstop - tstart) / (double)CLOCKS_PER_SEC * 1000;
		cout << "[" << codes[0] << "] - " << "compare " << ttime << " ms" << endl;*/
		string CR;
		ss >> CR;
		net.mSend(CR);
	}
	else {//С�Ž��ձȽϽ��
		string CR;
		net.mReceive(CR);
		vector<string> CR_str;
		net.deserialization(CR, CR_str);
		string fileName = "cipherCR" + codes[1] + "-R" + round + ".txt";
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