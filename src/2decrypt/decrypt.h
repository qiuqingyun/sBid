#pragma once
#include "../global.h"
extern G_q G;               // group used for the Pedersen commitment
extern G_q H;               // group used for the the encryption
extern ElGamal El;         // The class for encryption and decryption
extern Network net;

class Decrypt {
private:
	ifstream ist;
	ofstream ost;
	array<string, 2> codes;//�Լ��ͶԷ��ı�ţ���һ�����Լ��ģ��ڶ����ǶԷ���
	string codeBig, codeSmall;
	array<Cipher_elg, 32> ciphertext;	 //�������ֻ���������
	array<ZZ, 32> dk_1;    //�Լ��Ľ��ܷݶ�
	array<ZZ, 32> dk_2;  //�Է��Ľ��ܷݶ�
	array<ZZ, 32> c2;
	string ans[2] = { "FAIL","PASS" };
	int cipherNum = 32;
	bool bigMe;
	ZZ mod;
	ZZ ord;
	ZZ sk;
	Mod_p g;
	Mod_p h;
	Mod_p y;

	//��ȡ�������ֻ���������
	void readCipherShuffled() {
		string fileName = "cipherSR" + codeBig + ".txt";
		ist.open(fileName, ios::in);
		if (!ist) {
			cout << "Can't open " << fileName << endl;
			exit(1);
		}
		for (int i = 0; i < cipherNum; i++) {
			ist >> ciphertext[i];
		}
		ist.close();
	}
	//�������ܷݶ�
	void createDk() {
		string fileName = "dk" + codes[0] + ".txt";
		ost.open(fileName, ios::out);
		if (!ost) {
			cout << "Can't create " << fileName << endl;
			exit(1);
		}
		stringstream ss;
		for (int i = 0; i < cipherNum; i++) {
			c2[i] = ciphertext[i].get_u();
			dk_1[i] = PowerMod(c2[i], sk, mod);
			ost << dk_1[i] << endl;
			ss << dk_1[i] << ";";
		}
		ost.close();

		string cipher_1, cipher_2;
		ss >> cipher_1;
		if (bigMe) {//����Ƚ����ٷ���
			net.mReceive(cipher_2);
			net.mSend(cipher_1);
		}
		else {//С���ȷ����ٽ���
			net.mSend(cipher_1);
			net.mReceive(cipher_2);
		}
		vector<string> ciphertext_2_str;
		net.deserialization(cipher_2, ciphertext_2_str);
		//����
		fileName = "dk" + codes[1] + ".txt";
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
	//��ȡ�Է��Ľ��ܷݶ�
	void readDk() {
		string fileName = "dk" + codes[1] + ".txt";
		ist.open(fileName, ios::in);
		if (!ist) {
			cout << "Can't open " << fileName << endl;
			exit(1);
		}
		for (int i = 0; i < cipherNum; i++) {
			ist >> dk_2[i];
		}
		ist.close();
	}
	//������
	int outputAns() {
		int result = 0, flag = 0;
		for (int i = 0; i < cipherNum; i++)
		{
			ZZ dk = MulMod(dk_1[i], dk_2[i], mod);//�ӷ�̬ͬ
			ZZ dk_inv = InvMod(dk, mod);//ȡ��
			ZZ ans = El.get_m(MulMod(ciphertext[i].get_v(), dk_inv, mod));//����
			if (ans == 0)
			{//���ʤ

				return 0;
			}
			else if (ans == 1)
			{//ƽ��
				flag++;
			}
		}
		if (flag == cipherNum)

			return 1;
		return 2;

	}
public:
	Decrypt(array<string, 2> codes, string codeBig, string codeSmall, bool bigMe) :codes(codes), codeBig(codeBig), codeSmall(codeSmall), bigMe(bigMe) {
		SetSeed(to_ZZ((long)time(0) + (long)clock()));
		y = El.get_pk();
		mod = El.get_group().get_mod();
		ord = El.get_group().get_ord();
		g = El.get_group().get_g();
		h = El.get_group().get_gen();
		sk = El.get_sk();
	}
	int decrypt() {
		readCipherShuffled();
		createDk();
		readDk();
		return outputAns();
	}
	void prove() {
		clock_t tstart = clock();
		string fileName = "proveDecrypt" + codes[0] + ".txt";
		ost.open(fileName, ios::out);
		if (!ost)
		{
			cout << "Can't create " << fileName << endl;
			exit(1);
		}
		//����֤��
		Commitment com(codes, c2, dk_1, bigMe, fileName);
		com.decryptCommit();

		ost.close();
		clock_t tstop = clock();
		double ttime = (tstop - tstart) / (double)CLOCKS_PER_SEC * 1000;
		cout << "[" << codes[0] << "] - " << "prove decrypt " << ttime << " ms" << endl;
	}

	bool verify() {
		clock_t tstart = clock();
		bool flag = true;
		//��������
		string fileName = "cipherSR" + codeBig + ".txt";
		ist.open(fileName, ios::in);
		if (!ist) {
			cout << "Can't open " << fileName << endl;
			exit(1);
		}
		for (int i = 0; i < cipherNum; i++) {
			ist >> ciphertext[i];
		}
		ist.close();
		//����֤��
		fileName = "proveDecrypt" + codes[0] + ".txt";
		ist.open(fileName, ios::in);
		if (!ist)
		{
			cout << "Can't open " << fileName << endl;
			exit(1);
		}

		//��֤֤��
		Commitment com(codes, ciphertext, bigMe, fileName);
		flag &= com.decryptCheck();

		ist.close();
		clock_t tstop = clock();
		double ttime = (tstop - tstart) / (double)CLOCKS_PER_SEC * 1000;
		cout << "[" << codes[0] << "] - " << "verify decrypt " << ttime << " ms" << endl;
		return flag;
	}
};