#pragma once
#include "../base/global.h"
#include "../shuffle/shuffle.h"

extern G_q G;               // group used for the Pedersen commitment
extern G_q H;               // group used for the the encryption

class SBid {
private:
	ifstream ist;
	ofstream ost;
	bitset<32> plaintext;
	ZZ mod;
	ZZ ord;
	ZZ gen;
	ZZ gen_g;
public:
	//��ȡȺ�Ĳ���������Ⱥ
	void readParameters() {
		string fileName = "parameters.txt";
		ist.open(fileName, ios::in);
		if (!ist)
		{
			cout << "Can't open " << fileName << endl;
			exit(1);
		}
		ist >> mod;
		ist >> ord;
		ist >> gen;
		ist >> gen_g;
		ist.close();
		H = G_q(gen, ord, mod); //����Ԫh ����q ģ��p
		G = G_q(gen, ord, mod);
	}
	//����ElGamal��˽Կ
	void creatElGamal() {
		El.set_group(H);
		string fileName = "ElGamal.txt";
		ist.open(fileName, ios::in);
		if (!ist)
		{
			cout << "Can't open " << fileName << endl;
			exit(1);
		}
		ZZ sk, pk;
		string sk_str, pk_str;
		getline(ist, sk_str);
		getline(ist, pk_str);
		conv(sk, sk_str.c_str());
		conv(pk, pk_str.c_str());
		El.set_key(sk, pk);
		ist.close();
	}
	//��������Կ
	//��ȡ����
	void readPlaintext() {
		string fileName = "plaintext_in.txt";
		ist.open(fileName, ios::in);
		if (!ist) {
			cout << "Can't open " << fileName << endl;
			exit(1);
		}
		ist >> plaintext;
		ist.close();
	}
	//��������
};