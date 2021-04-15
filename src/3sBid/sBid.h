#pragma once
#include "../2shuffle/shuffle.h"
#include "../2paraGen/paraGen.h"
extern G_q G;               // group used for the Pedersen commitment
extern G_q H;               // group used for the the encryption
extern ElGamal El;         // The class for encryption and decryption
//A 00111000100001101100100001110110 948357238
//B 00111000100101101100100001110110 949405814
class SBid {
private:
	ifstream ist;
	ofstream ost;
	array<string, 2> codes;//�Լ��ͶԷ��ı�ţ���һ�����Լ��ģ��ڶ����ǶԷ���
	string pkFileName;
	string coCode;
	bitset<32> plaintext;//���۶���������
	array<Cipher_elg, 32> ciphertext;    //ԭʼ���������
	ZZ mod;
	ZZ ord;
	ZZ gen_h;
	ZZ gen_g;
	int cipherNum = 32;
	int pBits = 100;
	int qBits = 90;

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
		ist >> gen_h;
		ist >> gen_g;
		ist.close();
		H = G_q(gen_h, ord, mod); //����Ԫh ����q ģ��p
		G = G_q(gen_h, ord, mod);
		H.set_g(gen_g);
	}
	//���ó�ʼ��ElGamal
	void creatElGamal() {
		El.set_group(H);
		string fileName = "pk" + codes[0] + ".txt";
		ist.open(fileName, ios::in);
		if (!ist)
		{//���ɹ�˽Կ
			cout << fileName << " does not exist, a new key will be generated" << endl;
			ZZ x = RandomBnd(H.get_ord());//�������˽Կ
			El.set_sk(x);//���ɹ�Կ
			//�����˽Կ
			ost.open(fileName, ios::out);
			if (!ost)
			{
				cout << "Can't creat " << fileName << endl;
				exit(1);
			}
			ost << El.get_pk_1() << endl;
			ost.close();
			fileName = "sk" + codes[0] + ".txt";
			ost.open(fileName, ios::out);
			if (!ost)
			{
				cout << "Can't creat " << fileName << endl;
				exit(1);
			}
			ost << El.get_sk() << endl;
			ost.close();
		}
		else
		{//��ȡ��˽Կ
			ZZ sk, pk;
			string sk_str, pk_str;
			getline(ist, pk_str);
			conv(pk, pk_str.c_str());
			ist.close();
			fileName = "sk" + codes[0] + ".txt";
			ist.open(fileName, ios::in);
			if (!ist)
			{
				cout << "Can't open " << fileName << endl;
				exit(1);
			}
			getline(ist, sk_str);
			conv(sk, sk_str.c_str());
			El.set_key(sk, pk);
			ist.close();
		}
		//TODO:�����ɵĹ�Կ���ݸ��Է�
		//��������Կ
		fileName = "pk" + codes[1] + ".txt";
		ist.open(fileName, ios::in);
		if (!ist)
		{
			cout << "Can't open " << fileName << endl;
			exit(1);
		}
		string pk_2_str;
		ist >> pk_2_str;
		ist.close();
		El.keyGen(pk_2_str);
		//�������Կ
		int suffixFlag = (codes[0] < codes[1]);
		coCode = codes[!suffixFlag] + "-" + codes[suffixFlag];
		fileName = "pk" + coCode + ".txt";
		pkFileName = fileName;
		ost.open(fileName, ios::out);
		if (!ist)
		{
			cout << "Can't creat " << fileName << endl;
			exit(1);
		}
		ost << El.get_pk() << endl;
		ost.close();
	}
	//��ȡ����
	void readPlaintext() {
		string fileName = "plaintext" + codes[0] + ".txt";
		ist.open(fileName, ios::in);
		if (!ist) {
			cout << "Can't open " << fileName << endl;
			exit(1);
		}
		ist >> plaintext;
		ist.close();
	}
	//��������
	void createCipher() {
		string fileName = "ciphertext" + codes[0] + ".txt";
		ost.open(fileName, ios::out);
		if (!ost) {
			cout << "Can't creat " << fileName << endl;
			exit(1);
		}
		for (int i = 0; i < cipherNum; i++)
		{
			ZZ m;
			ZZ r = RandomBnd(ord);						//�����r��Ҳ��������ʱ��Կ
			conv(m, plaintext[i]);						//����m
			m = PowerMod(H.get_g().get_val(), m, mod);  //g^m
			//cout << m <<" | "<< H.get_g().get_val()<< endl;
			Cipher_elg temp = El.encrypt(m, r);			//�õ�(u,v)�����飬u = h^r��v = g^m��y^r��yΪ��Կ
			ciphertext[i] = temp;
			ost << temp << endl;
		}
		ost.close();
	}

public:
	//���ɲ���
	void parametersGen() {
		ParaGen paraGen;
		paraGen.parametersGen(pBits, qBits);
	}
	//����׼������
	void prepare(array<int, 2> codes_in) {
		codes[0] = to_string(codes_in[0]);//�Լ��ı��
		codes[1] = to_string(codes_in[1]);//�Է��ı��
		readParameters();
		creatElGamal();
		readPlaintext();
		createCipher();
	}
	//TODO:�Ƚ�

	//����
	void shuffleOp() {
		Shuffle prover(coCode);
		prover.creatProver();
		prover.shuffle();
		prover.prove();
		
	}
	void shuffleOp2() {
		//test
		Shuffle verifier(coCode);
		verifier.creatVerifier();
		verifier.verify();
	}

	//TODO:����
};