#pragma once
#include "../2paraGen/paraGen.h"
#include "../2cipherGen/cipherGen.h"
#include "../2compare/compare.h"
#include "../2shuffle/shuffle.h"
#include "../2decrypt/decrypt.h"
extern G_q G;               // group used for the Pedersen commitment
extern G_q H;               // group used for the the encryption
extern ElGamal El;         // The class for encryption and decryption
extern Network net;
class SBid {
private:
	ifstream ist;
	ofstream ost;
	array<string, 2> codes;//�Լ��ͶԷ��ı�ţ���һ�����Լ��ģ��ڶ����ǶԷ���
	string codeBig, codeSmall;
	string pkFileName;
	string coCode;
	array<ZZ, 32> plaintext;//���۶���������
	array<Cipher_elg, 32> ciphertext;    //����
	array<ZZ, 32> ran_1;//���ܵ������
	array<Cipher_elg, 32> cipherAns;	 //�������ֻ���������
	array<ZZ, 32> dk_1;    //�Լ��Ľ��ܷݶ�
	array<ZZ, 32> dk_2;  //�Է��Ľ��ܷݶ�]
	CipherGen* cipherGen;
	ZZ ranZero;
	string ans[2] = { "FAIL","PASS" };
	bool bigMe;
	ZZ mod;
	ZZ ord;
	ZZ gen_h;
	ZZ gen_g;
	ZZ sk, pk;
	int plaintext_int;
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
		G.set_g(gen_g);
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
				cout << "Can't create " << fileName << endl;
				exit(1);
			}
			ost << El.get_pk_1() << endl;
			ost.close();
			fileName = "sk" + codes[0] + ".txt";
			ost.open(fileName, ios::out);
			if (!ost)
			{
				cout << "Can't create " << fileName << endl;
				exit(1);
			}
			ost << El.get_sk() << endl;
			ost.close();
		}
		else
		{//��ȡ��˽Կ
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
		//�����ɵĹ�Կ���ݸ��Է�
		string pk_1, pk_2;
		stringstream ss;
		ss << El.get_pk_1();
		ss >> pk_1;
		if (bigMe) {
			net.mSend(pk_1);
			net.mReceive(pk_2);
		}
		else {
			net.mReceive(pk_2);
			net.mSend(pk_1);
		}
		fileName = "pk" + codes[1] + ".txt";
		ost.open(fileName, ios::out);
		if (!ost)
		{
			cout << "Can't create " << fileName << endl;
			exit(1);
		}
		ost << pk_2 << endl;
		ost.close();
		//��������Կ
		El.keyGen(pk_2);
		//�������Կ
		int suffixFlag = (codes[0] < codes[1]);
		coCode = codes[!suffixFlag] + "-" + codes[suffixFlag];
		fileName = "pk" + coCode + ".txt";
		pkFileName = fileName;
		ost.open(fileName, ios::out);
		if (!ost)
		{
			cout << "Can't create " << fileName << endl;
			exit(1);
		}
		ost << El.get_pk() << endl;
		ost.close();
	}
	//���ܲ�����֤��
	void ciphertextOp() {
		CipherGen* cipherGen = new CipherGen(codes, bigMe);
		cipherGen->gen(ciphertext, plaintext, ranZero, ran_1);//��������( h^r , g^m �� y^r )
		cipherGen->prove();//��������֤��
	}
	//��֤����
	void ciphertextVerify() {
		CipherGen* cipherVerify = new CipherGen(codes, bigMe);
		bool flag = cipherVerify->verify();
		cout << "[" << codes[0] << "] - " << "ciphertext results: " << ans[flag] << endl;
	}
	//�Ƚϲ�����֤��
	void compareOp() {
		Compare compare(codes, plaintext, ciphertext, ran_1, ranZero, bigMe);
		compare.compare();
		compare.prove();
	}
	//��֤�Ƚ�
	void compareVerify() {
		Compare compare(codes, ciphertext, bigMe);
		bool flag = compare.verify();
		cout << "[" << codes[0] << "] - " << "compare results: " << ans[flag] << endl;
	}
	//����������֤��
	void shuffleOp() {
		Shuffle prover(codes, coCode);
		prover.creatProver(bigMe);
		prover.shuffle();
		prover.prove();
	}
	//��֤����
	void shuffleVerify() {
		Shuffle verifier(codes, coCode);
		verifier.creatVerifier();
		bool flag = verifier.verify();
		cout << "[" << codes[0] << "] - " << "shuffle results: " << ans[flag] << endl;
	}

	//���ܲ�����֤��
	void decryptOp() {
		Decrypt decrypt(codes, codeBig, codeSmall, bigMe);
		int ans = decrypt.decrypt();
		decrypt.prove();
		switch (ans)
		{
			case 0:
				cout << "[" << codes[0] << "] - Winner No." << codeSmall << endl;
				break;
			case 1:
				cout << "[" << codes[0] << "] - - Winner DRAW" << endl;
				break;
			case 2:
				cout << "[" << codes[0] << "] - Winner No." << codeBig << endl;
				break;
			default:
				break;
		}
	}
	//��֤����
	void decryptVerify() {
		Decrypt decrypt(codes, codeBig, codeSmall, bigMe);
		bool flag = decrypt.verify();
		cout << "[" << codes[0] << "] - " << "decrypt results: " << ans[flag] << endl;
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
		codeBig = (stoi(codes[0]) > stoi(codes[1])) ? codes[0] : codes[1];
		codeSmall = (stoi(codes[0]) < stoi(codes[1])) ? codes[0] : codes[1];
		bigMe = codes_in[0] > codes_in[1];
		int port = 20200;
		if (bigMe)
			port += codes_in[0];
		else
			port += codes_in[1];
		net.init(codes[0], bigMe, port);
		readParameters();
		creatElGamal();
		ciphertextOp();
	}
	//��ʼ����
	void bid() {
		compareOp();
		shuffleOp();
		decryptOp();
	}
	//��֤
	void verify() {
		cout << "[" << codes[0] << "] - " << "=====Verify=====" << endl;
		ciphertextVerify();
		compareVerify();
		shuffleVerify();
		decryptVerify();
		cout << "[" << codes[0] << "] - " << "======OVER======" << endl;
	}
};