#pragma once
#include "../2shuffle/shuffle.h"
#include "../2paraGen/paraGen.h"
extern G_q G;               // group used for the Pedersen commitment
extern G_q H;               // group used for the the encryption
extern ElGamal El;         // The class for encryption and decryption
//A 00111000100001101100100001110110 948357238 ��11,13λ��ͬ
//B 00111000100100101100100001110110 949143670
class SBid {
private:
	ifstream ist;
	ofstream ost;
	array<string, 2> codes;//�Լ��ͶԷ��ı�ţ���һ�����Լ��ģ��ڶ����ǶԷ���
	string codeBig, codeSmall;
	string pkFileName;
	string coCode;
	bitset<32> plaintext;//���۶���������
	array<Cipher_elg, 32> ciphertext;    //����
	array<Cipher_elg, 32> ciphertext_2;  //�Է�������
	array<Cipher_elg, 32> cipherAns;	 //�������ֻ���������
	array<Cipher_elg, 33> Wj;
	array<Cipher_elg, 32> compareResults;//�ȽϽ������
	array<ZZ, 32> dk_1;    //�Լ��Ľ��ܷݶ�
	array<ZZ, 32> dk_2;  //�Է��Ľ��ܷݶ�
	array<ZZ, 32> ans;    //�ܽ��ܷݶ�
	ZZ mod;
	ZZ ord;
	ZZ gen_h;
	ZZ gen_g;
	ZZ sk, pk;
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
			cout << "Can't create " << fileName << endl;
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
			cout << "Can't create " << fileName << endl;
			exit(1);
		}
		for (int i = cipherNum - 1; i >= 0; i--)
		{//�������
			ZZ r = RandomBnd(ord);							    //�����r��Ҳ��������ʱ��Կ
			Cipher_elg temp = El.encrypt_g(ZZ(plaintext[i]), r);//�õ�(u,v)�����飬u = h^r��v = g^m��y^r��yΪ��Կ
			ciphertext[cipherNum - i - 1] = temp;			    //˳�����
			ost << temp << endl;								//�������
		}
		ost.close();
	}
	//��ȡ�Է�������
	void readCipher() {
		string fileName = "ciphertext" + codes[1] + ".txt";
		ist.open(fileName, ios::in);
		if (!ist) {
			cout << "Can't open " << fileName << endl;
			exit(1);
		}
		for (int i = 0; i < cipherNum; i++) {
			ist >> ciphertext_2[i];
		}
		ist.close();
	}
	//��ȡ�������ֻ���������
	void readCipherShuffled() {
		codeBig = (codes[0] > codes[1]) ? codes[0] : codes[1];
		codeSmall = (codes[0] < codes[1]) ? codes[0] : codes[1];
		string fileName = "cipherSR" + codeBig + ".txt";
		ist.open(fileName, ios::in);
		if (!ist) {
			cout << "Can't open " << fileName << endl;
			exit(1);
		}
		for (int i = 0; i < cipherNum; i++) {
			ist >> cipherAns[i];
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
		for (int i = 0; i < cipherNum; i++) {
			ZZ u = cipherAns[i].get_u();
			dk_1[i] = PowerMod(u, sk, mod);
			ost << dk_1[i] << endl;
		}
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

public:
	~SBid() {

	}
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
	void bid() {
		compare();
		shuffleOp();
		prepareDecrypt();
		decrypt();
	}
	//�Ӹߵ�����λ�Ƚ�
	void compare() {
		readCipher();
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
		for (int i = 0; i < cipherNum; i++) {
			a = ciphertext[i];
			b = ciphertext_2[i];
			aPb = a * b;//a+b
			aTb = Cipher_elg::expo(b, ZZ(plaintext[cipherNum - i - 1]));//a*b ���Ĳ���
			twoTaTb = Cipher_elg::expo(aTb, ZZ(2));//2*a*b
			minus2TaTb = Cipher_elg::inverse(twoTaTb);//-2*a*b
			Wj[i + 1] = aPb * minus2TaTb;//a+b-2*a*b
			Wj_sum = Wj_sum * Wj[i];
			b_minus = Cipher_elg::inverse(b);//-b
			aMbM1 = a * b_minus * ONE;//a-b+1
			compareResults[i] = aMbM1 * Wj_sum;
			ost << compareResults[i] << endl;
		}
		ost.close();
		clock_t  tstop = clock();
		double ttime = (tstop - tstart) / (double)CLOCKS_PER_SEC * 1000;
		cout << "[" << codes[0] << "] - " << "compare " << ttime << " ms" << endl;
	}
	//����������֤��
	void shuffleOp() {
		Shuffle prover(codes, coCode);
		prover.creatProver();
		prover.shuffle();
		prover.prove();

	}
	//��֤����
	void shuffleVerify() {
		Shuffle verifier(codes, coCode);
		verifier.creatVerifier();
		verifier.verify();
	}
	//����׼��
	void prepareDecrypt() {
		readCipherShuffled();
		createDk();
	}
	//���ܲ�������,0Ϊ(С��)����(���)��1Ϊ(С��)С��(���)��2Ϊ(С��)����(���)
	void decrypt() {
		readDk();
		ZZ dk, dk_inv;
		int result;
		for (int i = 0; i < cipherNum; i++)
		{
			dk = MulMod(dk_1[i], dk_2[i], mod);//�ӷ�̬ͬ
			dk_inv = InvMod(dk, mod);//ȡ��
			ans[i] = El.get_m(MulMod(cipherAns[i].get_v(), dk_inv, mod));//����
			if (ans[i] == 0)
			{//���ʤ
				cout << "[" << codes[0] << "] - " << "No." << codeBig << " WIN" << endl;
				return;
			}
			else if (ans[i] == 1)
				continue;
			else
			{//С��ʤ
				cout << "[" << codes[0] << "] - " << "No." << codeSmall << " WIN" << endl;
				return;
			}
		}
		cout << "[" << codes[0] << "] - " << "DRAW" << endl;
	}
};