#include "sBid.h"

//���ɲ���
void SBid::parametersGen() {
	ParaGen paraGen;
	paraGen.parametersGen(pBits, qBits);
}
//����׼������
void SBid::prepare(array<int, 3> codes_in) {
	codes[0] = to_string(codes_in[0]);//�Լ��ı��
	codes[1] = to_string(codes_in[1]);//�Է��ı��
	round = to_string(codes_in[2]);//����
	codeBig = (stoi(codes[0]) > stoi(codes[1])) ? codes[0] : codes[1];
	codeSmall = (stoi(codes[0]) < stoi(codes[1])) ? codes[0] : codes[1];
	bigMe = codes_in[0] > codes_in[1];
	readParameters();
	cout << "\n[" << codes[0] << "] - No." << codes[0] << " vs No." << codes[1] << " - Round: " << round << endl;
	int port = 20202;
	if (bigMe)
		port += stoi(codes[0]) * 100 + stoi(round);
	else
		port += stoi(codes[1]) * 100 + stoi(round);
	net.init(codes[0], bigMe, port);
}
//��ʼ����
void SBid::bid() {
	creatElGamal();
	pkExchange();
	ciphertextOp();
	compareOp();
	shuffleOp();
	decryptOp();
}
//��֤
void SBid::verify() {
	cout << "[" << codes[0] << "] - " << "===============Verify===============" << endl;
	bool flag = true;
	flag &= ciphertextVerify();
	flag &= compareVerify();
	flag &= shuffleVerify();
	flag &= decryptVerify();
	cout << "[" << codes[0] << "] - " << "Verify results: " << ans[flag] << endl;
	cout << "[" << codes[0] << "] - " << "================OVER================" << endl;
}
//��ȡȺ�Ĳ���������Ⱥ
void SBid::readParameters() {
	string fileName = "parameters.txt";
	ist.open(fileName, ios::in);
	if (!ist)
	{
		cout << "[" << codes[0] << "] - " << "Can't open " << fileName << endl;
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
int SBid::creatElGamal() {
	El.set_group(H);
	string fileName = "pk" + codes[0] + ".txt";
	ist.open(fileName, ios::in);
	if (!ist)
	{//���ɹ�˽Կ
		cout << "[" << codes[0] << "] - The key does not exist, a new key will be generated randomly" << endl;
		ZZ x = RandomBnd(H.get_ord());//�������˽Կ
		El.set_sk(x);//���ɹ�Կ
		//�����˽Կ
		ost.open(fileName, ios::out);
		if (!ost)
		{
			cout << "[" << codes[0] << "] - " << "Can't create " << fileName << endl;
			exit(1);
		}
		ost << El.get_pk_1() << endl;
		ost.close();
		fileName = "sk" + codes[0] + ".txt";
		ost.open(fileName, ios::out);
		if (!ost)
		{
			cout << "[" << codes[0] << "] - " << "Can't create " << fileName << endl;
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
			cout << "[" << codes[0] << "] - " << "Can't open " << fileName << endl;
			exit(1);
		}
		getline(ist, sk_str);
		conv(sk, sk_str.c_str());
		El.set_key(sk, pk);
		ist.close();
		return 1;
	}
	return 0;
}
//�����ɵĹ�Կ���ݸ��Է�
void SBid::pkExchange() {
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
	string fileName = "pk" + codes[1] + ".txt";
	ost.open(fileName, ios::out);
	if (!ost)
	{
		cout << "[" << codes[0] << "] - " << "Can't create " << fileName << endl;
		exit(1);
	}
	ost << pk_2 << endl;
	ost.close();
	//��������Կ
	El.keyGen(pk_2);
}
//���ܲ�����֤��
void SBid::ciphertextOp() {
	CipherGen cipherGen(codes, round, bigMe);
	if (round == "1")
		cipherGen.chainPrepare();
	cipherGen.gen(ciphertext, plaintext, ranZero, ran_1);//��������( h^r , g^m �� y^r )
	cipherGen.prove();//��������֤��
}
//��֤����
bool SBid::ciphertextVerify() {
	CipherGen cipherVerify(codes, round, bigMe);
	bool flag = cipherVerify.verify();
	return flag;
}
//�Ƚϲ�����֤��
void SBid::compareOp() {
	Compare compare(codes, round, plaintext, ciphertext, ran_1, ranZero, bigMe);
	compare.compare();
	compare.prove();
}
//��֤�Ƚ�
bool SBid::compareVerify() {
	Compare compare(codes, round, ciphertext, bigMe);
	bool flag = compare.verify();
	if ((bigMe && !vMode) || (!bigMe && vMode))//��Ų������Լ�С����֤��������
		return true;
	else
		return flag;
}
//����������֤��
void SBid::shuffleOp() {
	Shuffle prover(codes, round);
	prover.creatProver(bigMe);
	prover.shuffle();
	prover.prove();
}
//��֤����
bool SBid::shuffleVerify() {
	Shuffle verifier(codes, round);
	verifier.creatVerifier(bigMe);
	bool flag = verifier.verify();
	return flag;
}
//���ܲ�����֤��
void SBid::decryptOp() {
	Decrypt decrypt(codes, round, codeBig, codeSmall, bigMe);
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
bool SBid::decryptVerify() {
	Decrypt decrypt(codes, round, codeBig, codeSmall, bigMe);
	bool flag = decrypt.verify();
	return flag;
}
//��������
void SBid::decrypt(array<string, 3> paras) {
	codes[0] = paras[0];//�Լ��ı��
	readParameters();

	if (creatElGamal()) {
		string fileName = paras[1];
		ist.open(fileName, ios::in);
		if (!ist)
		{
			cout << "[" << codes[0] << "] - " << "Can't open " << fileName << endl;
			exit(1);
		}
		Cipher_elg cipher_amount;
		ist >> cipher_amount;
		ist.close();

		ZZ ans = El.decrypt(cipher_amount);
		cout << "[" << codes[0] << "] - " << "ciphertext amount: " << cipher_amount << endl;
		cout << "[" << codes[0] << "] - " << "plaintext  amount: " << ans << endl;

		fileName = paras[2];
		ost.open(fileName, ios::out);
		if (!ost)
		{
			cout << "[" << codes[0] << "] - " << "Can't create " << fileName << endl;
			exit(1);
		}
		ost << ans << endl;
		ost.close();
	}
	else {
		cout << "[" << codes[0] << "] - " << "Decryption error: Unable to read key file" << endl;
		exit(1);
	}
}