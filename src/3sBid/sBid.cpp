#include "sBid.h"

//���ɲ���
void SBid::parametersGen() {
	ParaGen paraGen;
	paraGen.parametersGen(pBits, qBits);
}
//������Կ��������������ע��
void SBid::registration(string code) {
	codes[0] = code;
	int port = 18000;
	port += stoi(codes[0]) * 100;
	cout << "[" << codes[0] << "] - port: " << port << endl;
	net.start(port);
	net.acceptConnect();
	readParameters();
	string fileName = filesPath + "plaintext_int" + codes[0] + ".txt";
	net.fReceive(fileName);
	creatElGamal();
	CipherGen cipherGen(codes);
	cipherGen.chainPrepare();//�ø��˹�Կ���ܵ�����( h^r , m��y_1^r )
}
//����׼������
void SBid::prepare(array<int, 6> codes_in) {
	codes[0] = to_string(codes_in[0]);//�Լ��ı��
	codes[1] = to_string(codes_in[1]);//�Է��ı��
	round = to_string(codes_in[2]);//����
	codeBig = (stoi(codes[0]) > stoi(codes[1])) ? codes[0] : codes[1];
	codeSmall = (stoi(codes[0]) < stoi(codes[1])) ? codes[0] : codes[1];
	bigMe = codes_in[0] > codes_in[1];
	lastFinishRoundMe = to_string(codes_in[3]);
	lastFinishRoundOp = to_string(codes_in[4]);
	strategyFlag = codes_in[5];
	cout << "[" << codes[0] << "] - No." << codes[0] << " vs No." << codes[1] << " - Round: " << round << endl;

	int port = 18000;
	if (bigMe)
		port += stoi(codes[0]) * 100 + stoi(round);
	else
		port += stoi(codes[0]) * 100 + stoi(round);
	cout << "[" << codes[0] << "] - port: " << port << endl;
	net.start(port);
	net.acceptConnect();
	readParameters();
}
//��ʼ����
void SBid::bid() {
	//creatElGamal();
	readElGamal();
	pkExchange();
	ciphertextOp();
	compareOp();
	shuffleOp();
	decryptOp();
}
//��֤
void SBid::verify() {
	cout << "[" << codes[0] << "] - " << "===========Verify===========" << endl;
	bool flag = true;
	flag &= ciphertextVerify();
	flag &= compareVerify();
	flag &= shuffleVerify();
	flag &= decryptVerify();
	cout << "[" << codes[0] << "] - " << "Verify results: " << ans[flag] << endl;
	cout << "[" << codes[0] << "] - " << "============OVER============" << endl;
}
//��ȡȺ�Ĳ���������Ⱥ
void SBid::readParameters() {
	filesPath = "./files_" + codes[0] + "/";
	if (access(filesPath.c_str(), 0))
		mkdir(filesPath.c_str(), S_IRWXU | S_IRWXG | S_IRWXO);
	string logPath = "./log";
	if (access(logPath.c_str(), 0))
		mkdir(logPath.c_str(), S_IRWXU | S_IRWXG | S_IRWXO);
	string fileName = filesPath + "parameters.txt";
	ist.open(fileName, ios::in);
	if (!ist) {
		net.fReceive(fileName);
		ist.open(fileName, ios::in);
	}
	//waitFile(fileName, ist);
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
//����ElGamal��˽Կ
int SBid::creatElGamal() {
	El.set_group(H);
	string fileName = filesPath + "pk" + codes[0] + ".txt";
	ist.open(fileName, ios::in);
	if (ist)
	{//��Կ����
		net.fSend(fileName);
		ZZ pk, sk;
		ist >> pk;
		ist.close();
		fileName = filesPath + "sk" + codes[0] + ".txt";
		ist.open(fileName, ios::in);
		if (ist)
		{//˽Կ����
			ist >> sk;
			cout << "[" << codes[0] << "] - " << "The key already exists " << fileName << endl;
			ist.close();
			El.set_key(sk, pk);
			return 1;
		}
	}
	ist.close();
	//���ɹ�˽Կ
	cout << "[" << codes[0] << "] - A new key will be generated randomly" << endl;
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
	net.fSend(fileName);
	fileName = filesPath + "sk" + codes[0] + ".txt";
	ost.open(fileName, ios::out);
	if (!ost)
	{
		cout << "[" << codes[0] << "] - " << "Can't create " << fileName << endl;
		exit(1);
	}
	ost << El.get_sk() << endl;
	ost.close();

	return 0;
}
//��ȡElGamal��˽Կ
int SBid::readElGamal() {
	//��ȡ��˽Կ
	El.set_group(H);
	string fileName = filesPath + "pk" + codes[0] + ".txt";
	ist.open(fileName, ios::in);
	if (!ist)
	{
		cout << "[" << codes[0] << "] - " << "Can't open " << fileName << endl;
		exit(1);
	}
	string sk_str, pk_str;
	getline(ist, pk_str);
	conv(pk, pk_str.c_str());
	ist.close();
	fileName = filesPath + "sk" + codes[0] + ".txt";
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
	return 0;
}
//�����ɵĹ�Կ���ݸ��Է�
void SBid::pkExchange() {
	string fileName = filesPath + "pk" + codes[0] + ".txt";
	string fileName1 = filesPath + "pk" + codes[1] + ".txt";

	net.fReceive(fileName1);

	ist.open(fileName1, ios::in);
	waitFile(fileName1, ist);
	if (!ist)
	{
		cout << "[" << codes[0] << "] - " << "Can't open " << fileName1 << endl;
		exit(1);
	}
	string pk_2;
	ist >> pk_2;
	ist.close();

	//cout << "pk_1: " << El.get_pk_1() << " | pk_2: " << pk_2 << endl;
	//��������Կ
	El.keyGen(pk_2);
}
//���ܲ�����֤��
void SBid::ciphertextOp() {
	CipherGen cipherGen(codes, round, bigMe);
	cipherGen.gen(ciphertext, plaintext, ranZero, ran_1);//��������( h^r , g^m �� y^r )
	cipherGen.prove();//��������֤��
	cipherGen.proveConsistency(lastFinishRoundMe, lastFinishRoundOp);
}
//��֤����
bool SBid::ciphertextVerify() {
	CipherGen cipherVerify(codes, round, bigMe);
	bool flag = cipherVerify.verify();
	flag &= cipherVerify.verifyConsistency(lastFinishRoundOp);
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
	string fileName = filesPath + "ans" + codes[0] + "-R" + round + ".txt";
	ost.open(fileName, ios::out);
	if (!ost)
	{
		cout << "Can't create " << fileName << endl;
		exit(1);
	}
	/*cout << "ans: " << ans << endl;
	cout << "strategy: " << strategyFlag << endl;
	cout << "codeBig: " << codeBig << endl;
	cout << "codeSmall: " << codeSmall << endl;*/
	ost << "No." << codes[0] << "_vs_No." << codes[1] << "_Round_" << round << endl;
	if (strategyFlag == 1) {//���Ӯ
		switch (ans)
		{
			case 0://С�Ŵ��ڴ��
				cout << "[" << codes[0] << "] - Winner No." << codeSmall << endl;
				ost << (bigMe ? "LOSE" : "WIN") << endl;
				break;
			case 1:
				cout << "[" << codes[0] << "] - - Winner DRAW" << endl;
				ost << "DRAW" << endl;
				break;
			case 2://С��С�ڴ��
				cout << "[" << codes[0] << "] - Winner No." << codeBig << endl;
				ost << (bigMe ? "WIN" : "LOSE") << endl;
				break;
			default:
				break;
		}
	}
	else {//С��Ӯ
		switch (ans)
		{	
			case 0://���С��С��
				cout << "[" << codes[0] << "] - Winner No." << codeBig << endl;
				ost << (bigMe ? "WIN" : "LOSE") << endl;
				break;
			case 1:
				cout << "[" << codes[0] << "] - - Winner DRAW" << endl;
				ost << "DRAW" << endl;
				break;
			case 2://��Ŵ���С��
				cout << "[" << codes[0] << "] - Winner No." << codeSmall << endl;
				ost << (bigMe ? "LOSE" : "WIN") << endl;
				break;
			default:
				break;
		}
	}

	ost.close();
	net.fSend(fileName);
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

	if (!readElGamal()) {
		string fileName = paras[1];
		ist.open(fileName, ios::in);
		waitFile(fileName, ist);
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