#include "sBid.h"

//生成参数
void SBid::parametersGen() {
	ParaGen paraGen;
	paraGen.parametersGen(pBits, qBits);
}
//竞拍准备操作
void SBid::prepare(array<int, 2> codes_in) {
	codes[0] = to_string(codes_in[0]);//自己的编号
	codes[1] = to_string(codes_in[1]);//对方的编号
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
//开始竞标
void SBid::bid() {
	compareOp();
	shuffleOp();
	decryptOp();
}
//验证
void SBid::verify() {
	cout << "[" << codes[0] << "] - " << "=====Verify=====" << endl;
	ciphertextVerify();
	compareVerify();
	shuffleVerify();
	decryptVerify();
	cout << "[" << codes[0] << "] - " << "======OVER======" << endl;
}
//读取群的参数并生成群
void SBid::readParameters() {
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
	H = G_q(gen_h, ord, mod); //生成元h 阶数q 模数p
	G = G_q(gen_h, ord, mod);
	H.set_g(gen_g);
	G.set_g(gen_g);
}
//设置初始化ElGamal
void SBid::creatElGamal() {
	El.set_group(H);
	string fileName = "pk" + codes[0] + ".txt";
	ist.open(fileName, ios::in);
	if (!ist)
	{//生成公私钥
		cout << fileName << " does not exist, a new key will be generated" << endl;
		ZZ x = RandomBnd(H.get_ord());//随机生成私钥
		El.set_sk(x);//生成公钥
		//输出公私钥
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
	{//读取公私钥
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
	//将生成的公钥传递给对方
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
	//生成主公钥
	El.keyGen(pk_2);
	//输出主公钥
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
//加密并生成证明
void SBid::ciphertextOp() {
	CipherGen* cipherGen = new CipherGen(codes, bigMe);
	cipherGen->gen(ciphertext, plaintext, ranZero, ran_1);//生成密文( h^r , g^m × y^r )
	cipherGen->prove();//生成密文证明
}
//验证加密
void SBid::ciphertextVerify() {
	CipherGen* cipherVerify = new CipherGen(codes, bigMe);
	bool flag = cipherVerify->verify();
	cout << "[" << codes[0] << "] - " << "ciphertext results: " << ans[flag] << endl;
}
//比较并生成证明
void SBid::compareOp() {
	Compare compare(codes, plaintext, ciphertext, ran_1, ranZero, bigMe);
	compare.compare();
	compare.prove();
}
//验证比较
void SBid::compareVerify() {
	Compare compare(codes, ciphertext, bigMe);
	bool flag = compare.verify();
	cout << "[" << codes[0] << "] - " << "compare results: " << ans[flag] << endl;
}
//混淆并生成证明
void SBid::shuffleOp() {
	Shuffle prover(codes, coCode);
	prover.creatProver(bigMe);
	prover.shuffle();
	prover.prove();
}
//验证混淆
void SBid::shuffleVerify() {
	Shuffle verifier(codes, coCode);
	verifier.creatVerifier();
	bool flag = verifier.verify();
	cout << "[" << codes[0] << "] - " << "shuffle results: " << ans[flag] << endl;
}
//解密并生成证明
void SBid::decryptOp() {
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
//验证解密
void SBid::decryptVerify() {
	Decrypt decrypt(codes, codeBig, codeSmall, bigMe);
	bool flag = decrypt.verify();
	cout << "[" << codes[0] << "] - " << "decrypt results: " << ans[flag] << endl;
}