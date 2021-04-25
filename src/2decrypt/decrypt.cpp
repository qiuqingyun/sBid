#include "decrypt.h"

Decrypt::Decrypt(array<string, 2> codes, string round, string codeBig, string codeSmall, bool bigMe) :codes(codes), round(round), codeBig(codeBig), codeSmall(codeSmall), bigMe(bigMe) {
	SetSeed(to_ZZ((long)time(0) + (long)clock()));
	y = El.get_pk();
	mod = El.get_group().get_mod();
	ord = El.get_group().get_ord();
	g = El.get_group().get_g();
	h = El.get_group().get_gen();
	sk = El.get_sk();
}
int Decrypt::decrypt() {
	readCipherShuffled();
	createDk();
	readDk();
	return outputAns();
}
//读取经过两轮混淆的密文
void Decrypt::readCipherShuffled() {
	string fileName = "cipherSR" + codeBig + "-R" + round + ".txt";
	ist.open(fileName, ios::in);
	if (!ist) {
		cout << "[" << codes[0] << "] - " << "Can't open " << fileName << endl;
		exit(1);
	}
	for (int i = 0; i < cipherNum; i++) {
		ist >> ciphertext[i];
	}
	ist.close();
}
//创建解密份额
void Decrypt::createDk() {
	string fileName = "dk" + codes[0] + "-R" + round + ".txt";
	ost.open(fileName, ios::out);
	if (!ost) {
		cout << "[" << codes[0] << "] - " << "Can't create " << fileName << endl;
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
	if (bigMe) {//大号先接收再发送
		net.mReceive(cipher_2);
		net.mSend(cipher_1);
	}
	else {//小号先发送再接收
		net.mSend(cipher_1);
		net.mReceive(cipher_2);
	}
	vector<string> ciphertext_2_str;
	net.deserialization(cipher_2, ciphertext_2_str);
	//保存
	fileName = "dk" + codes[1] + "-R" + round + ".txt";
	ost.open(fileName, ios::out);
	if (!ost)
	{
		cout << "[" << codes[0] << "] - " << "Can't create " << fileName << endl;
		exit(1);
	}
	for (int i = 0; i < cipherNum; i++)
		ost << ciphertext_2_str[i] << endl;
	ost.close();
}
//读取对方的解密份额
void Decrypt::readDk() {
	string fileName = "dk" + codes[1] + "-R" + round + ".txt";
	ist.open(fileName, ios::in);
	if (!ist) {
		cout << "[" << codes[0] << "] - " << "Can't open " << fileName << endl;
		exit(1);
	}
	for (int i = 0; i < cipherNum; i++) {
		ist >> dk_2[i];
	}
	ist.close();
}
//输出结果
int Decrypt::outputAns() {
	int result = 0, flag = 0;
	for (int i = 0; i < cipherNum; i++)
	{
		ZZ dk = MulMod(dk_1[i], dk_2[i], mod);//加法同态
		ZZ dk_inv = InvMod(dk, mod);//取逆
		ZZ ans = El.get_m(MulMod(ciphertext[i].get_v(), dk_inv, mod));//解密
		if (ans == 0)
		{//大号胜

			return 0;
		}
		else if (ans == 1)
		{//平局
			flag++;
		}
	}
	if (flag == cipherNum)

		return 1;
	return 2;

}
void Decrypt::prove() {
	//生成证明
	string fileName = "proveDecrypt" + codes[0] + "-R" + round + ".txt";
	Commitment com(codes, round, c2, dk_1, bigMe, fileName);
	com.decryptCommit();
	//交换证明
	string fileName1 = "proveDecrypt" + codes[1] + "-R" + round + ".txt";
	if (bigMe) {
		net.fSend(fileName);
		net.fReceive(fileName1);
	}
	else {
		net.fReceive(fileName1);
		net.fSend(fileName);
	}
}
bool Decrypt::verify() {
	int index = 0;
	if (!vMode)
		index = 1;
	bool flag = true;
	//读入密文，得到c2
	string fileName = "cipherSR" + codeBig + "-R" + round + ".txt";
	ist.open(fileName, ios::in);
	if (!ist) {
		cout << "[" << codes[0] << "] - " << "Can't open " << fileName << endl;
		exit(1);
	}
	for (int i = 0; i < cipherNum; i++) {
		ist >> ciphertext[i];
	}
	ist.close();
	//读入dk
	fileName = "dk" + codes[index] + "-R" + round + ".txt";
	ist.open(fileName, ios::in);
	if (!ist) {
		cout << "[" << codes[0] << "] - " << "Can't open " << fileName << endl;
		exit(1);
	}
	for (int i = 0; i < cipherNum; i++) {
		ist >> dk_1[i];
	}
	ist.close();
	//读入pk
	fileName = "pk" + codes[index] + ".txt";
	ist.open(fileName, ios::in);
	if (!ist) {
		cout << "[" << codes[0] << "] - " << "Can't open " << fileName << endl;
		exit(1);
	}
	string container;
	ist >> container;
	pk.toModP(container, mod);
	ist.close();
	//读入证明
	fileName = "proveDecrypt" + codes[index] + "-R" + round + ".txt";
	ist.open(fileName, ios::in);
	if (!ist)
	{
		cout << "[" << codes[0] << "] - " << "Can't open " << fileName << endl;
		exit(1);
	}
	//验证证明
	Commitment com(codes, round, ciphertext, dk_1, pk, bigMe, fileName);
	flag &= com.decryptCheck();

	ist.close();
	return flag;
}
