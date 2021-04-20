#pragma once
#include "../global.h"
#include "Functions.h"
#include "Prover_toom.h"
#include "Verifier_toom.h"

extern G_q G;               // group used for the Pedersen commitment
extern G_q H;              // group used for the the encryption
extern ElGamal El;         // The class for encryption and decryption
extern Pedersen Ped;        // Object which calculates the commitments
extern Network net;

class Shuffle {
private:
	ifstream ist;
	ofstream ost;
	vector<vector<Cipher_elg>*>* cipher_in;    //ԭʼ���������
	vector<vector<Cipher_elg>*>* cipher_out;   //�ؼ��ܵ�����
	vector<vector<vector<int>*>*>* pi;        //Permutation������shuffle
	vector<vector<ZZ>*>* R;			           //�����ؼ��ܵ������
	string codeName;
	array< string, 2> codes;
	int mu = 4;                      // number of rows after reduction
	int m_r = 4;                     // number of rows after reduction
	int mu_h = 7;					  // 2*mu-1, number of extra elements in the reduction
	int omega_mulex = 7;			  //windowsize for sliding-window technique
	int omega_sw = 6;				  //windowsize for multi-expo technique
	int omega_LL = 5;				  //windowsize for multi-expo technique
	int m = 16;//����
	int n = 2;//����
	int ans = 0;//��֤���
	bool bigMe;
	ZZ mod;
	ZZ ord;
	ZZ gen;
	ZZ genq;  // generator of Z_q��������֤������Ԫ

	//��ȡȺ�Ĳ���������Ⱥ
	//void readParameters();
	//����ElGamal��˽Կ
	//void creatElGamal();
	//��ȡ�ļ��е����ģ�����Ϊ16��2�ľ�����ʽ
	void readCipher(vector<vector<Cipher_elg>*>* Cipher);
	//��������滻����
	void permutation(vector<int>* v, int N);
	//��������滻����
	void perm_matrix(vector<vector<vector<int>* >* >* pi);
	//�������������
	void randomEl(vector<vector<ZZ>*>* R);
	//�ؼ���
	void reencryptCipher(stringstream& ss);
public:
	Shuffle(array< string, 2> codes, string codeName);
	//����Prover��ɫ
	void creatProver(bool bigMe);
	//����Verifier��ɫ
	void creatVerifier();
	//����shuffle����
	void shuffle();
	//���ɳ�ŵ
	void prove();
	//��ȷ����֤
	bool verify();
};

