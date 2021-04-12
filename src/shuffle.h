#pragma once
#include "Cipher_elg.h"
#include "ElGamal.h"
#include "Functions.h"
#include "G_q.h"
#include "Prover_toom.h"
#include "Verifier_toom.h"
#include "global.h"
#include "sha256.h"
extern G_q G;               // group used for the Pedersen commitment
extern G_q H;               // group used for the the encryption
extern ElGamal El;         // The class for encryption and decryption
extern Pedersen Ped;        // Object which calculates the commitments

class Shuffle {
private:
	ifstream ist;
	ofstream ost;
	vector<vector<Cipher_elg>*>* cipher_in;    //ԭʼ���������
	vector<vector<Cipher_elg>*>* cipher_out;   //�ؼ��ܵ�����
	vector<vector<vector<int>*>*>* pi;        //Permutation������shuffle
	vector<vector<ZZ>*>* R;			           //�����ؼ��ܵ������
	int mu = 4;                      // number of rows after reduction
	int m_r = 7;                     // number of rows after reduction
	int mu_h = 4;					  // 2*mu-1, number of extra elements in the reduction
	int omega_mulex = 7;			  //windowsize for sliding-window technique
	int omega_sw = 6;				  //windowsize for multi-expo technique
	int omega_LL = 5;				  //windowsize for multi-expo technique
	int m = 16;//����
	int n = 2;//����
	int ans = 0;//��֤���
	ZZ mod;
	ZZ ord;
	ZZ gen;
	ZZ genq;  // generator of Z_q��������֤������Ԫ
public:
	//����Prover��ɫ
	void creatProver() {
		cipher_in = new vector<vector<Cipher_elg>*>(m);  //���������
		cipher_out = new vector<vector<Cipher_elg>*>(m);  //���������
		readParameters();
		creatElGamal();
		//��ȡδshuffle������
		string fileName = "cipher_in.txt";
		ist.open(fileName, ios::in);
		if (!ist)
		{
			cout << "Can't open " << fileName << endl;
			exit(1);
		}
		readCipher(cipher_in);
		ist.close();
	}
	//����Verifier��ɫ
	void creatVerifier() {
		cipher_in = new vector<vector<Cipher_elg>*>(m);  //���������
		cipher_out = new vector<vector<Cipher_elg>*>(m);  //���������
		readParameters();
		creatElGamal();
		//��ȡδshuffle������
		string fileName = "cipher_in.txt";
		ist.open(fileName, ios::in);
		if (!ist)
		{
			cout << "Can't open " << fileName << endl;
			exit(1);
		}
		readCipher(cipher_in);
		ist.close();
		//��ȡshuffle��������
		fileName = "cipher_out.txt";
		ist.open(fileName, ios::in);
		if (!ist)
		{
			cout << "Can't open " << fileName << endl;
			exit(1);
		}
		readCipher(cipher_out);
		ist.close();
	}
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
		ist >> genq;
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
	//��ȡ�ļ��е����ģ�����Ϊ16��2�ľ�����ʽ
	void readCipher(vector<vector<Cipher_elg>*>* Cipher) {
		string in_temp, u_str, v_str;
		size_t pos_start, pos_mid, pos_end;
		Cipher = new vector<vector<Cipher_elg>*>(m);
		for (int row = 0; row < m; row++) {
			vector<Cipher_elg>* r = new vector<Cipher_elg>(n);
			for (int col = 0; col < n; col++) {
				ist >> in_temp;
				pos_start = in_temp.find("(");
				pos_mid = in_temp.find(",");
				pos_end = in_temp.find(")");
				u_str = in_temp.substr(pos_start + 1, pos_mid - 1);
				v_str = in_temp.substr(pos_mid + 1, pos_end - pos_mid - 1);
				ZZ u, v;
				conv(u, u_str.c_str());
				conv(v, v_str.c_str());
				Cipher_elg Cipher_temp = Cipher_elg(u, v, H.get_mod());
				r->at(col) = Cipher_temp;
			}
			Cipher->at(row) = r;
		}
	}
	//����shuffle����
	void shuffle() {
		clock_t tstart = clock();
		R = new vector<vector<ZZ>*>(m);
		pi = new vector<vector<vector<int>*>*>(m);
		perm_matrix(pi);//��������shuffle������pi������Ϊ32������
		randomEl(R);//���������ؼ��ܵ����������R������Ϊ32�������
		//ʹ��pi��R������cipher_in�������¼��ܣ�����32��(u,v)�����飬�����
		string fileName = "cipher_out.txt";
		ost.open(fileName, ios::in);
		if (!ost)
		{
			cout << "Can't creat " << fileName << endl;
			exit(1);
		}
		reencryptCipher();
		ost.close();
		/*Functions::decryptCipher(c, num, 0);
		Functions::decryptCipher(C, num, 1);*/
		clock_t  tstop = clock();
		double ttime = (tstop - tstart) / (double)CLOCKS_PER_SEC * 1000;
		cout << "To shuffle the ciphertexts took " << ttime << " ms." << endl;
	}
	//��������滻����
	void permutation(vector<int>* v, int N)
	{
		int r, temp;
		//new seed for the randomness
		SetSeed(to_ZZ((unsigned int)time(0)));
		//vector containing the values 1 to N ordered
		for (int i = 0; i < N; i++)
		{
			v->at(i) = i + 1;
		}
		//create N times a random number <N, calculates r = i+r%N and switchs the values v[i] and v[r]
		for (int i = 0; i < N; i++)
		{//�������
			r = (RandomBnd(N) + i) % N;
			temp = v->at(i);
			v->at(i) = v->at(r);
			v->at(r) = temp;
		}
	}
	//��������滻����
	void perm_matrix(vector<vector<vector<int>* >* >* pi) {
		int i, j, k, t_1, t_2;
		vector<int>* v = new vector<int>(n * m);
		//��������滻����
		permutation(v, n * m);
		for (i = 0; i < m; i++) {
			vector<vector<int>* >* r = new vector<vector<int>* >(n);
			for (j = 0; j < n; j++) {
				k = i * n + j;//v��index 
				t_1 = v->at(k) / n;//shuffle�����
				t_2 = v->at(k) % n;//shuffle�����
				if (t_2 == 0)
				{
					t_1 = t_1 - 1;
					t_2 = n - 1;
				}
				else
				{
					t_2 = t_2 - 1;
				}
				vector<int>* el = new vector<int>(2);
				el->at(0) = t_1;
				el->at(1) = t_2;
				r->at(j) = el;
			}
			pi->at(i) = r;
		}
		delete v;
	}
	//�������������
	void randomEl(vector<vector<ZZ>*>* R)
	{
		for (int i = 0; i < m; i++)
		{
			vector<ZZ>* r = new vector<ZZ>(n);
			for (int j = 0; j < n; j++)
			{
				r->at(j) = RandomBnd(ord);
			}
			R->at(i) = r;
		}
	}
	//�ؼ���
	void reencryptCipher() {
		for (int i = 0; i < m; i++)
		{
			vector<Cipher_elg>* r = new vector<Cipher_elg>(n);
			for (int j = 0; j < n; j++)
			{
				Cipher_elg temp = El.encrypt(1, R->at(i)->at(j));				//����������ܵ�����1
				int row = pi->at(i)->at(j)->at(0);								//shuffle����Ҫ�ƶ�����
				int col = pi->at(i)->at(j)->at(1);								//shuffle����Ҫ�ƶ�����
				Cipher_elg::mult(r->at(j), temp, cipher_in->at(row)->at(col));  //̬ͬ�˷�
				ost << r->at(j) << endl;
			}
			cipher_out->at(i) = r;
		}
	}
	//���ɳ�ŵ
	void prove() {
		clock_t tstart = clock();
		Ped = Pedersen(n, G);
		Ped.set_omega(omega_mulex, omega_LL, omega_sw);
		vector<int> num = { m, n, omega_mulex, omega_sw, omega_LL, mu, m_r, mu_h };
		Prover_toom* P = new Prover_toom(cipher_out, R, pi, num, genq);
		P->prove();
		delete P;
		clock_t tstop = clock();
		double ttime = (tstop - tstart) / (double)CLOCKS_PER_SEC * 1000;
		cout << "To prove the proof took " << ttime << " ms." << endl;
	}
	//��ȷ����֤
	void verify() {
		clock_t tstart = clock();
		//��ȡPedersen����
		string fileName = "Pedersen.txt";
		ist.open(fileName, ios::in);
		if (!ist)
		{
			cout << "Can't open " << fileName << endl;
			exit(1);
		}
		vector<Mod_p> gen_in;
		ZZ gen_temp;
		for (int i = 0; i <= n; i++)
		{
			string gen_str;
			ist >> gen_str;
			conv(gen_temp, gen_str.c_str());
			gen_in.push_back(Mod_p(gen_temp, H.get_mod()));
		}
		ist.close();
		Ped = Pedersen(n, G, gen_in);
		Ped.set_omega(omega_mulex, omega_LL, omega_sw);

		vector<int> num = { m, n, omega_mulex, omega_sw, omega_LL, mu, m_r, mu_h };

		Verifier_toom* V = new Verifier_toom(num);
		ans = V->round_10(cipher_in, cipher_out);
		delete V;

		clock_t tstop = clock();
		double ttime = (tstop - tstart) / (double)CLOCKS_PER_SEC * 1000;
		cout << "To verify the proof took " << ttime << " ms." << endl;
	}
};

