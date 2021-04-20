#include "./3sBid/sBid.h"
extern ZZ sk_debug;
int main(int argc, char** argv)
{
	array<int, 2> codes;
	int op;
	switch (argc)
	{
		case 1: {
			cout << "Input your code:" << flush;
			cin >> codes[0];
			cout << "Input your opponent's code:" << flush;
			cin >> codes[1];
			break;
		}
		case 2: {
			//Verify
			cout << "You are Verifier" << endl;
			return 0;
		}
		case 3: {
			codes[0] = atoi(argv[1]);
			codes[1] = atoi(argv[2]);
			break;
		}
		default: {
			cout << "parameters error" << endl;
			return 0;
		}
	}
	SBid sbid;
	sbid.prepare(codes);
	sbid.bid();
	sbid.verify();
	return 0;
	//int role = -1;
	//if (argc < 2)
	//{
	//	cout << "Input your role:\nProver   -> 0\nVerifier -> 1" << endl;
	//	;
	//	while (role != 0 && role != 1)
	//	{
	//		cout << "role(0/1): " << flush;
	//		cin >> role;
	//	}
	//}
	//else
	//{
	//	role = argv[1][0] - '0';
	//	if (role != 0 && role != 1 && role != 2)
	//	{
	//		cout << "Input your role:\nProver   -> 0\nVerifier -> 1" << endl;
	//		while (role != 0 && role != 1)
	//		{
	//			cout << "role(0/1): " << flush;
	//			cin >> role;
	//		}
	//	}
	//}
	//if (role == 2) {
	//	long p = 100, q = 90;
	//	srand((unsigned)time(NULL));
	//	if (argc > 2)
	//	{
	//		p = atol(argv[2]);
	//		q = atol(argv[3]);
	//		cout << "s" << endl;
	//	}
	//	cout << "Parameters generating" << flush;
	//	//Functions::pqGen(p, q);
	//	cout << "\nParameters have been generated\n" << endl;
	//	return 0;
	//}
	//cout << "You are " << (role ? "Verifier" : "Prover") << "." << endl;

	/*if (role == 0) {
		Shuffle prover;
		prover.creatProver();
		prover.shuffle();
		prover.prove();
	}
	else {
		Shuffle verifier;
		verifier.creatVerifier();
		verifier.verify();
	}*/
	//return 0;
}