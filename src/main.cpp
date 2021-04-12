#include "shuffle.h"
int main(int argc, char** argv)
{
	int role = -1;
	if (argc < 2)
	{
		cout << "Input your role:\nProver   -> 0\nVerifier -> 1" << endl;
		;
		while (role != 0 && role != 1)
		{
			cout << "role(0/1): " << flush;
			cin >> role;
		}
	}
	else
	{
		role = argv[1][0] - '0';
		if (role != 0 && role != 1 && role != 2)
		{
			cout << "Input your role:\nProver   -> 0\nVerifier -> 1" << endl;
			while (role != 0 && role != 1)
			{
				cout << "role(0/1): " << flush;
				cin >> role;
			}
		}
	}
	if (role == 2) {
		long p = 100, q = 90;
		srand((unsigned)time(NULL));
		if (argc > 2)
		{
			p = atol(argv[2]);
			q = atol(argv[3]);
			cout << "s" << endl;
		}
		cout << "Parameters generating" << flush;
		Functions::pqGen(p, q);
		cout << "\nParameters have been generated\n" << endl;
		return 0;
	}
	cout << "You are " << (role ? "Verifier" : "Prover") << "." << endl;

	if (role == 0) {
		Shuffle prover;
		prover.creatProver();
		prover.shuffle();
		prover.prove();
	}
	else {
		Shuffle verifier;
		verifier.creatVerifier();
		verifier.verify();
	}
	return 0;
}