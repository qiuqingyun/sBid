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
}