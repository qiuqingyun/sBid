#pragma once
#include "./0base/base.h"
#include "./0base/Mod_p.h"
#include "./0base/G_q.h"
#include "./0base/Cyclic_group.h"
#include "./0base/sha256.h"
#include "./0base/network.h"
#include "./1ElGamal/ElGamal.h"
#include "./1Pedersen/Pedersen.h"

extern G_q G;               // group used for the Pedersen commitment
extern G_q H;               // group used for the the encryption
extern ElGamal El;         // The class for encryption and decryption
extern Pedersen Ped;        // Object which calculates the commitments
extern bool vMode;
extern bool debug;
extern string filesPath;

inline void waitFile(string fileName, ifstream& ist) {
	int index = 0;
	while (!ist && ++index < 300000) {
		usleep(1);
		ist.close();
		ist.open(fileName, ios::in);
	}
}

inline clock_t GetTickCount()
{
	struct timeval tv;
	gettimeofday(&tv, NULL);
	return (tv.tv_sec * 1000 + tv.tv_usec / 1000)*1000;
}