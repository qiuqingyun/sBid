#pragma once
#include "./base/base.h"
#include "./base/Mod_p.h"
#include "./base/G_q.h"
#include "./base/Cyclic_group.h"
#include "./base/sha256.h"
#include "./ElGamal/ElGamal.h"
#include "./Pedersen/Pedersen.h"

extern G_q G;               // group used for the Pedersen commitment
extern G_q H;               // group used for the the encryption
extern ElGamal El;         // The class for encryption and decryption
extern Pedersen Ped;        // Object which calculates the commitments