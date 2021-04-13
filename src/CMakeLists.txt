ADD_EXECUTABLE(main 
 "main.cpp"
 "base/global.cpp"
 "base/Cipher_elg.cpp"
 "base/Cyclic_group.cpp"
 "base/ElGamal.cpp"
 "base/G_mem.cpp"
 "base/G_q.cpp"
 "base/Mod_p.cpp"
 "base/Pedersen.cpp"
 "base/sha256.cpp"
 "base/multi_expo.cpp"
 "shuffle/shuffle.cpp"
 "shuffle/func_pro.cpp"
 "shuffle/func_ver.cpp"
 "shuffle/Functions.cpp"
 "shuffle/Prover_toom.cpp"
 "shuffle/Verifier_toom.cpp" 
 "sBid/sBid.cpp")

SET(EXECUTABLE_OUTPUT_PATH ${sBid_SOURCE_DIR}/bin)

# GMP
find_path(GMP_INCLUDE_DIR NAMES gmp.h)
find_path(GMPXX_INCLUDE_DIR NAMES gmpxx.h)
find_library(GMP_LIBRARIES NAMES gmp libgmp)
find_library(GMPXX_LIBRARIES NAMES gmpxx libgmpxx)

# NTL
find_path(NTL_INCLUDE_DIR NAMES NTL)
find_library(NTL_LIBRARIES NAMES ntl libntl)

target_link_libraries(main ntl gmp gmpxx)
add_definitions(-std=c++17)