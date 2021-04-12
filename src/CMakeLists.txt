ADD_EXECUTABLE(main 
 "main.cpp"
 "global.cpp"
 "shuffle.cpp"
 "Cipher_elg.cpp"
 "Cyclic_group.cpp"
 "ElGamal.cpp"
 "fft.cpp"
 "func_pro.cpp"
 "func_ver.cpp"
 "Functions.cpp"
 "G_mem.cpp"
 "G_q.cpp"
 "Mod_p.cpp"
 "multi_expo.cpp"
 "Pedersen.cpp"
 "Prover_toom.cpp"
 "sha256.cpp"
 "Verifier_toom.cpp")

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