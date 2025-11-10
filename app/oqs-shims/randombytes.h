#ifndef RANDOMBYTES_H
#define RANDOMBYTES_H

// Provide randombytes function for PQClean (not using liboqs)
// This will be defined in sphincs.c
void randombytes(uint8_t *x, size_t xlen);

#endif // RANDOMBYTES_H

