/* The one header the capi imports name. Upstream's s2n-bignum.h carries no
   include guard, and GHC's capi stub includes the named header once per
   foreign import; this wraps it so the prototypes stay upstream's, unedited. */
#ifndef EVENTCHAIN_S2N_BIGNUM_H
#define EVENTCHAIN_S2N_BIGNUM_H
#include <stdint.h>
#include "s2n-bignum.h"
#endif
