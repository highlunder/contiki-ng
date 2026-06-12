/*
 * Standalone test for mbedtls_mpi_core_sub_int() borrow propagation.
 *
 * Exercises the exact "s = 0, c_in = 1" case documented as the trigger for
 * the suspected ARM SBCS-carry-flag miscompilation in bignum_core.c, plus a
 * multi-limb case with carry propagating through a zero limb and stopping
 * at a non-zero limb.
 *
 * SECURITY NOTICE: Test only. Not for production use.
 */

#include "contiki.h"
#include "sys/log.h"
#include "bignum_core.h"

#define LOG_MODULE "bignum-core-sub-test"
#define LOG_LEVEL  LOG_LEVEL_DBG

/******************************************************************************/
PROCESS(bignum_core_sub_test, "mbedtls_mpi_core_sub_int borrow test");
AUTOSTART_PROCESSES(&bignum_core_sub_test);
/******************************************************************************/
PROCESS_THREAD(bignum_core_sub_test, ev, data)
{
    PROCESS_BEGIN();

    LOG_INFO("=== mbedtls_mpi_core_sub_int borrow test ===\n");

    int all_pass = 1;

    /* Case 1: single limb, A[0]=0, c_in=1 -> X[0]=0xFFFF...FF, c_out=1 */
    {
        mbedtls_mpi_uint A[1] = { 0 };
        mbedtls_mpi_uint X[1];
        mbedtls_mpi_uint c = mbedtls_mpi_core_sub_int(X, A, 1, 1);

        LOG_DBG("case1: X[0]=0x%08lx c_out=%lu\n",
                (unsigned long)X[0], (unsigned long)c);

        int ok = (X[0] == (mbedtls_mpi_uint) -1) && (c == 1);
        if(ok) {
            LOG_INFO("case1 (s=0,c_in=1) PASS\n");
        } else {
            LOG_ERR("case1 (s=0,c_in=1) FAIL: X[0]=0x%08lx (exp 0xffffffff) "
                    "c_out=%lu (exp 1)\n",
                    (unsigned long)X[0], (unsigned long)c);
            all_pass = 0;
        }
    }

    /* Case 2: multi-limb, carry propagates through a zero limb and stops
     * at a non-zero limb: A=[0,5], c_in=1 -> X=[0xFFFF...FF,4], c_out=0 */
    {
        mbedtls_mpi_uint A[2] = { 0, 5 };
        mbedtls_mpi_uint X[2];
        mbedtls_mpi_uint c = mbedtls_mpi_core_sub_int(X, A, 1, 2);

        LOG_DBG("case2: X[0]=0x%08lx X[1]=0x%08lx c_out=%lu\n",
                (unsigned long)X[0], (unsigned long)X[1], (unsigned long)c);

        int ok = (X[0] == (mbedtls_mpi_uint) -1) && (X[1] == 4) && (c == 0);
        if(ok) {
            LOG_INFO("case2 (multi-limb borrow propagation) PASS\n");
        } else {
            LOG_ERR("case2 FAIL: X[0]=0x%08lx (exp 0xffffffff) "
                    "X[1]=0x%08lx (exp 4) c_out=%lu (exp 0)\n",
                    (unsigned long)X[0], (unsigned long)X[1],
                    (unsigned long)c);
            all_pass = 0;
        }
    }

    /* Case 3: no borrow needed: A=[5], c_in=1 -> X[0]=4, c_out=0 */
    {
        mbedtls_mpi_uint A[1] = { 5 };
        mbedtls_mpi_uint X[1];
        mbedtls_mpi_uint c = mbedtls_mpi_core_sub_int(X, A, 1, 1);

        LOG_DBG("case3: X[0]=0x%08lx c_out=%lu\n",
                (unsigned long)X[0], (unsigned long)c);

        int ok = (X[0] == 4) && (c == 0);
        if(ok) {
            LOG_INFO("case3 (s=5,c_in=1, no borrow) PASS\n");
        } else {
            LOG_ERR("case3 FAIL: X[0]=0x%08lx (exp 4) c_out=%lu (exp 0)\n",
                    (unsigned long)X[0], (unsigned long)c);
            all_pass = 0;
        }
    }

    /* Case 4: c_in=0, A=[0] -> X[0]=0, c_out=0 (trivial, no borrow at all) */
    {
        mbedtls_mpi_uint A[1] = { 0 };
        mbedtls_mpi_uint X[1];
        mbedtls_mpi_uint c = mbedtls_mpi_core_sub_int(X, A, 0, 1);

        LOG_DBG("case4: X[0]=0x%08lx c_out=%lu\n",
                (unsigned long)X[0], (unsigned long)c);

        int ok = (X[0] == 0) && (c == 0);
        if(ok) {
            LOG_INFO("case4 (s=0,c_in=0) PASS\n");
        } else {
            LOG_ERR("case4 FAIL: X[0]=0x%08lx (exp 0) c_out=%lu (exp 0)\n",
                    (unsigned long)X[0], (unsigned long)c);
            all_pass = 0;
        }
    }

    if(all_pass) {
        LOG_INFO("ALL TESTS PASSED\n");
    } else {
        LOG_ERR("SOME TESTS FAILED\n");
    }

    PROCESS_END();
}
