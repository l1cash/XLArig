/* XMRig and XLArig
 * Copyright 2010      Jeff Garzik <jgarzik@pobox.com>
 * Copyright 2012-2014 pooler      <pooler@litecoinpool.org>
 * Copyright 2014      Lucas Jones <https://github.com/lucasjones>
 * Copyright 2014-2016 Wolf9466    <https://github.com/OhGodAPet>
 * Copyright 2016      Jay D Dee   <jayddee246@gmail.com>
 * Copyright 2017-2018 XMR-Stak    <https://github.com/fireice-uk>, <https://github.com/psychocrypt>
 * Copyright 2018      Lee Clagett <https://github.com/vtnerd>
 * Copyright 2018-2019 SChernykh   <https://github.com/SChernykh>
 * Copyright 2016-2019 XMRig       <https://github.com/xmrig>, <support@xmrig.com>
 *
 *   This program is free software: you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, either version 3 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program. If not, see <http://www.gnu.org/licenses/>.
 */


#include <thread>


#include "crypto/cn/CryptoNight_test.h"
#include "workers/CpuThread.h"
#include "workers/MultiWorker.h"
#include "workers/Workers.h"


template<size_t N>
MultiWorker<N>::MultiWorker(ThreadHandle *handle)
    : Worker(handle)
{
    if (m_thread->algorithm() != xlarig::RANDOM_X) {
        m_memory = Mem::create(m_ctx, m_thread->algorithm(), N);
    }
}


template<size_t N>
MultiWorker<N>::~MultiWorker()
{
    Mem::release(m_ctx, N, m_memory);

#   ifdef XMRIG_ALGO_RANDOMX
    if (m_rx_vm) {
        defyx_destroy_vm(m_rx_vm);
    }
#   endif
}


#ifdef XMRIG_ALGO_RANDOMX
template<size_t N>
void MultiWorker<N>::allocateRandomX_VM()
{
    if (!m_rx_vm) {
        int flags = RANDOMX_FLAG_LARGE_PAGES | RANDOMX_FLAG_FULL_MEM | RANDOMX_FLAG_JIT;
        if (!m_thread->isSoftAES()) {
            flags |= RANDOMX_FLAG_HARD_AES;
        }

        m_rx_vm = defyx_create_vm(static_cast<defyx_flags>(flags), nullptr, Workers::getDataset());
        if (!m_rx_vm) {
            m_rx_vm = defyx_create_vm(static_cast<defyx_flags>(flags - RANDOMX_FLAG_LARGE_PAGES), nullptr, Workers::getDataset());
        }
    }
}
#endif


template<size_t N>
bool MultiWorker<N>::selfTest()
{
    using namespace xlarig;

    if (m_thread->algorithm() == CRYPTONIGHT) {
        const bool rc = verify(VARIANT_0,      test_output_v0)   &&
                        verify(VARIANT_1,      test_output_v1)   &&
                        verify(VARIANT_2,      test_output_v2)   &&
                        verify(VARIANT_XTL,    test_output_xtl)  &&
                        verify(VARIANT_MSR,    test_output_msr)  &&
                        verify(VARIANT_XAO,    test_output_xao)  &&
                        verify(VARIANT_RTO,    test_output_rto)  &&
                        verify(VARIANT_HALF,   test_output_half) &&
                        verify2(VARIANT_WOW,   test_output_wow)  &&
                        verify2(VARIANT_4,     test_output_r)    &&
                        verify(VARIANT_RWZ,    test_output_rwz)  &&
                        verify(VARIANT_ZLS,    test_output_zls)  &&
                        verify(VARIANT_DOUBLE, test_output_double);

#       ifdef XMRIG_ALGO_CN_GPU
        if (!rc || N > 1) {
            return rc;
        }

        return verify(VARIANT_GPU, test_output_gpu);
#       else
        return rc;
#       endif
    }

#   ifdef XMRIG_ALGO_CN_LITE
    if (m_thread->algorithm() == CRYPTONIGHT_LITE) {
        return verify(VARIANT_0,    test_output_v0_lite) &&
               verify(VARIANT_1,    test_output_v1_lite);
    }
#   endif

#   ifdef XMRIG_ALGO_CN_HEAVY
    if (m_thread->algorithm() == CRYPTONIGHT_HEAVY) {
        return verify(VARIANT_0,    test_output_v0_heavy)  &&
               verify(VARIANT_XHV,  test_output_xhv_heavy) &&
               verify(VARIANT_TUBE, test_output_tube_heavy);
    }
#   endif

#   ifdef XMRIG_ALGO_CN_PICO
    if (m_thread->algorithm() == CRYPTONIGHT_PICO) {
        return verify(VARIANT_TRTL, test_output_pico_trtl);
    }
#   endif

#   ifdef XMRIG_ALGO_RANDOMX
    if (m_thread->algorithm() == RANDOM_X) {
        return true;
    }
#   endif

    return false;
}


template<size_t N>
void MultiWorker<N>::start()
{
    while (Workers::sequence() > 0) {
        if (Workers::isPaused()) {
            do {
                std::this_thread::sleep_for(std::chrono::milliseconds(200));
            }
            while (Workers::isPaused());

            if (Workers::sequence() == 0) {
                break;
            }

            consumeJob();
        }

        while (!Workers::isOutdated(m_sequence)) {
            if ((m_count & 0x7) == 0) {
                storeStats();
            }

            const xlarig::Variant v = m_state.job.algorithm().variant();

#           ifdef XMRIG_ALGO_RANDOMX
            if (v == xlarig::VARIANT_RX_DEFYX) {
                allocateRandomX_VM();
                Workers::updateDataset(m_state.job.seedHash(), m_totalWays);
                defyx_calculate_hash(m_rx_vm, m_state.blob, m_state.job.size(), m_hash);
            }
            else if (v == xlarig::VARIANT_RX_DEFYX) {
                // FIXME: same as above, but needs to be different!
                allocateRandomX_VM();
                Workers::updateDataset(m_state.job.seedHash(), m_totalWays);
                defyx_calculate_hash(m_rx_vm, m_state.blob, m_state.job.size(), m_hash);
            }
            else
#           endif
            {
                m_thread->fn(v)(m_state.blob, m_state.job.size(), m_hash, m_ctx, m_state.job.height());
            }

            for (size_t i = 0; i < N; ++i) {
                if (*reinterpret_cast<uint64_t*>(m_hash + (i * 32) + 24) < m_state.job.target()) {
                    Workers::submit(xlarig::JobResult(m_state.job.poolId(), m_state.job.id(), m_state.job.clientId(), *nonce(i), m_hash + (i * 32), m_state.job.diff(), m_state.job.algorithm()));
                }

                *nonce(i) += 1;
            }

            m_count += N;

            std::this_thread::yield();
        }

        consumeJob();
    }
}


template<size_t N>
bool MultiWorker<N>::resume(const xlarig::Job &job)
{
    if (m_state.job.poolId() == -1 && job.poolId() >= 0 && job.id() == m_pausedState.job.id()) {
        m_state = m_pausedState;
        return true;
    }

    return false;
}


template<size_t N>
bool MultiWorker<N>::verify(xlarig::Variant variant, const uint8_t *referenceValue)
{

    xlarig::CpuThread::cn_hash_fun func = m_thread->fn(variant);
    if (!func) {
        return false;
    }

    func(test_input, 76, m_hash, m_ctx, 0);
    return memcmp(m_hash, referenceValue, sizeof m_hash) == 0;
}


template<size_t N>
bool MultiWorker<N>::verify2(xlarig::Variant variant, const uint8_t *referenceValue)
{
    xlarig::CpuThread::cn_hash_fun func = m_thread->fn(variant);
    if (!func) {
        return false;
    }

    for (size_t i = 0; i < (sizeof(cn_r_test_input) / sizeof(cn_r_test_input[0])); ++i) {
        const size_t size = cn_r_test_input[i].size;
        for (size_t k = 0; k < N; ++k) {
            memcpy(m_state.blob + (k * size), cn_r_test_input[i].data, size);
        }

        func(m_state.blob, size, m_hash, m_ctx, cn_r_test_input[i].height);

        for (size_t k = 0; k < N; ++k) {
            if (memcmp(m_hash + k * 32, referenceValue + i * 32, sizeof m_hash / N) != 0) {
                return false;
            }
        }
    }

    return true;
}


template<>
bool MultiWorker<1>::verify2(xlarig::Variant variant, const uint8_t *referenceValue)
{
    xlarig::CpuThread::cn_hash_fun func = m_thread->fn(variant);
    if (!func) {
        return false;
    }

    for (size_t i = 0; i < (sizeof(cn_r_test_input) / sizeof(cn_r_test_input[0])); ++i) {
        func(cn_r_test_input[i].data, cn_r_test_input[i].size, m_hash, m_ctx, cn_r_test_input[i].height);

        if (memcmp(m_hash, referenceValue + i * 32, sizeof m_hash) != 0) {
            return false;
        }
    }

    return true;
}


template<size_t N>
void MultiWorker<N>::consumeJob()
{
    xlarig::Job job = Workers::job();
    m_sequence = Workers::sequence();
    if (m_state.job == job) {
        return;
    }

    save(job);

    if (resume(job)) {
        return;
    }

    m_state.job = job;

    const size_t size = m_state.job.size();
    memcpy(m_state.blob, m_state.job.blob(), m_state.job.size());

    if (N > 1) {
        for (size_t i = 1; i < N; ++i) {
            memcpy(m_state.blob + (i * size), m_state.blob, size);
        }
    }

    for (size_t i = 0; i < N; ++i) {
        if (m_state.job.isNicehash()) {
            *nonce(i) = (*nonce(i) & 0xff000000U) + (0xffffffU / m_totalWays * (m_offset + i));
        }
        else {
           *nonce(i) = 0xffffffffU / m_totalWays * (m_offset + i);
        }
    }
}


template<size_t N>
void MultiWorker<N>::save(const xlarig::Job &job)
{
    if (job.poolId() == -1 && m_state.job.poolId() >= 0) {
        m_pausedState = m_state;
    }
}


template class MultiWorker<1>;
template class MultiWorker<2>;
template class MultiWorker<3>;
template class MultiWorker<4>;
template class MultiWorker<5>;
