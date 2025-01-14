/* XMRig and XLArig
 * Copyright 2010      Jeff Garzik <jgarzik@pobox.com>
 * Copyright 2012-2014 pooler      <pooler@litecoinpool.org>
 * Copyright 2014      Lucas Jones <https://github.com/lucasjones>
 * Copyright 2014-2016 Wolf9466    <https://github.com/OhGodAPet>
 * Copyright 2016      Jay D Dee   <jayddee246@gmail.com>
 * Copyright 2017-2018 XMR-Stak    <https://github.com/fireice-uk>, <https://github.com/psychocrypt>
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

#include <cmath>
#include <inttypes.h>
#include <thread>


#include "api/Api.h"
#include "base/io/log/Log.h"
#include "base/tools/Handle.h"
#include "core/config/Config.h"
#include "core/Controller.h"
#include "crypto/cn/CryptoNight_constants.h"
#include "interfaces/IJobResultListener.h"
#include "interfaces/IThread.h"
#include "Mem.h"
#include "rapidjson/document.h"
#include "workers/Hashrate.h"
#include "workers/MultiWorker.h"
#include "workers/ThreadHandle.h"
#include "workers/Workers.h"


bool Workers::m_active = false;
bool Workers::m_enabled = true;
Hashrate *Workers::m_hashrate = nullptr;
xlarig::IJobResultListener *Workers::m_listener = nullptr;
xlarig::Job Workers::m_job;
Workers::LaunchStatus Workers::m_status;
std::atomic<int> Workers::m_paused;
std::atomic<uint64_t> Workers::m_sequence;
std::list<xlarig::JobResult> Workers::m_queue;
std::vector<ThreadHandle*> Workers::m_workers;
uint64_t Workers::m_ticks = 0;
uv_async_t *Workers::m_async = nullptr;
uv_mutex_t Workers::m_mutex;
uv_rwlock_t Workers::m_rwlock;
uv_timer_t *Workers::m_timer = nullptr;
xlarig::Controller *Workers::m_controller = nullptr;

#ifdef XMRIG_ALGO_RANDOMX
uv_rwlock_t Workers::m_rx_dataset_lock;
defyx_cache *Workers::m_rx_cache = nullptr;
defyx_dataset *Workers::m_rx_dataset = nullptr;
uint8_t Workers::m_rx_seed_hash[32] = {};
std::atomic<uint32_t> Workers::m_rx_dataset_init_thread_counter = {};
#endif


xlarig::Job Workers::job()
{
    uv_rwlock_rdlock(&m_rwlock);
    xlarig::Job job = m_job;
    uv_rwlock_rdunlock(&m_rwlock);

    return job;
}


size_t Workers::hugePages()
{
    uv_mutex_lock(&m_mutex);
    const size_t hugePages = m_status.hugePages;
    uv_mutex_unlock(&m_mutex);

    return hugePages;
}


size_t Workers::threads()
{
    uv_mutex_lock(&m_mutex);
    const size_t threads = m_status.threads;
    uv_mutex_unlock(&m_mutex);

    return threads;
}


void Workers::printHashrate(bool detail)
{
    assert(m_controller != nullptr);
    if (!m_controller) {
        return;
    }

    if (detail) {
        char num1[8] = { 0 };
        char num2[8] = { 0 };
        char num3[8] = { 0 };

        xlarig::Log::print(WHITE_BOLD_S "| THREAD | AFFINITY | 10s H/s | 60s H/s | 15m H/s |");

        size_t i = 0;
        for (const xlarig::IThread *thread : m_controller->config()->threads()) {
             xlarig::Log::print("| %6zu | %8" PRId64 " | %7s | %7s | %7s |",
                            thread->index(),
                            thread->affinity(),
                            Hashrate::format(m_hashrate->calc(thread->index(), Hashrate::ShortInterval),  num1, sizeof num1),
                            Hashrate::format(m_hashrate->calc(thread->index(), Hashrate::MediumInterval), num2, sizeof num2),
                            Hashrate::format(m_hashrate->calc(thread->index(), Hashrate::LargeInterval),  num3, sizeof num3)
                            );

             i++;
        }
    }

    m_hashrate->print();
}


void Workers::setEnabled(bool enabled)
{
    if (m_enabled == enabled) {
        return;
    }

    m_enabled = enabled;
    if (!m_active) {
        return;
    }

    m_paused = enabled ? 0 : 1;
    m_sequence++;
}


void Workers::setJob(const xlarig::Job &job, bool donate)
{
    uv_rwlock_wrlock(&m_rwlock);
    m_job = job;

    if (donate) {
        m_job.setPoolId(-1);
    }
    uv_rwlock_wrunlock(&m_rwlock);

    m_active = true;
    if (!m_enabled) {
        return;
    }

    m_sequence++;
    m_paused = 0;
}


void Workers::start(xlarig::Controller *controller)
{
#   ifdef APP_DEBUG
    LOG_NOTICE("THREADS ------------------------------------------------------------------");
    for (const xlarig::IThread *thread : controller->config()->threads()) {
        thread->print();
    }
    LOG_NOTICE("--------------------------------------------------------------------------");
#   endif

#   ifndef XMRIG_NO_ASM
    xlarig::CpuThread::patchAsmVariants();
#   endif

    m_controller = controller;

    const std::vector<xlarig::IThread *> &threads = controller->config()->threads();
    m_status.algo    = controller->config()->algorithm().algo();
    m_status.variant = controller->config()->algorithm().variant();
    m_status.threads = threads.size();

    for (const xlarig::IThread *thread : threads) {
       m_status.ways += thread->multiway();
    }

    m_hashrate = new Hashrate(threads.size(), controller);

    uv_mutex_init(&m_mutex);
    uv_rwlock_init(&m_rwlock);

#   ifdef XMRIG_ALGO_RANDOMX
    uv_rwlock_init(&m_rx_dataset_lock);
#   endif

    m_sequence = 1;
    m_paused   = 1;

    m_async = new uv_async_t;
    uv_async_init(uv_default_loop(), m_async, Workers::onResult);

    m_timer = new uv_timer_t;
    uv_timer_init(uv_default_loop(), m_timer);
    uv_timer_start(m_timer, Workers::onTick, 500, 500);

    uint32_t offset = 0;

    for (xlarig::IThread *thread : threads) {
        ThreadHandle *handle = new ThreadHandle(thread, offset, m_status.ways);
        offset += thread->multiway();

        m_workers.push_back(handle);
        handle->start(Workers::onReady);
    }
}


void Workers::stop()
{
    xlarig::Handle::close(m_timer);
    xlarig::Handle::close(m_async);
    m_hashrate->stop();

    m_paused   = 0;
    m_sequence = 0;

    for (size_t i = 0; i < m_workers.size(); ++i) {
        m_workers[i]->join();
    }
}


void Workers::submit(const xlarig::JobResult &result)
{
    uv_mutex_lock(&m_mutex);
    m_queue.push_back(result);
    uv_mutex_unlock(&m_mutex);

    uv_async_send(m_async);
}


#ifdef XMRIG_FEATURE_API
void Workers::threadsSummary(rapidjson::Document &doc)
{
    uv_mutex_lock(&m_mutex);
    const uint64_t pages[2] = { m_status.hugePages, m_status.pages };
    const uint64_t memory   = m_status.ways * xlarig::cn_select_memory(m_status.algo, m_status.variant);
    uv_mutex_unlock(&m_mutex);

    auto &allocator = doc.GetAllocator();

    rapidjson::Value hugepages(rapidjson::kArrayType);
    hugepages.PushBack(pages[0], allocator);
    hugepages.PushBack(pages[1], allocator);

    doc.AddMember("hugepages", hugepages, allocator);
    doc.AddMember("memory", memory, allocator);
}
#endif


void Workers::onReady(void *arg)
{
    auto handle = static_cast<ThreadHandle*>(arg);

    IWorker *worker = nullptr;

    switch (handle->config()->multiway()) {
    case 1:
        worker = new MultiWorker<1>(handle);
        break;

    case 2:
        worker = new MultiWorker<2>(handle);
        break;

    case 3:
        worker = new MultiWorker<3>(handle);
        break;

    case 4:
        worker = new MultiWorker<4>(handle);
        break;

    case 5:
        worker = new MultiWorker<5>(handle);
        break;

    default:
        break;
    }

    handle->setWorker(worker);

    if (!worker->selfTest()) {
        LOG_ERR("thread %zu error: \"hash self-test failed\".", handle->worker()->id());

        return;
    }

    start(worker);
}


void Workers::onResult(uv_async_t *)
{
    std::list<xlarig::JobResult> results;

    uv_mutex_lock(&m_mutex);
    while (!m_queue.empty()) {
        results.push_back(std::move(m_queue.front()));
        m_queue.pop_front();
    }
    uv_mutex_unlock(&m_mutex);

    for (auto result : results) {
        m_listener->onJobResult(result);
    }

    results.clear();
}


void Workers::onTick(uv_timer_t *)
{
    for (ThreadHandle *handle : m_workers) {
        if (!handle->worker()) {
            return;
        }

        m_hashrate->add(handle->threadId(), handle->worker()->hashCount(), handle->worker()->timestamp());
    }

    if ((m_ticks++ & 0xF) == 0)  {
        m_hashrate->updateHighest();
    }
}


void Workers::start(IWorker *worker)
{
    const Worker *w = static_cast<const Worker *>(worker);

    uv_mutex_lock(&m_mutex);
    m_status.started++;
    m_status.pages     += w->memory().pages;
    m_status.hugePages += w->memory().hugePages;

    if (m_status.started == m_status.threads) {
        const double percent = (double) m_status.hugePages / m_status.pages * 100.0;
        const size_t memory  = m_status.ways * xlarig::cn_select_memory(m_status.algo, m_status.variant) / 1024;

#       ifdef XMRIG_ALGO_RANDOMX
        if (m_status.algo == xlarig::RANDOM_X) {
            LOG_INFO(GREEN_BOLD("READY (CPU)") " threads " CYAN_BOLD("%zu(%zu)") " memory " CYAN_BOLD("%zu KB") "",
                     m_status.threads, m_status.ways, memory);
        } else
#       endif
        {
            LOG_INFO(GREEN_BOLD("READY (CPU)") " threads " CYAN_BOLD("%zu(%zu)") " huge pages %s%zu/%zu %1.0f%%\x1B[0m memory " CYAN_BOLD("%zu KB") "",
                     m_status.threads, m_status.ways,
                     (m_status.hugePages == m_status.pages ? GREEN_BOLD_S : (m_status.hugePages == 0 ? RED_BOLD_S : YELLOW_BOLD_S)),
                     m_status.hugePages, m_status.pages, percent, memory);
        }
    }

    uv_mutex_unlock(&m_mutex);

    worker->start();
}


#ifdef XMRIG_ALGO_RANDOMX
void Workers::updateDataset(const uint8_t* seed_hash, const uint32_t num_threads)
{
    // Check if we need to update cache and dataset
    if (memcmp(m_rx_seed_hash, seed_hash, sizeof(m_rx_seed_hash)) == 0)
        return;

    const uint32_t thread_id = m_rx_dataset_init_thread_counter++;
    LOG_DEBUG("Thread %u started updating RandomX dataset", thread_id);

    // Wait for all threads to get here
    do {
        if (m_sequence.load(std::memory_order_relaxed) == 0) {
            // Exit immediately if workers were stopped
            return;
        }
        std::this_thread::yield();
    } while (m_rx_dataset_init_thread_counter.load() != num_threads);

    // One of the threads updates cache
    uv_rwlock_wrlock(&m_rx_dataset_lock);
    if (memcmp(m_rx_seed_hash, seed_hash, sizeof(m_rx_seed_hash)) != 0) {
        memcpy(m_rx_seed_hash, seed_hash, sizeof(m_rx_seed_hash));
        defyx_init_cache(m_rx_cache, m_rx_seed_hash, sizeof(m_rx_seed_hash));
    }
    uv_rwlock_wrunlock(&m_rx_dataset_lock);

    // All threads update dataset
    const uint32_t a = (defyx_dataset_item_count() * thread_id) / num_threads;
    const uint32_t b = (defyx_dataset_item_count() * (thread_id + 1)) / num_threads;
    defyx_init_dataset(m_rx_dataset, m_rx_cache, a, b - a);

    LOG_DEBUG("Thread %u finished updating RandomX dataset", thread_id);

    // Wait for all threads to complete
    --m_rx_dataset_init_thread_counter;
    do {
        if (m_sequence.load(std::memory_order_relaxed) == 0) {
            // Exit immediately if workers were stopped
            return;
        }
        std::this_thread::yield();
    } while (m_rx_dataset_init_thread_counter.load() != 0);
}

defyx_dataset* Workers::getDataset()
{
    if (m_rx_dataset)
        return m_rx_dataset;

    uv_rwlock_wrlock(&m_rx_dataset_lock);
    if (!m_rx_dataset) {
        defyx_dataset* dataset = defyx_alloc_dataset(RANDOMX_FLAG_LARGE_PAGES);
        if (!dataset) {
            dataset = defyx_alloc_dataset(RANDOMX_FLAG_DEFAULT);
        }
        m_rx_cache = defyx_alloc_cache(static_cast<defyx_flags>(RANDOMX_FLAG_JIT | RANDOMX_FLAG_LARGE_PAGES));
        if (!m_rx_cache) {
            m_rx_cache = defyx_alloc_cache(RANDOMX_FLAG_JIT);
        }
        m_rx_dataset = dataset;
    }
    uv_rwlock_wrunlock(&m_rx_dataset_lock);

    return m_rx_dataset;
}
#endif
