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


#include <stdlib.h>
#include <sys/mman.h>


#include "base/io/log/Log.h"
#include "common/xlarig.h"
#include "crypto/common/portable/mm_malloc.h"
#include "crypto/common/VirtualMemory.h"
#include "crypto/cn/CryptoNight.h"
#include "Mem.h"


#if defined(__APPLE__)
#   include <mach/vm_statistics.h>
#endif


void Mem::init(bool enabled)
{
    m_enabled = enabled;
}


void Mem::allocate(MemInfo &info, bool enabled)
{
    info.hugePages = 0;

    if (!enabled) {
        info.memory = static_cast<uint8_t*>(_mm_malloc(info.size, 4096));

        return;
    }

    info.memory = static_cast<uint8_t*>(xlarig::VirtualMemory::allocateLargePagesMemory(info.size));
    if (!info.memory) {
        return allocate(info, false);;
    }

    info.hugePages = info.pages;

    if (madvise(info.memory, info.size, MADV_RANDOM | MADV_WILLNEED) != 0) {
        LOG_ERR("madvise failed");
    }

    if (mlock(info.memory, info.size) == 0) {
        m_flags |= Lock;
    }
}


void Mem::release(MemInfo &info)
{
    if (info.hugePages) {
        if (m_flags & Lock) {
            munlock(info.memory, info.size);
        }

        xlarig::VirtualMemory::freeLargePagesMemory(info.memory, info.size);
    }
    else {
        _mm_free(info.memory);
    }
}
