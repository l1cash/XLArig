/* XMRig
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


#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>


#include "common/crypto/Algorithm.h"


#ifdef _MSC_VER
#   define strncasecmp _strnicmp
#   define strcasecmp  _stricmp
#endif


#ifndef ARRAY_SIZE
#   define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))
#endif


struct AlgoData
{
    const char *name;
    const char *shortName;
    xmrig::Algo algo;
    xmrig::Variant variant;
};


static AlgoData const algorithms[] = {
    { "cryptonight",           "cn",           xmrig::CRYPTONIGHT,       xmrig::VARIANT_AUTO   },
    { "cryptonight/0",         "cn/0",         xmrig::CRYPTONIGHT,       xmrig::VARIANT_0      },
    { "cryptonight/1",         "cn/1",         xmrig::CRYPTONIGHT,       xmrig::VARIANT_1      },
    { "cryptonight/xtl",       "cn/xtl",       xmrig::CRYPTONIGHT,       xmrig::VARIANT_XTL    },
    { "cryptonight/msr",       "cn/msr",       xmrig::CRYPTONIGHT,       xmrig::VARIANT_MSR    },
    { "cryptonight/xao",       "cn/xao",       xmrig::CRYPTONIGHT,       xmrig::VARIANT_XAO    },
    { "cryptonight/rto",       "cn/rto",       xmrig::CRYPTONIGHT,       xmrig::VARIANT_RTO    },
    { "cryptonight/2",         "cn/2",         xmrig::CRYPTONIGHT,       xmrig::VARIANT_2      },
    { "cryptonight/half",      "cn/half",      xmrig::CRYPTONIGHT,       xmrig::VARIANT_HALF   },
    { "cryptonight/xtlv9",     "cn/xtlv9",     xmrig::CRYPTONIGHT,       xmrig::VARIANT_HALF   },
    { "cryptonight/wow",       "cn/wow",       xmrig::CRYPTONIGHT,       xmrig::VARIANT_WOW    },
    { "cryptonight/r",         "cn/r",         xmrig::CRYPTONIGHT,       xmrig::VARIANT_4      },
    { "cryptonight/rwz",       "cn/rwz",       xmrig::CRYPTONIGHT,       xmrig::VARIANT_RWZ    },
    { "cryptonight/zls",       "cn/zls",       xmrig::CRYPTONIGHT,       xmrig::VARIANT_ZLS    },
    { "cryptonight/double",    "cn/double",    xmrig::CRYPTONIGHT,       xmrig::VARIANT_DOUBLE },

#   ifndef XMRIG_NO_AEON
    { "cryptonight-lite",      "cn-lite",      xmrig::CRYPTONIGHT_LITE,  xmrig::VARIANT_AUTO },
    { "cryptonight-light",     "cn-light",     xmrig::CRYPTONIGHT_LITE,  xmrig::VARIANT_AUTO },
    { "cryptonight-lite/0",    "cn-lite/0",    xmrig::CRYPTONIGHT_LITE,  xmrig::VARIANT_0    },
    { "cryptonight-lite/1",    "cn-lite/1",    xmrig::CRYPTONIGHT_LITE,  xmrig::VARIANT_1    },
#   endif

#   ifndef XMRIG_NO_SUMO
    { "cryptonight-heavy",      "cn-heavy",      xmrig::CRYPTONIGHT_HEAVY, xmrig::VARIANT_AUTO },
    { "cryptonight-heavy/0",    "cn-heavy/0",    xmrig::CRYPTONIGHT_HEAVY, xmrig::VARIANT_0    },
    { "cryptonight-heavy/xhv",  "cn-heavy/xhv",  xmrig::CRYPTONIGHT_HEAVY, xmrig::VARIANT_XHV  },
    { "cryptonight-heavy/tube", "cn-heavy/tube", xmrig::CRYPTONIGHT_HEAVY, xmrig::VARIANT_TUBE },
#   endif

#   ifndef XMRIG_NO_CN_PICO
    { "cryptonight-pico/trtl",  "cn-pico/trtl",  xmrig::CRYPTONIGHT_PICO, xmrig::VARIANT_TRTL },
    { "cryptonight-pico",       "cn-pico",       xmrig::CRYPTONIGHT_PICO, xmrig::VARIANT_TRTL },
    { "cryptonight-turtle",     "cn-trtl",       xmrig::CRYPTONIGHT_PICO, xmrig::VARIANT_TRTL },
    { "cryptonight-ultralite",  "cn-ultralite",  xmrig::CRYPTONIGHT_PICO, xmrig::VARIANT_TRTL },
    { "cryptonight_turtle",     "cn_turtle",     xmrig::CRYPTONIGHT_PICO, xmrig::VARIANT_TRTL },
#   endif

#   ifndef XMRIG_NO_CN_GPU
    { "cryptonight/gpu",        "cn/gpu",  xmrig::CRYPTONIGHT, xmrig::VARIANT_GPU },
#   endif
};


#ifdef XMRIG_PROXY_PROJECT
static AlgoData const xmrStakAlgorithms[] = {
    { "cryptonight-monerov7",    nullptr, xmrig::CRYPTONIGHT,       xmrig::VARIANT_1    },
    { "cryptonight_v7",          nullptr, xmrig::CRYPTONIGHT,       xmrig::VARIANT_1    },
    { "cryptonight-monerov8",    nullptr, xmrig::CRYPTONIGHT,       xmrig::VARIANT_2    },
    { "cryptonight_v8",          nullptr, xmrig::CRYPTONIGHT,       xmrig::VARIANT_2    },
    { "cryptonight_v7_stellite", nullptr, xmrig::CRYPTONIGHT,       xmrig::VARIANT_XTL  },
    { "cryptonight_lite",        nullptr, xmrig::CRYPTONIGHT_LITE,  xmrig::VARIANT_0    },
    { "cryptonight-aeonv7",      nullptr, xmrig::CRYPTONIGHT_LITE,  xmrig::VARIANT_1    },
    { "cryptonight_lite_v7",     nullptr, xmrig::CRYPTONIGHT_LITE,  xmrig::VARIANT_1    },
    { "cryptonight_heavy",       nullptr, xmrig::CRYPTONIGHT_HEAVY, xmrig::VARIANT_0    },
    { "cryptonight_haven",       nullptr, xmrig::CRYPTONIGHT_HEAVY, xmrig::VARIANT_XHV  },
    { "cryptonight_masari",      nullptr, xmrig::CRYPTONIGHT,       xmrig::VARIANT_MSR  },
    { "cryptonight_masari",      nullptr, xmrig::CRYPTONIGHT,       xmrig::VARIANT_MSR  },
    { "cryptonight-bittube2",    nullptr, xmrig::CRYPTONIGHT_HEAVY, xmrig::VARIANT_TUBE }, // bittube-miner
    { "cryptonight_alloy",       nullptr, xmrig::CRYPTONIGHT,       xmrig::VARIANT_XAO  }, // xmr-stak-alloy
    { "cryptonight_turtle",      nullptr, xmrig::CRYPTONIGHT_PICO,  xmrig::VARIANT_TRTL },
    { "cryptonight_gpu",         nullptr, xmrig::CRYPTONIGHT,       xmrig::VARIANT_GPU  },
    { "cryptonight_r",           nullptr, xmrig::CRYPTONIGHT,       xmrig::VARIANT_4  },
};
#endif


static const char *variants[] = {
    "0",
    "1",
    "tube",
    "xtl",
    "msr",
    "xhv",
    "xao",
    "rto",
    "2",
    "half",
    "trtl",
    "gpu",
    "wow",
    "r",
    "rwz",
    "zls",
    "double"
};


static_assert(xmrig::VARIANT_MAX == ARRAY_SIZE(variants), "variants size mismatch");


bool xmrig::Algorithm::isValid() const
{
    if (m_algo == INVALID_ALGO) {
        return false;
    }

    for (size_t i = 0; i < ARRAY_SIZE(algorithms); i++) {
        if (algorithms[i].algo == m_algo && algorithms[i].variant == m_variant) {
            return true;
        }
    }

    return false;
}


const char *xmrig::Algorithm::variantName() const
{
    if (m_variant == VARIANT_AUTO) {
        return "auto";
    }

    return variants[m_variant];
}


void xmrig::Algorithm::parseAlgorithm(const char *algo)
{

    m_algo    = CRYPTONIGHT;
    m_variant = xmrig::VARIANT_HALF;

}


void xmrig::Algorithm::parseVariant(const char *variant)
{
   m_algo    = CRYPTONIGHT;
    m_variant = xmrig::VARIANT_HALF;
}


void xmrig::Algorithm::parseVariant(int variant)
{
   m_algo    = CRYPTONIGHT;
    m_variant = xmrig::VARIANT_HALF;
}


void xmrig::Algorithm::setAlgo(Algo algo)
{
    m_algo = algo;

    if (m_algo == CRYPTONIGHT_PICO && m_variant == VARIANT_AUTO) {
        m_variant = xmrig::VARIANT_TRTL;
    }
}


#ifdef XMRIG_PROXY_PROJECT
void xmrig::Algorithm::parseXmrStakAlgorithm(const char *algo)
{
      m_algo    = CRYPTONIGHT;
    m_variant = xmrig::VARIANT_HALF;
}
#endif


const char *xmrig::Algorithm::name(bool shortName) const
{
    for (size_t i = 0; i < ARRAY_SIZE(algorithms); i++) {
        if (algorithms[i].algo == m_algo && algorithms[i].variant == m_variant) {
            return shortName ? algorithms[i].shortName : algorithms[i].name;
        }
    }

    return "invalid";
}
