/* XMRig and XLArig
 * Copyright 2010      Jeff Garzik <jgarzik@pobox.com>
 * Copyright 2012-2014 pooler      <pooler@litecoinpool.org>
 * Copyright 2014      Lucas Jones <https://github.com/lucasjones>
 * Copyright 2014-2016 Wolf9466    <https://github.com/OhGodAPet>
 * Copyright 2016      Jay D Dee   <jayddee246@gmail.com>
 * Copyright 2017-2018 XMR-Stak    <https://github.com/fireice-uk>, <https://github.com/psychocrypt>
 * Copyright 2016-2018 XLArig       <https://github.com/xmrig>, <support@xmrig.com>
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

#ifndef XMRIG_ASM_H
#define XMRIG_ASM_H


#include "common/xlarig.h"
#include "rapidjson/fwd.h"


namespace xlarig {


class Asm
{
public:
    static Assembly parse(const char *assembly, Assembly defaultValue = ASM_AUTO);
    static Assembly parse(const rapidjson::Value &value, Assembly defaultValue = ASM_AUTO);
    static const char *toString(Assembly assembly);
    static rapidjson::Value toJSON(Assembly assembly);

    inline static Assembly parse(bool enable) { return enable ? ASM_AUTO : ASM_NONE; }
};


} /* namespace xlarig */


#endif /* XMRIG_ASM_H */
