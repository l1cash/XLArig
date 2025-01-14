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

#ifndef XMRIG_BUFFER_H
#define XMRIG_BUFFER_H


#include "base/tools/String.h"


namespace xlarig {


class Buffer
{
public:
    Buffer();
    Buffer(Buffer &&other);
    Buffer(const Buffer &other);
    Buffer(const char *data, size_t size);
    Buffer(size_t size);
    ~Buffer();


    inline char *data()                   { return m_data; }
    inline const char *data() const       { return m_data; }
    inline size_t size() const            { return m_size; }
    inline void from(const Buffer &other) { from(other.data(), other.size()); }


    void from(const char *data, size_t size);


    inline Buffer &operator=(const Buffer &other) { from(other); return *this; }
    inline Buffer &operator=(Buffer &&other)      { move(std::move(other)); return *this; }


    static Buffer allocUnsafe(size_t size);
    static inline Buffer alloc(size_t size) { return Buffer(size); }


    inline static bool fromHex(const char *in, size_t size, char *out)    { return fromHex(reinterpret_cast<const uint8_t *>(in), size, reinterpret_cast<uint8_t *>(out)); }
    inline static bool fromHex(const char *in, size_t size, uint8_t *out) { return fromHex(reinterpret_cast<const uint8_t *>(in), size, out); }
    inline static Buffer fromHex(const char *data)                        { return fromHex(data, strlen(data)); }
    inline static Buffer fromHex(const String &str)                       { return fromHex(str.data(), str.size()); }
    inline static void toHex(const char *in, size_t size, char *out)      { return toHex(reinterpret_cast<const uint8_t *>(in), size, reinterpret_cast<uint8_t *>(out)); }
    inline static void toHex(const uint8_t *in, size_t size, char *out)   { return toHex(in, size, reinterpret_cast<uint8_t *>(out)); }

    static bool fromHex(const uint8_t *in, size_t size, uint8_t *out);
    static Buffer fromHex(const char *data, size_t size);
    static String toHex(const uint8_t *in, size_t size);
    static void toHex(const uint8_t *in, size_t size, uint8_t *out);
    String toHex() const;

private:
    void copy(const char *data, size_t size);
    void move(Buffer &&other);

    char *m_data;
    size_t m_size;
};


} /* namespace xlarig */


#endif /* XMRIG_BUFFER_H */
