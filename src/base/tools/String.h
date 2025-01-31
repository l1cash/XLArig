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

#ifndef XMRIG_STRING_H
#define XMRIG_STRING_H


#include <utility>
#include <vector>


#include "rapidjson/fwd.h"


namespace xlarig {


/**
 * @brief Simple C string wrapper.
 *
 * 1. I know about std:string.
 * 2. For some reason I prefer don't use std:string in miner, eg because of file size of MSYS2 builds.
 * 3. nullptr and JSON conversion supported.
 */
class String
{
public:
    inline String() : m_data(nullptr), m_size(0)                                     {}
    inline String(char *str) : m_data(str), m_size(str == nullptr ? 0 : strlen(str)) {}
    inline String(String &&other) : m_data(other.m_data), m_size(other.m_size)       { other.m_data = nullptr; other.m_size = 0; }

    String(const char *str);
    String(const char *str, size_t size);
    String(const String &other);

    inline ~String() { delete [] m_data; }


    bool isEqual(const char *str) const;
    bool isEqual(const String &other) const;


    inline bool contains(const char *str) const { return isNull() ? false : strstr(m_data, str) != nullptr; }


    inline bool isEmpty() const          { return size() == 0; }
    inline bool isNull() const           { return m_data == nullptr; }
    inline char *data()                  { return m_data; }
    inline const char *data() const      { return m_data; }
    inline size_t size() const           { return m_size; }


    inline bool operator!=(const char *str) const      { return !isEqual(str); }
    inline bool operator!=(const String &other) const  { return !isEqual(other); }
    inline bool operator<(const String &str) const     { return strcmp(data(), str.data()) < 0; }
    inline bool operator==(const char *str) const      { return isEqual(str); }
    inline bool operator==(const String &other) const  { return isEqual(other); }
    inline operator const char*() const                { return m_data; }
    inline String &operator=(char *str)                { move(str); return *this; }
    inline String &operator=(const char *str)          { copy(str); return *this; }
    inline String &operator=(const String &str)        { copy(str); return *this; }
    inline String &operator=(std::nullptr_t)           { delete [] m_data; m_data = nullptr; m_size = 0; return *this; }
    inline String &operator=(String &&other)           { move(std::move(other)); return *this; }

    rapidjson::Value toJSON() const;
    rapidjson::Value toJSON(rapidjson::Document &doc) const;
    std::vector<xlarig::String> split(char sep) const;
    String &toLower();

    static String join(const std::vector<xlarig::String> &vec, char sep);

private:
    void copy(const char *str);
    void copy(const String &other);
    void move(char *str);
    void move(String &&other);

    char *m_data;
    size_t m_size;
};


} /* namespace xlarig */


#endif /* XMRIG_STRING_H */
