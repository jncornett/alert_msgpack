// Copyright (c) 2016, Joel Cornett
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this
//    list of conditions and the following disclaimer.
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
// ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
// WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
// ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
// LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
// ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//
// The views and conclusions contained in the software and documentation are those
// of the authors and should not be interpreted as representing official policies,
// either expressed or implied, of the FreeBSD Project.

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <iostream>
#include <fstream>
#include <map>
#include <string>
#include <msgpack.hpp>

#include "detection/signature.h"
#include "framework/logger.h"
#include "framework/module.h"

#define s_name "alert_msgpack"

//-------------------------------------------------------------------------
// msgpack
//-------------------------------------------------------------------------

#define PACK_PAIR(key, value) \
    pk.pack(std::string(key)); \
    pk.pack(value)

#define PACK_STRING(key, value) \
    PACK_PAIR(key, std::string(value ? value : ""))

namespace
{

inline void pack_event(std::ostream& os, const Event& e)
{
    msgpack::packer<std::ostream> pk { &os };

    if ( e.sig_info )
        pk.pack_map(11);
    else
        pk.pack_map(4);

    PACK_PAIR("event_id", e.event_id);
    PACK_PAIR("event_reference", e.event_reference);
    PACK_PAIR("ref_time", e.ref_time.tv_sec);
    PACK_STRING("alt_msg", e.alt_msg);

    if ( e.sig_info )
    {
        const auto& si = *e.sig_info;
        PACK_PAIR("gid", si.generator);
        PACK_PAIR("sid", si.id);
        PACK_PAIR("rev", si.rev);
        PACK_PAIR("classification", si.class_id);
        PACK_PAIR("priority", si.priority);
        PACK_STRING("message", si.message);
        PACK_PAIR("text_rule", si.text_rule);
    }
}

}

//-------------------------------------------------------------------------
// module
//-------------------------------------------------------------------------

static const Parameter s_params[] =
{
    { "path", Parameter::PT_STRING, nullptr, "stdout",
        "path of file or socket to write to (or stderr/stdout)" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

#define s_help ""

class MsgPackModule : public Module
{
public:
    MsgPackModule() : Module(s_name, s_help, s_params) { }
    bool set(const char*, Value&, SnortConfig*) override;
    std::string path;
};

bool MsgPackModule::set(const char*, Value& v, SnortConfig*)
{
    if ( v.is("path") )
        path = v.get_string();
    else
        return false;

    return true;
}

//-------------------------------------------------------------------------
// plugin
//-------------------------------------------------------------------------

class MsgPackLogger : public Logger
{
public:
    MsgPackLogger(std::string path) : path { path } { }

    void open() override;
    void close() override;

    void alert(Packet*, const char* msg, Event*) override;

private:
    std::string path;
    std::ostream* stream = nullptr;
};

void MsgPackLogger::open()
{
    assert(!stream);
    assert(!path.empty());

    if ( path == "stdout" )
        stream = &std::cout;

    else if ( path == "stderr" )
        stream = &std::cerr;

    else
        stream = new std::ofstream(path);
}

void MsgPackLogger::close()
{
    assert(stream);

    if ( path != "stdout" && path != "stderr" )
        delete stream;

    stream = nullptr;
}

void MsgPackLogger::alert(Packet*, const char* msg, Event* e)
{
    pack_event(*stream, *e);
    stream->flush();
}

//-------------------------------------------------------------------------
// api
//-------------------------------------------------------------------------

static Module* mod_ctor()
{ return new MsgPackModule; }

static void mod_dtor(Module* m)
{ delete m; }

static Logger* msgpack_ctor(SnortConfig*, Module* m)
{ return new MsgPackLogger(static_cast<MsgPackModule*>(m)->path); }

static void msgpack_dtor(Logger* p)
{ delete p; }

static LogApi msgpack_api
{
    {
        PT_LOGGER,
        sizeof(LogApi),
        LOGAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        s_name,
        s_help,
        mod_ctor,
        mod_dtor
    },
    OUTPUT_TYPE_FLAG__ALERT,
    msgpack_ctor,
    msgpack_dtor
};

SO_PUBLIC const BaseApi* snort_plugins[] =
{
    &msgpack_api.base,
    nullptr
};
