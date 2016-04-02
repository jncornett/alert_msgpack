#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <iostream>
#include <fstream>
#include <map>
#include <string>
#include <msgpack.hpp>

#include "framework/logger.h"
#include "framework/module.h"

#define s_name "alert_msgpack"

//-------------------------------------------------------------------------
// msgpack
//-------------------------------------------------------------------------

namespace
{

inline void pack_event(std::ostream& os, const Event& e)
{
    msgpack::packer<std::ostream> pk { &os };
    pk.pack_map(4);
    pk.pack(std::string("event_id"));
    pk.pack(e.event_id);
    pk.pack(std::string("event_reference"));
    pk.pack(e.event_reference);
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
    MsgPackLogger(std::string) { }

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
    *stream << "TEST\n";
    pack_event(*stream, *e);
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
