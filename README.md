# Alert Msgpack

A MessagePack alert plugin for [Snort 3](https://github.com/snortadmin/snort3).
This plugin outputs alert events in [MessagePack format](http://msgpack.org/index.html).

# Installation

In short:

    git clone https://github.com/jncornett/alert_msgpack.git
    mkdir build && cd build
    cmake ..
    make

## Dependencies

 - Snort 3: https://github.com/snortadmin/snort3
 - msgpack-c: https://github.com/msgpack/msgpack-c

## Notes

 - AlertMsgPack uses PkgConfig to locate its dependencies, so make sure that you set `PKG_CONFIG_PATH` appropriately

## Usage

To output alerts to a file:

    $ snort --plugin-path $alert_msgpack_path -A alert_msgpack --lua "{ path='output.msgpack' }" $snort_args
