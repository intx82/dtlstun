
#ifndef __IO_H
#define __IO_H

#include <atomic>
#include <cstdint>
#include <cstring>
#include <functional>
#include <iostream>
#include <pthread.h>
#include <stdexcept>
#include <string>
#include <thread>

class io_t
{
public:
    struct endpoint_t
    {
        std::string host;
        uint16_t port;
    };

    using receive_callback = std::function<void(const endpoint_t &from, const uint8_t *data, size_t len, io_t &self)>;

    virtual void write(const endpoint_t &to, const uint8_t *data, size_t len) = 0;

    virtual ~io_t(void) = default;

    template <typename t>
    t *get_user_data() const
    {
        return reinterpret_cast<t *>(user_data_);
    }

    template <typename t>
    void set_user_data(t *data)
    {
        user_data_ = reinterpret_cast<void *>(data);
    }

    static void set_thread_name(const char *name)
    {
        pthread_setname_np(pthread_self(), name);
    }

private:
    void *user_data_ = nullptr;
};
#endif
