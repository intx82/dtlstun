
#ifndef __IO_H
#define __IO_H

#include <pthread.h>

#include <atomic>
#include <cstdint>
#include <cstring>
#include <functional>
#include <iostream>
#include <stdexcept>
#include <string>
#include <thread>

class io_t
{
   public:
    struct endpoint_t {
        std::string host;
        uint16_t port;
    };

    enum state_t {
        NOT_CONNECTED,
        CONNECTING,
        CONNECTED,
        EXITING,
    };

    using receive_callback = std::function<void(const endpoint_t &from, const uint8_t *data, size_t len, io_t &self)>;
    using status_callback = std::function<void(state_t, io_t &)>;

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

    void set_status_cb(status_callback cb) {
        status_callback_ = cb;
    };

    void set_state(state_t state) {
        io_state_ = state;
        if (status_callback_) {
            status_callback_(io_state_, *this);
        }
    }

    state_t get_state() const {
        return io_state_;
    }

    void set_rx_cb(receive_callback& cb) {
        rx_cb_ = std::move(cb);
    }

    receive_callback& get_rx_cb() {
        return rx_cb_;
    }

   private:
    void *user_data_ = nullptr;
    status_callback status_callback_ = {};
    receive_callback rx_cb_ = {};
    state_t io_state_ = state_t::NOT_CONNECTED;
};
#endif
