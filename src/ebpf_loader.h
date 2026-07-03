// src/ebpf_loader.h — RAII обёртки над libbpf

#pragma once
#include <bpf/libbpf.h>
#include <stdexcept>
#include <string>
#include <string_view>
#include <cstring>

namespace ebpf {

/* ── Исключения ───────────────────────────────────────────────────────── */
struct Error : std::runtime_error {
    using std::runtime_error::runtime_error;
};

/* ── BpfObject: RAII владелец bpf_object ─────────────────────────────── */
class BpfObject {
public:
    explicit BpfObject(std::string_view path)
        : obj_(bpf_object__open(path.data()))
    {
        if (!obj_)
            throw Error("bpf_object__open(\"" + std::string(path) + "\") failed");
        if (int err = bpf_object__load(obj_); err != 0)
            throw Error("bpf_object__load failed: " + std::string(strerror(-err)));
    }

    ~BpfObject() { if (obj_) bpf_object__close(obj_); }

    BpfObject(const BpfObject&)            = delete;
    BpfObject& operator=(const BpfObject&) = delete;
    BpfObject(BpfObject&& o) noexcept : obj_(o.obj_) { o.obj_ = nullptr; }

    [[nodiscard]] bpf_object* get() const noexcept { return obj_; }

    /* Найти и аттачить программу по имени секции */
    [[nodiscard]] bpf_link* attach_kprobe(std::string_view func_name,
                                           std::string_view prog_name) const
    {
        bpf_program *prog = bpf_object__find_program_by_name(obj_, prog_name.data());
        if (!prog)
            throw Error("Program not found: " + std::string(prog_name));
        bpf_link *link = bpf_program__attach_kprobe(prog, false, func_name.data());
        if (!link)
            throw Error("attach_kprobe failed for " + std::string(func_name));
        return link;
    }

    [[nodiscard]] bpf_link* attach_tracepoint(std::string_view category,
                                               std::string_view name,
                                               std::string_view prog_name) const
    {
        bpf_program *prog = bpf_object__find_program_by_name(obj_, prog_name.data());
        if (!prog)
            throw Error("Program not found: " + std::string(prog_name));
        bpf_link *link = bpf_program__attach_tracepoint(prog,
                                                          category.data(),
                                                          name.data());
        if (!link)
            throw Error("attach_tracepoint failed");
        return link;
    }

    [[nodiscard]] bpf_map* find_map(std::string_view name) const
    {
        bpf_map *m = bpf_object__find_map_by_name(obj_, name.data());
        if (!m)
            throw Error("Map not found: " + std::string(name));
        return m;
    }

private:
    bpf_object *obj_ = nullptr;
};

/* ── BpfLink: RAII владелец bpf_link ─────────────────────────────────── */
class BpfLink {
public:
    explicit BpfLink(bpf_link *l) : link_(l) {}
    ~BpfLink() { if (link_) bpf_link__destroy(link_); }

    BpfLink(const BpfLink&)            = delete;
    BpfLink& operator=(const BpfLink&) = delete;
    BpfLink(BpfLink&& o) noexcept : link_(o.link_) { o.link_ = nullptr; }

    [[nodiscard]] bpf_link* get() const noexcept { return link_; }

private:
    bpf_link *link_ = nullptr;
};

/* ── BpfRingBuffer: RAII обёртка ring_buffer ──────────────────────────── */
class BpfRingBuffer {
public:
    using Callback = ring_buffer_sample_fn;

    BpfRingBuffer(bpf_map *map, Callback cb, void *ctx)
        : rb_(ring_buffer__new(bpf_map__fd(map), cb, ctx, nullptr))
    {
        if (!rb_)
            throw Error("ring_buffer__new failed");
    }

    ~BpfRingBuffer() { if (rb_) ring_buffer__free(rb_); }

    BpfRingBuffer(const BpfRingBuffer&)            = delete;
    BpfRingBuffer& operator=(const BpfRingBuffer&) = delete;

    /* Блокирующий poll, timeout_ms = -1 → ждать вечно */
    int poll(int timeout_ms = 100) const
    {
        return ring_buffer__poll(rb_, timeout_ms);
    }

private:
    ring_buffer *rb_ = nullptr;
};

} // namespace ebpf
