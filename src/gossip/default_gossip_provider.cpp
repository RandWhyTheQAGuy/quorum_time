/*
 * Quorum Time — Open Trusted Time & Distributed Verification Framework
 * Copyright 2026 Randy Spickler (github.com/RandWhyTheQAGuy)
 * SPDX-License-Identifier: Apache-2.0
 *
 * Quorum Time is an open, verifiable, Byzantine-resilient trusted-time
 * system designed for modern distributed environments. It provides a
 * cryptographically anchored notion of time that can be aligned,
 * audited, and shared across domains without requiring centralized
 * trust.
 *
 * This project also includes the Aegis Semantic Passport components,
 * which complement Quorum Time by offering structured, verifiable
 * identity and capability attestations for agents and services.
 *
 * Core capabilities:
 *   - BFT Quorum Time: multi-authority, tamper-evident time agreement
 *                      with drift bounds, authority attestation, and
 *                      cross-domain alignment (AlignTime).
 *
 *   - Transparency Logging: append-only, hash-chained audit records
 *                           for time events, alignment proofs, and
 *                           key-rotation operations.
 *
 *   - Open Integration: designed for interoperability with distributed
 *                       systems, security-critical infrastructure,
 *                       autonomous agents, and research environments.
 *
 * Quorum Time is developed as an open-source project with a focus on
 * clarity, auditability, and long-term maintainability. Contributions,
 * issue reports, and discussions are welcome.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * This implementation is intended for open research, practical
 * deployment, and community-driven evolution of verifiable time and
 * distributed trust standards.
 */
#include "uml001/default_gossip_provider.h"

#include "GossipForwarder.h"
#include "TTLPolicy.h"

#include <algorithm>
#include <mutex>
#include <unordered_map>

namespace uml001 {

namespace {

bool topic_matches(const std::string& topic, const std::string& event_id)
{
    if (topic == "*") return true;
    if (!topic.empty() && topic.back() == '*') {
        const std::string prefix = topic.substr(0, topic.size() - 1);
        return event_id.rfind(prefix, 0) == 0;
    }
    return topic == event_id;
}

class LocalLoopTransport final : public gossip::IGossipTransport {
public:
    explicit LocalLoopTransport(std::vector<std::string> peers)
        : peers_(std::move(peers)) {}

    void set_sink(std::function<void(const SignedState&)> sink)
    {
        std::lock_guard<std::mutex> lock(mu_);
        sink_ = std::move(sink);
    }

    void send(const std::string&, const SignedState& msg) override
    {
        std::function<void(const SignedState&)> sink_copy;
        {
            std::lock_guard<std::mutex> lock(mu_);
            sink_copy = sink_;
        }
        if (sink_copy) {
            sink_copy(msg);
        }
    }

    std::vector<std::string> peers() const override
    {
        return peers_;
    }

private:
    std::vector<std::string> peers_;
    mutable std::mutex mu_;
    std::function<void(const SignedState&)> sink_;
};

} // namespace

struct DefaultGossipProvider::Impl {
    explicit Impl(std::string node_id, std::vector<std::string> peers)
        : transport(std::make_shared<LocalLoopTransport>(std::move(peers)))
        , ttl_policy(std::make_shared<gossip::TTLPolicy>())
        , forwarder(std::make_unique<gossip::GossipForwarder>(transport, ttl_policy, std::move(node_id)))
    {
        auto self = this;
        transport->set_sink([self](const SignedState& msg) { self->dispatch(msg); });
        forwarder->set_ingest_handler([self](const SignedState& msg) { self->dispatch(msg); });
    }

    void dispatch(const SignedState& msg)
    {
        std::vector<GossipCallback> targets;
        {
            std::lock_guard<std::mutex> lock(mu);
            for (const auto& kv : subscribers) {
                if (topic_matches(kv.first, msg.event_id())) {
                    targets.insert(targets.end(), kv.second.begin(), kv.second.end());
                }
            }
        }
        for (const auto& cb : targets) {
            cb(msg);
        }
    }

    std::shared_ptr<LocalLoopTransport> transport;
    std::shared_ptr<gossip::TTLPolicy> ttl_policy;
    std::unique_ptr<gossip::GossipForwarder> forwarder;
    mutable std::mutex mu;
    std::unordered_map<std::string, std::vector<GossipCallback>> subscribers;
};

DefaultGossipProvider::DefaultGossipProvider(std::string node_id,
                                             std::vector<std::string> peers)
    : impl_(std::make_shared<Impl>(std::move(node_id), std::move(peers))) {}

void DefaultGossipProvider::broadcast(const SignedState& state)
{
    impl_->forwarder->send_to_peers(state);
}

void DefaultGossipProvider::subscribe(const std::string& topic, GossipCallback cb)
{
    std::lock_guard<std::mutex> lock(impl_->mu);
    impl_->subscribers[topic].push_back(std::move(cb));
}

bool DefaultGossipProvider::is_external() const
{
    return !impl_->transport->peers().empty();
}

uint32_t DefaultGossipProvider::cluster_size() const
{
    const auto peers = impl_->transport->peers();
    return static_cast<uint32_t>(peers.size() + 1U);
}

void DefaultGossipProvider::on_receive(const SignedState& state)
{
    impl_->forwarder->onReceive(state);
}

} // namespace uml001
