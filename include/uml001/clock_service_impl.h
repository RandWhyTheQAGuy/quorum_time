#pragma once

#include <grpcpp/grpcpp.h>
#include "proto/clock.grpc.pb.h"
#include "main_ntp.cpp" // Assuming definitions are accessible

class ClockServiceImpl final : public uml001::ClockService::Service {
public:
    ClockServiceImpl(ProductionStore& store, const uml001::ClockGovernor& gov) 
        : store_(store), governor_(gov) {}

    grpc::Status GetTime(grpc::ServerContext* context, 
                        const uml001::GetTimeRequest* request, 
                        uml001::TimeResponse* response) override {
        
        auto state_opt = store_.get();
        if (!state_opt) {
            return grpc::Status(grpc::StatusCode::UNAVAILABLE, "Clock not yet synchronized.");
        }

        response->set_unix_timestamp(state_opt->unix_timestamp());
        response->set_drift_applied(state_opt->drift_applied());
        response->set_monotonic_version(state_opt->monotonic_version());
        response->set_signature(state_opt->signature());
        response->set_leader_id(state_opt->leader_id());

        return grpc::Status::OK;
    }

    grpc::Status GetStatus(grpc::ServerContext* context, 
                          const uml001::GetStatusRequest* request, 
                          uml001::StatusResponse* response) override {
        
        auto state = store_.get();
        response->set_operational(state.has_value());
        // Note: Governor current_count is private in your snippet; 
        // you may need to add a getter to ClockGovernor for this.
        response->set_quorum_size(15); 
        
        return grpc::Status::OK;
    }

private:
    ProductionStore& store_;
    const uml001::ClockGovernor& governor_;
};