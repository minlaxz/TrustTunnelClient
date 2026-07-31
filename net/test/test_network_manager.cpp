#include <gtest/gtest.h>

#include "net/network_manager.h"

class NetworkManagerTest : public testing::Test {
protected:
    void SetUp() override {
        ag::vpn_network_manager_set_tunnel_active(false);
    }

    void TearDown() override {
        ag::vpn_network_manager_set_tunnel_active(false);
    }
};

TEST_F(NetworkManagerTest, TunnelActiveState) {
    ASSERT_FALSE(ag::vpn_network_manager_get_tunnel_active());

    ag::vpn_network_manager_set_tunnel_active(true);
    ASSERT_TRUE(ag::vpn_network_manager_get_tunnel_active());

    ag::vpn_network_manager_set_tunnel_active(false);
    ASSERT_FALSE(ag::vpn_network_manager_get_tunnel_active());
}

TEST_F(NetworkManagerTest, TunnelActiveStateIsIdempotent) {
    ag::vpn_network_manager_set_tunnel_active(true);
    ag::vpn_network_manager_set_tunnel_active(true);
    ASSERT_TRUE(ag::vpn_network_manager_get_tunnel_active());

    ag::vpn_network_manager_set_tunnel_active(false);
    ag::vpn_network_manager_set_tunnel_active(false);
    ASSERT_FALSE(ag::vpn_network_manager_get_tunnel_active());
}