from src.inventory import (
    count_users,
    count_privileged_users,
    count_network_devices,
)


def test_inventory_counts():
    assert count_users() == 8
    assert count_privileged_users() == 3
    assert count_network_devices() == 2