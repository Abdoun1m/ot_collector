#!/usr/bin/env sh
set -eu

# Safe snippet template for integrating ot_collector into an existing attach_ot.sh flow.
# Adjust helper function names to match your script conventions.
#
# Goal:
# - container: ot_collector
# - bridge: br-labshock
# - IP: 192.168.1.70/24
#
# Preconditions:
# - ot_collector container is running (network_mode: none).
# - OVS bridge br-labshock already exists.

CONTAINER_NAME="${CONTAINER_NAME:-ot_collector}"
BRIDGE_NAME="${BRIDGE_NAME:-br-labshock}"
COLLECTOR_IP_CIDR="${COLLECTOR_IP_CIDR:-192.168.1.70/24}"

echo "Attach snippet for ${CONTAINER_NAME} -> ${BRIDGE_NAME} (${COLLECTOR_IP_CIDR})"
echo "Integrate this using your existing attach helpers."

# Example pseudo-flow (replace with your existing implementation):
# 1) resolve container PID
# PID="$(docker inspect -f '{{.State.Pid}}' "${CONTAINER_NAME}")"
#
# 2) create and move veth pair into container netns
# ip link add veth-${CONTAINER_NAME} type veth peer name eth1-${CONTAINER_NAME}
# ip link set eth1-${CONTAINER_NAME} netns "${PID}"
#
# 3) attach host side to OVS bridge
# ovs-vsctl add-port "${BRIDGE_NAME}" veth-${CONTAINER_NAME}
# ip link set veth-${CONTAINER_NAME} up
#
# 4) configure container side
# nsenter -t "${PID}" -n ip link set lo up
# nsenter -t "${PID}" -n ip link set eth1-${CONTAINER_NAME} name eth1
# nsenter -t "${PID}" -n ip addr add "${COLLECTOR_IP_CIDR}" dev eth1
# nsenter -t "${PID}" -n ip link set eth1 up

