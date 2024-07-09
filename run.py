import argparse
import logging
import os
import re
import signal
import subprocess
import sys
import time
from dataclasses import dataclass
from typing import Any, Generator, List, Optional

import docker
import miniupnpc

#!/usr/bin/env python3
log = logging.getLogger(__name__)
log.setLevel(os.environ.get("LOGLEVEL", "INFO").upper())
log.addHandler(logging.StreamHandler(sys.stdout))


containers: List[str] = os.environ.get("PORTICAL_CONTAINERS", "").split(",")
root: Optional[str] = os.environ.get("PORTICAL_UPNP_ROOT_URL")
duration: int = int(os.environ.get("PORTICAL_POLL_INTERVAL", 15))
rule_duration: int = int(os.environ.get("PORTICAL_RULE_DURATION", 3600))
label: str = "portical.upnp.forward"
verbose: bool = False
force: bool = False
spawn: Optional[str] = os.environ.get("PORTICAL_SPAWN_UPNPC_CONTAINER")
dry_run: bool = os.environ.get("PORTICAL_DRY_RUN", "false").lower() == "true"


args: List[str] = sys.argv[1:]
command = "update"

parser = argparse.ArgumentParser()
parser.add_argument(
    "-r", "--root", help="Set the root URL for UPnP", type=str, default=root
)
parser.add_argument(
    "-d",
    "--duration",
    help="Set the poll interval duration",
    type=int,
    default=duration,
)
parser.add_argument(
    "-l", "--label", help="Set the label for portical", type=str, default=label
)
parser.add_argument(
    "-v", "--verbose", help="Enable verbose mode", action="store_true", default=verbose
)
parser.add_argument(
    "-f", "--force", help="Force rule creation", action="store_true", default=force
)
parser.add_argument(
    "-s", "--spawn", help="Spawn UPnP container", action="store_true", default=spawn
)
parser.add_argument(
    "command",
    help="The command to run",
    choices=["update", "poll"],
    default=command,
)
parser.add_argument(
    "-c",
    "--container",
    help="The container to run the command on",
    type=str,
    default=containers,
    nargs="+",
)
parsed_args = parser.parse_args(args)

root = parsed_args.root
duration = parsed_args.duration
label = parsed_args.label
verbose = parsed_args.verbose
force = parsed_args.force
spawn = parsed_args.spawn
command = parsed_args.command
containers = parsed_args.container or []
containers = [container for container in containers if container]
assert(type(containers) == list)

docker_client = docker.from_env()

@dataclass(eq=True, frozen=True, order=True)
class UPNPRule:
    @staticmethod
    def build_rules_from_label(
        *, container_name: str, internal_ip: str, label: str
    ) -> Generator["UPNPRule", None, None]:
        for label_segment in label.split(","):
            yield from UPNPRule._build_rules_from_label_segment(
                container_name=container_name,
                internal_ip=internal_ip,
                label_segment=label_segment,
            )

    @staticmethod
    def _build_rules_from_label_segment(
        container_name: str, internal_ip: str, label_segment: str
    ) -> Generator["UPNPRule", None, None]:
        match = re.match(r"([0-9]+)(:([0-9]+))?(\/(tcp|udp))?", label_segment)
        if not match:
            return

        external_port = match.group(1)
        internal_port = match.group(3) or external_port
        protocol = match.group(5)
        if protocol:
            protocols = [protocol]
        else:
            protocols = ["tcp", "udp"]

        for p in protocols:
            description = f"portical: ({external_port}->{internal_ip}:{internal_port}/{protocol}) {container_name}"
            yield UPNPRule(
                container_name=container_name,
                description=description,
                protocol=p.upper(),
                external_port=int(external_port),
                internal_ip=internal_ip,
                internal_port=int(internal_port),
            )

    container_name: str
    description: str
    protocol: str
    external_port: int
    internal_ip: str
    internal_port: int
    ttl: int | None = None


class UPNPContainerProcessor:
    def __init__(self, containers: List[str]) -> None:
        self.containers = containers
        self.container_ips: dict[str, str] = {}
        self.existing_rules: dict[str, UPNPRule] = []
        self.desired_rules: list[UPNPRule] = []

        self.upnp = miniupnpc.UPnP()
        self.upnp.discoverdelay = 100
        self.upnp.discover()
        self.upnp.selectigd()
        self.internal_ip = str(self.upnp.lanaddr)

    def process(self) -> None:
        self.load_container_ips()
        self.load_existing_rules()
        self.load_desired_rules()
        for rule in self.desired_rules:
            self.forward(rule)

    def load_existing_rules(self):
        index = 0
        parsed_rules: set[UPNPRule] = set()
        while True:
            rule = self.upnp.getgenericportmapping(index)
            index += 1

            if rule == None:
                break
            (
                external_port,
                protocol,
                (internal_ip, internal_port),
                description,
                _,
                remote_host,
                ttl,
            ) = rule

            if not description.startswith(f"portical"):
                continue

            parsed_rules.add(
                UPNPRule(
                    protocol=protocol.upper(),
                    external_port=external_port,
                    internal_ip=internal_ip,
                    internal_port=internal_port,
                    description=description,
                    ttl=ttl,
                    container_name=description.split(" ")[-1],
                )
            )

        parsed_rules = sorted(parsed_rules)
        for parsed_rule in parsed_rules:
            log.debug("Found existing rule %s", str(parsed_rule))
        self.existing_rules = {x.description: x for x in parsed_rules}

    def load_desired_rules(self):
        desired_rules: set[UPNPRule] = set()
        for container in self.containers:
            # Query the docker API for each container and extract the desired rules
            # Append the desired rules to the `desired_rules` list
            desired_rules.update(self.generate_rules_for_container(container))

        desired_rules = sorted(desired_rules)

        for desired_rule in desired_rules:
            log.debug("Parsed desired rule %s", str(desired_rule))
        self.desired_rules = desired_rules

    def load_container_ips(self):
        for container in self.containers:
            container_ip = self.get_internal_ip_for_container(container)
            log.debug("Found ip '%s' for container '%s'", container_ip, container)
            self.container_ips[container] = container_ip

    def get_internal_ip_for_container(self, container: str) -> str:
        # Right now, we don't support this.
        # This would enable us to forward based on the IP for a macvlan/ipvlan
        enable_ip_lookup = False
        if enable_ip_lookup:
            networks = docker_client.networks.list(names=[container])
            if len(networks) == 0:
                log.error("Container '%s' has no networks", container)
                sys.exit(1)
            network_name = networks[0].name
            network = docker_client.networks.get(network_name)
            network_driver = network.attrs['Driver']
            return "1.2.3.4"
        return self.internal_ip

    def generate_rules_for_container(
        self, container: str
    ) -> Generator[UPNPRule, None, None]:
        log.debug("Generating rules for '%s' via docker api...", container)
        container_info = docker_client.api.inspect_container(container)
        labels = container_info['Config']['Labels']
        label_value = labels.get(label, "")
        if label_value == "published":
            log.debug(f"Extracting published ports for {container}... ")
            rules = []
            ports = container_info['NetworkSettings']['Ports']
            for port in ports:
                if ports[port] is not None:
                    for binding in ports[port]:
                        host_port = binding['HostPort']
                        rules.append(f"{host_port}:{port}")
            rules = "\n".join(rules)
            label_value = rules.replace("\n", ",")

        container_ip = self.container_ips[container]

        return UPNPRule.build_rules_from_label(
            container_name=container,
            internal_ip=container_ip,
            label=label_value,
        )

    def forward(self, rule: UPNPRule) -> None:
        log.debug(f"Setting up %s...", rule.description)
        existing = self.existing_rules.get(rule.description)

        should_delete = False
        if existing:
            if force:
                should_delete = True
            elif existing.ttl < (duration * 2):
                should_delete = True
            else:
                log.debug("Rule already exists. Skipping...")
                return

        if should_delete:
            log.debug("Removing existing rule... ")
            if not dry_run:
                self.upnp.deleteportmapping(
                    existing.external_port, existing.protocol.upper()
                )
            log.debug("DONE")

        log.debug("Adding new rule... ")
        if not dry_run:
            self.upnp.addportmapping(
                rule.external_port,
                rule.protocol.upper(),
                rule.internal_ip,
                rule.internal_port,
                rule.description,
                "",
                rule_duration,
            )
        log.debug("DONE")


def update() -> None:
    log.debug(f"Finding all containers with label '{label}' set...")
    current_run_containers = containers
    if not current_run_containers:
        current_run_containers = docker_client.containers.list(filters={"label": label})
        current_run_containers = [container.name for container in current_run_containers]
    UPNPContainerProcessor(current_run_containers).process()


def poll() -> None:
    while True:
        update()
        log.debug(f"Sleeping for {duration} seconds...")
        time.sleep(duration)

def handle_sigterm(signum, frame):
    log.info("Received SIGTERM signal. Exiting...")
    sys.exit(0)

def handle_sigkill(signum, frame):
    log.info("Received SIGKILL signal. Exiting...")
    sys.exit(0)

signal.signal(signal.SIGTERM, handle_sigterm)
signal.signal(signal.SIGKILL, handle_sigkill)
try:
    match command:
        case "update":
            update()
        case "poll":
            poll()
        case _:
            log.error(f"Error: '{command}' is not a valid command.")
            sys.exit(1)
except Exception as e:
    log.error(f"Error: %s", str(e), exc_info=e)
    sys.exit(1)
