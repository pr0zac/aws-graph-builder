"""EC2 scanner: fetches raw EC2 instance inventory via `ec2:DescribeInstances`.

Region-scoped -- EC2 has no global data, so a separate caller constructs one
`CachedClient`/one `Ec2Scanner` per enabled region.

`Ec2ScanResult.instances` holds raw boto3 `Instance` dicts exactly as AWS
returns them (PascalCase keys, e.g. `InstanceId`, `State`,
`IamInstanceProfile`) -- no renaming or filtering -- so `graph.builder` works
directly against real, well-documented AWS API response shapes rather than an
invented intermediate format. Note `DescribeInstances`'s nested
`Reservations[*].Instances[*]` shape is flattened here into a single flat
list; ARN construction (which needs the account id) is left to the
graph-building layer, not this scanner.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from aws_graph_builder.scan.base import CachedClient, ScanGap, Scanner

SERVICE = "ec2"


@dataclass
class Ec2ScanResult:
    region: str
    instances: list[dict[str, Any]] = field(default_factory=list)
    gaps: list[ScanGap] = field(default_factory=list)


class Ec2Scanner(Scanner):
    """Scans EC2 instances for a single region. Region-scoped -- a separate
    caller constructs one `CachedClient`/one `Ec2Scanner` per enabled region.
    """

    def __init__(self, client: CachedClient, *, region: str) -> None:
        self._client = client
        self._region = region

    @staticmethod
    def required_actions() -> list[str]:
        return ["ec2:DescribeInstances"]

    def scan(self) -> Ec2ScanResult:
        self._client.report("Fetching EC2 instances...")
        page = self._client.paginate("describe_instances", ["Reservations"])
        reservations = page["Reservations"] if page else []

        # DescribeInstances nests instances under each reservation --
        # flatten into a single flat list of raw Instance dicts.
        instances = [instance for reservation in reservations for instance in reservation.get("Instances", [])]
        self._client.report(f"  found {len(instances)} instance(s)")

        return Ec2ScanResult(
            region=self._region,
            instances=instances,
            # `self._client.gaps` accumulates across every call made above --
            # collect it once at the end rather than threading a list through.
            gaps=list(self._client.gaps),
        )
