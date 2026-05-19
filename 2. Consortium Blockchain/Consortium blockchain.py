from __future__ import annotations

import hashlib
import json
import os
import random
import time
from dataclasses import dataclass, asdict, field
from datetime import datetime
from enum import Enum
from typing import Dict, List, Literal, Optional, Set, Tuple

from cert_store import CertStore

# Default folder for local data (Excel files). Created on first use.
DEFAULT_DATA_DIR = "blockchain_data"


class OrgRole(str, Enum):
    """Organization roles in the consortium."""

    PRODUCER = "PRODUCER"
    TRANSPORTER = "TRANSPORTER"
    REGULATOR = "REGULATOR"
    DISPOSAL = "DISPOSAL"


class UserRole(str, Enum):
    """System login user roles."""

    ADMIN = "ADMIN"
    TRANSPORTER = "TRANSPORTER"
    REGULATOR = "REGULATOR"


@dataclass
class Organization:
    """An organization in the consortium."""

    org_id: str
    name: str
    role: OrgRole


@dataclass
class UserAccount:
    """Identity from certificate (no password in code)."""

    username: str
    role: UserRole
    org_id: Optional[str]  # admin has no org mapping


@dataclass
class IoTRecord:
    """A single IoT telemetry record (full data stored locally; only hash on chain)."""

    shipment_id: str
    container_id: str
    radiation_level: float
    gps_lat: float
    gps_lng: float
    timestamp: float
    location: str = ""
    temperature: float = 0.0
    event_time: Optional[float] = None

    def payload_for_hash(self) -> str:
        """Canonical payload for hashing (must match Excel row content)."""
        return json.dumps(
            {
                "shipment_id": self.shipment_id,
                "container_id": self.container_id,
                "radiation_level": self.radiation_level,
                "gps_lat": self.gps_lat,
                "gps_lng": self.gps_lng,
                "timestamp": self.timestamp,
                "location": self.location,
                "temperature": self.temperature,
                "event_time": self.event_time or self.timestamp,
            },
            sort_keys=True,
        )

    def to_excel_row(self, index: int) -> Dict:
        """Row for Excel: index, timestamp, location, latitude, longitude, radiation_level, temperature, event_time."""
        return {
            "index": index,
            "timestamp": self.timestamp,
            "location": self.location or f"({self.gps_lat:.6f}, {self.gps_lng:.6f})",
            "latitude": self.gps_lat,
            "longitude": self.gps_lng,
            "radiation-level": self.radiation_level,
            "temperature": self.temperature,
            "event-time": self.event_time if self.event_time is not None else self.timestamp,
        }


@dataclass
class ChainRecord:
    """On-chain entry: only hash + metadata (actual data in local Excel)."""

    record_type: Literal["DATA", "ADMIN"]
    index: int
    timestamp: float
    data_hash: str
    file_name: Optional[str] = None  # for DATA: Excel filename under data_dir
    action_type: Optional[str] = None  # for ADMIN: REGISTER / ASSIGN / DEREGISTER

    def to_dict(self) -> Dict:
        return {
            "record_type": self.record_type,
            "index": self.index,
            "timestamp": self.timestamp,
            "data_hash": self.data_hash,
            "file_name": self.file_name,
            "action_type": self.action_type,
        }


@dataclass
class Endorsement:
    """A regulator endorsement for a transaction (timestamp + org_id)."""

    org_id: str
    timestamp: float


@dataclass
class Transaction:
    """A blockchain transaction carrying one IoTRecord."""

    tx_id: str
    record: IoTRecord
    submitted_by: str
    data_hash: str
    endorsements: List[Endorsement] = field(default_factory=list)

    def to_dict(self) -> Dict:
        return {
            "tx_id": self.tx_id,
            "record": asdict(self.record),
            "submitted_by": self.submitted_by,
            "data_hash": self.data_hash,
            "endorsements": [asdict(e) for e in self.endorsements],
        }


@dataclass
class Block:
    """A block containing only hash records (chain stores hashes only)."""

    index: int
    previous_hash: str
    timestamp: float
    records: List[ChainRecord]
    nonce: int = 0
    hash: str = ""

    def compute_hash(self) -> str:
        """Recompute the block hash from its contents."""
        block_string = json.dumps(
            {
                "index": self.index,
                "previous_hash": self.previous_hash,
                "timestamp": self.timestamp,
                "records": [r.to_dict() for r in self.records],
                "nonce": self.nonce,
            },
            sort_keys=True,
        )
        return hashlib.sha256(block_string.encode("utf-8")).hexdigest()

    def seal(self) -> None:
        """Compute and store the block hash."""
        self.hash = self.compute_hash()


class EndorsementPolicy:
    """Endorsement policy: which regulators must approve."""

    def __init__(self, required_regulator_ids: List[str]):
        self.required_regulator_ids = sorted(required_regulator_ids)

    def is_satisfied(self, endorsements: List[Endorsement]) -> bool:
        endorsed_ids = sorted({e.org_id for e in endorsements})
        return all(req in endorsed_ids for req in self.required_regulator_ids)


def _ensure_data_dir(data_dir: str) -> None:
    os.makedirs(data_dir, exist_ok=True)


def _excel_filename_from_timestamp(ts: float) -> str:
    """Filename for on-chain time, e.g. 2026-02-25_14-30-00.xlsx"""
    dt = datetime.fromtimestamp(ts)
    return dt.strftime("%Y-%m-%d_%H-%M-%S") + ".xlsx"


def write_iot_to_excel(record: IoTRecord, index: int, data_dir: str) -> Tuple[str, str]:
    """
    Write one IoT record to a new Excel file in data_dir.
    Filename = on-chain time. Returns (data_hash, file_name).
    """
    _ensure_data_dir(data_dir)
    try:
        import openpyxl
        from openpyxl import Workbook
    except ImportError:
        raise ImportError("openpyxl is required. Install with: pip install openpyxl")

    row = record.to_excel_row(index)
    ts = time.time()
    file_name = _excel_filename_from_timestamp(ts)
    path = os.path.join(data_dir, file_name)

    wb = Workbook()
    ws = wb.active
    ws.title = "Data"
    headers = list(row.keys())
    ws.append(headers)
    ws.append([row[h] for h in headers])
    wb.save(path)

    payload = json.dumps(row, sort_keys=True)
    data_hash = hashlib.sha256(payload.encode("utf-8")).hexdigest()
    return data_hash, file_name


class Ledger:
    """
    Ledger stores only hashes on-chain. Full data is in local Excel under data_dir.
    """

    def __init__(self, data_dir: str = DEFAULT_DATA_DIR) -> None:
        self.blocks: List[Block] = []
        self.data_dir = data_dir
        self._next_data_index = 1

    def add_genesis_block(self) -> None:
        """Create the genesis block."""
        if self.blocks:
            return
        genesis = Block(
            index=0,
            previous_hash="0" * 64,
            timestamp=time.time(),
            records=[],
        )
        genesis.seal()
        self.blocks.append(genesis)

    def add_block(self, records: List[ChainRecord]) -> Block:
        """Append a new block (hash-only records)."""
        if not self.blocks:
            self.add_genesis_block()

        prev_hash = self.blocks[-1].hash
        block = Block(
            index=len(self.blocks),
            previous_hash=prev_hash,
            timestamp=time.time(),
            records=records,
        )
        block.seal()
        self.blocks.append(block)
        return block

    def add_data_record(self, iot_record: IoTRecord) -> ChainRecord:
        """Write IoT data to Excel, compute hash, append one DATA record to chain."""
        if not self.blocks:
            self.add_genesis_block()
        idx = self._next_data_index
        self._next_data_index += 1
        data_hash, file_name = write_iot_to_excel(iot_record, idx, self.data_dir)
        rec = ChainRecord(
            record_type="DATA",
            index=idx,
            timestamp=time.time(),
            data_hash=data_hash,
            file_name=file_name,
        )
        self.add_block([rec])
        return rec

    def add_admin_record(self, action_type: str, payload_hash: str) -> ChainRecord:
        """Append one ADMIN record (member change) to chain."""
        if not self.blocks:
            self.add_genesis_block()
        idx = self._next_data_index
        self._next_data_index += 1
        rec = ChainRecord(
            record_type="ADMIN",
            index=idx,
            timestamp=time.time(),
            data_hash=payload_hash,
            action_type=action_type,
        )
        self.add_block([rec])
        return rec

    def validate_chain(self) -> Tuple[bool, List[str]]:
        """Validate block hashes and previous_hash links."""
        errors: List[str] = []

        for i, block in enumerate(self.blocks):
            computed_hash = block.compute_hash()
            if block.hash != computed_hash:
                errors.append(
                    f"Block {i} hash mismatch: stored={block.hash}, recomputed={computed_hash}"
                )

            if i > 0:
                prev = self.blocks[i - 1]
                if block.previous_hash != prev.hash:
                    errors.append(
                        f"Block {i} previous_hash mismatch: {block.previous_hash} != {prev.hash}"
                    )

        return len(errors) == 0, errors


class ConsortiumNetwork:
    """
    Consortium network abstraction:
    - manages organizations (producer/transporter/regulators/etc.)
    - collects endorsements per policy
    - commits endorsed transactions to the ledger
    """

    def __init__(
        self,
        organizations: List[Organization],
        policy: EndorsementPolicy,
        ledger: Ledger,
    ) -> None:
        self.organizations: Dict[str, Organization] = {
            org.org_id: org for org in organizations
        }
        self.policy = policy
        self.ledger = ledger

    # ---------- Transaction building & commit ----------

    def create_transaction_from_iot_data(
        self,
        shipment_id: str,
        container_id: str,
        radiation_level: float,
        gps_lat: float,
        gps_lng: float,
        submitted_by_org_id: str,
        location: str = "",
        temperature: float = 0.0,
        event_time: Optional[float] = None,
    ) -> Transaction:
        """Create a transaction from IoT data (not endorsed, not committed yet)."""
        if submitted_by_org_id not in self.organizations:
            raise ValueError(f"Unknown org_id: {submitted_by_org_id}")

        ts = time.time()
        record = IoTRecord(
            shipment_id=shipment_id,
            container_id=container_id,
            radiation_level=radiation_level,
            gps_lat=gps_lat,
            gps_lng=gps_lng,
            timestamp=ts,
            location=location,
            temperature=temperature,
            event_time=event_time or ts,
        )

        payload = record.payload_for_hash()
        data_hash = hashlib.sha256(payload.encode("utf-8")).hexdigest()
        tx_id = hashlib.sha256(
            f"{payload}{submitted_by_org_id}{ts}".encode("utf-8")
        ).hexdigest()

        return Transaction(
            tx_id=tx_id,
            record=record,
            submitted_by=submitted_by_org_id,
            data_hash=data_hash,
        )

    def get_regulator_ids(self) -> List[str]:
        """Return org_id list of all regulators."""
        return [
            org_id
            for org_id, org in self.organizations.items()
            if org.role == OrgRole.REGULATOR
        ]

    def endorse_transaction(self, tx: Transaction, org_id: str) -> None:
        """Endorse a transaction by the given regulator org_id."""
        org = self.organizations.get(org_id)
        if not org:
            raise ValueError(f"Unknown org_id: {org_id}")
        if org.role != OrgRole.REGULATOR:
            raise PermissionError("Only regulators can endorse transactions.")

        if any(e.org_id == org_id for e in tx.endorsements):
            # Already endorsed; do not duplicate.
            return

        tx.endorsements.append(Endorsement(org_id=org_id, timestamp=time.time()))

    def submit_iot_data(
        self,
        shipment_id: str,
        container_id: str,
        radiation_level: float,
        gps_lat: float,
        gps_lng: float,
        submitted_by_org_id: str,
        auto_endorse: bool = True,
    ) -> Transaction:
        """
        Submit IoT data to the consortium chain:
        - submitted by transporter (or other org)
        - hash critical fields into data_hash
        - collect regulator endorsements (auto/manual)
        - commit to a new block once policy is satisfied
        """
        tx = self.create_transaction_from_iot_data(
            shipment_id=shipment_id,
            container_id=container_id,
            radiation_level=radiation_level,
            gps_lat=gps_lat,
            gps_lng=gps_lng,
            submitted_by_org_id=submitted_by_org_id,
        )

        # Collect regulator endorsements
        if auto_endorse:
            for reg_id in self.policy.required_regulator_ids:
                self.endorse_transaction(tx, reg_id)

        if not self.policy.is_satisfied(tx.endorsements):
            raise PermissionError(
                "Insufficient regulator endorsements; transaction cannot be committed."
            )

        self.ledger.add_data_record(tx.record)
        return tx


def simulate_iot_value(
    base: float = 5.0,
    fluctuation: float = 0.5,
    anomaly_chance: float = 0.1,
) -> float:
    """
    Simulate radiation level:
    - small fluctuations around base
    - occasional anomalies
    """
    value = random.gauss(base, fluctuation)
    if random.random() < anomaly_chance:
        value += random.uniform(5.0, 15.0)
    return max(0.0, value)


def simulate_gps_route(
    start_lat: float,
    start_lng: float,
    step: int,
) -> Tuple[float, float]:
    """Simulate GPS drift along a route (simple linear offset)."""
    lat = start_lat + 0.0005 * step
    lng = start_lng + 0.0003 * step
    return lat, lng


class PendingStatus(str, Enum):
    """Pending transaction status."""

    PENDING = "PENDING"
    REJECTED = "REJECTED"
    COMMITTED = "COMMITTED"


@dataclass
class PendingTransaction:
    """A transaction waiting for regulator decision(s)."""

    pending_id: int
    tx: Transaction
    status: PendingStatus = PendingStatus.PENDING
    approvals: Set[str] = field(default_factory=set)
    rejections: Set[str] = field(default_factory=set)


# All members who must vote on admin changes (register/assign/deregister).
ADMIN_VOTE_MEMBER_ORGS = ["TransporterOrg", "RegulatorA", "RegulatorB"]


class AdminActionType(str, Enum):
    REGISTER = "REGISTER"
    ASSIGN = "ASSIGN"
    DEREGISTER = "DEREGISTER"


@dataclass
class PendingAdminAction:
    """Admin proposal (register/assign/deregister) requiring all members' vote."""

    action_id: int
    action_type: AdminActionType
    payload: Dict  # e.g. {"username": "...", "password": "...", "role": "...", "org_id": "..."}
    status: PendingStatus = PendingStatus.PENDING
    approvals: Set[str] = field(default_factory=set)
    rejections: Set[str] = field(default_factory=set)


class AuthSystem:
    """Identity from certificates only; admin issues certs, no secrets in code."""

    def __init__(self, cert_store: Optional[CertStore] = None) -> None:
        self.cert_store = cert_store or CertStore()
        self.cert_store.bootstrap_if_needed()

    def _payload_to_user(self, payload: Dict) -> UserAccount:
        return UserAccount(
            username=payload["sub"],
            role=UserRole(payload["role"]),
            org_id=payload.get("org_id"),
        )

    def get_user(self, username: str) -> Optional[UserAccount]:
        """Get identity by username (certificate must exist and be valid)."""
        payload = self.cert_store.get_identity(username)
        if not payload:
            return None
        return self._payload_to_user(payload)

    def list_users(self) -> List[UserAccount]:
        """List all users that have a valid certificate."""
        users = []
        for name in self.cert_store.list_usernames():
            u = self.get_user(name)
            if u:
                users.append(u)
        return users

    def remove_user(self, username: str) -> bool:
        """Deregister: remove certificate and keys. Returns True if removed."""
        return self.cert_store.remove_certificate(username)

    def update_user_role(self, username: str, role: UserRole, org_id: Optional[str]) -> bool:
        """Re-issue certificate with new role/org. Returns True if updated."""
        return self.cert_store.reissue_certificate(username, role.value, org_id)

    def authenticate(self, username: str) -> Optional[UserAccount]:
        """Verify identity by valid certificate (no password)."""
        return self.get_user(username)

    def authenticate_with_signature(
        self, username: str, message: bytes, signature_b64: str
    ) -> Optional[UserAccount]:
        """Verify certificate and signature (for API: prove possession of private key)."""
        payload = self.cert_store.verify_identity_with_signature(
            username, message, signature_b64
        )
        if not payload:
            return None
        return self._payload_to_user(payload)


class BlockchainCLIApp:
    """
    CLI application:
    - login (admin / transporter / regulatorA / regulatorB)
    - menu actions: submit, endorse, validate, tamper, view chain, etc.
    """

    def __init__(self) -> None:
        random.seed(42)

        # 1) Consortium organizations
        self.orgs = [
            Organization("ProducerOrg", "Producer", OrgRole.PRODUCER),
            Organization("TransporterOrg", "Transporter", OrgRole.TRANSPORTER),
            Organization("RegulatorA", "Regulator A", OrgRole.REGULATOR),
            Organization("RegulatorB", "Regulator B", OrgRole.REGULATOR),
            Organization("DisposalOrg", "Disposal", OrgRole.DISPOSAL),
        ]
        policy = EndorsementPolicy(required_regulator_ids=["RegulatorA", "RegulatorB"])
        self.ledger = Ledger()
        _ensure_data_dir(self.ledger.data_dir)
        self.network = ConsortiumNetwork(self.orgs, policy, self.ledger)

        # 2) Auth system and pending queues
        self.auth = AuthSystem()
        self.pending_counter = 0
        self.pending_txs: Dict[int, PendingTransaction] = {}
        self.admin_action_counter = 0
        self.pending_admin_actions: Dict[int, PendingAdminAction] = {}

    # ---------- Common helpers ----------

    def _next_pending_id(self) -> int:
        self.pending_counter += 1
        return self.pending_counter

    def _print_chain_summary(self) -> None:
        if not self.ledger.blocks:
            print("The chain is empty.")
            return
        print("\n=== Blockchain View (hash-only) ===")
        for block in self.ledger.blocks:
            print(
                f"[Block {block.index}] time={time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(block.timestamp))}, "
                f"prev_hash={block.previous_hash}, hash={block.hash}"
            )
            for rec in block.records:
                extra = f" file={rec.file_name}" if rec.file_name else f" action={rec.action_type}"
                print(
                    f"  - {rec.record_type} index={rec.index} ts={rec.timestamp:.0f} data_hash={rec.data_hash[:16]}...{extra}"
                )
        print("=== End ===\n")

    def _print_pending_list(self, only_pending: bool = False) -> None:
        if not self.pending_txs:
            print("No pending transactions.")
            return
        print("\n=== Pending Transactions ===")
        for pid, ptx in self.pending_txs.items():
            if only_pending and ptx.status != PendingStatus.PENDING:
                continue
            r = ptx.tx.record
            t_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(r.timestamp))
            print(
                f"[ID={pid}] status={ptx.status.value}, shipment={r.shipment_id}, container={r.container_id}, "
                f"time={t_str}, radiation={r.radiation_level:.3f} μSv/h, "
                f"submitted_by={ptx.tx.submitted_by}, "
                f"approvals={list(ptx.approvals)}, rejections={list(ptx.rejections)}"
            )
        print("=== End ===\n")

    # ---------- Role menus ----------

    def _apply_admin_action(self, pa: PendingAdminAction) -> bool:
        """Apply the admin action and record on chain. Returns True if applied."""
        payload_str = json.dumps(pa.payload, sort_keys=True)
        payload_hash = hashlib.sha256(payload_str.encode("utf-8")).hexdigest()

        if pa.action_type == AdminActionType.REGISTER:
            if not self.auth.cert_store.issue_certificate(
                pa.payload["username"],
                pa.payload["role"],
                pa.payload.get("org_id"),
            ):
                return False
        elif pa.action_type == AdminActionType.ASSIGN:
            self.auth.update_user_role(
                pa.payload["username"],
                UserRole(pa.payload["role"]),
                pa.payload.get("org_id"),
            )
        elif pa.action_type == AdminActionType.DEREGISTER:
            self.auth.remove_user(pa.payload["username"])
        else:
            return False

        self.ledger.add_admin_record(pa.action_type.value, payload_hash)
        return True

    def _menu_admin(self, user: UserAccount) -> None:
        while True:
            print(
                "\n=== Admin Menu (member management only) ===\n"
                "1. Register member\n"
                "2. Assign member (change role/org)\n"
                "3. Deregister member\n"
                "4. View pending admin actions\n"
                "0. Logout\n"
            )
            choice = input("Select an option: ").strip()
            if choice == "1":
                username = input("New username: ").strip()
                if not username:
                    continue
                if self.auth.get_user(username):
                    print("Username already exists.")
                    continue
                role_str = input("Role (ADMIN/TRANSPORTER/REGULATOR): ").strip().upper()
                try:
                    role = UserRole(role_str)
                except ValueError:
                    print("Invalid role.")
                    continue
                if role == UserRole.ADMIN:
                    org_id = None
                elif role == UserRole.TRANSPORTER:
                    org_id = "TransporterOrg"
                else:
                    org_id = input("Org ID for REGULATOR (RegulatorA or RegulatorB): ").strip()
                    if not org_id:
                        print("org_id is required when role is REGULATOR.")
                        continue
                self.admin_action_counter += 1
                aid = self.admin_action_counter
                self.pending_admin_actions[aid] = PendingAdminAction(
                    action_id=aid,
                    action_type=AdminActionType.REGISTER,
                    payload={
                        "username": username,
                        "role": role_str,
                        "org_id": org_id,
                    },
                )
                print(f"Admin action #{aid} (Register {username}) created. All members must vote to approve.")
            elif choice == "2":
                username = input("Username to assign: ").strip()
                if not username or not self.auth.get_user(username):
                    print("User not found.")
                    continue
                role_str = input("New role (ADMIN/TRANSPORTER/REGULATOR): ").strip().upper()
                org_id = input("New org ID (for REGULATOR use RegulatorA or RegulatorB; or leave empty): ").strip() or None
                try:
                    UserRole(role_str)
                except ValueError:
                    print("Invalid role.")
                    continue
                self.admin_action_counter += 1
                aid = self.admin_action_counter
                self.pending_admin_actions[aid] = PendingAdminAction(
                    action_id=aid,
                    action_type=AdminActionType.ASSIGN,
                    payload={"username": username, "role": role_str, "org_id": org_id},
                )
                print(f"Admin action #{aid} (Assign {username}) created. All members must vote to approve.")
            elif choice == "3":
                username = input("Username to deregister: ").strip()
                if not username:
                    continue
                if username == user.username:
                    print("Cannot deregister yourself.")
                    continue
                if not self.auth.get_user(username):
                    print("User not found.")
                    continue
                self.admin_action_counter += 1
                aid = self.admin_action_counter
                self.pending_admin_actions[aid] = PendingAdminAction(
                    action_id=aid,
                    action_type=AdminActionType.DEREGISTER,
                    payload={"username": username},
                )
                print(f"Admin action #{aid} (Deregister {username}) created. All members must vote to approve.")
            elif choice == "4":
                if not self.pending_admin_actions:
                    print("No pending admin actions.")
                    continue
                for aid, pa in self.pending_admin_actions.items():
                    if pa.status != PendingStatus.PENDING:
                        continue
                    print(f"  #{aid} {pa.action_type.value} {pa.payload} approvals={pa.approvals} rejections={pa.rejections}")
            elif choice == "0":
                break
            else:
                print("Invalid option. Please try again.")

    def _do_vote_admin_action(self, voter_org_id: Optional[str]) -> None:
        """Let current user (by org) vote on a pending admin action."""
        if voter_org_id not in ADMIN_VOTE_MEMBER_ORGS:
            print("Your role cannot vote on admin actions.")
            return
        votable_items = [
            (aid, pa)
            for aid, pa in sorted(self.pending_admin_actions.items(), key=lambda x: x[0])
            if pa.status == PendingStatus.PENDING
            and voter_org_id not in pa.approvals
            and voter_org_id not in pa.rejections
        ]
        if not votable_items:
            print("No pending admin actions you can vote on.")
            return
        print("\nPending admin actions (select by number):")
        for idx, (aid, pa) in enumerate(votable_items, start=1):
            print(
                f"  [{idx}] #{aid} {pa.action_type.value} {pa.payload} "
                f"approvals={sorted(pa.approvals)} rejections={sorted(pa.rejections)}"
            )
        selected = input(f"Select action [1-{len(votable_items)}] (q to cancel): ").strip()
        if selected.lower() in {"q", "quit", "exit"}:
            print("Vote cancelled.")
            return
        try:
            choice_idx = int(selected)
        except ValueError:
            print("Invalid selection.")
            return
        if choice_idx < 1 or choice_idx > len(votable_items):
            print("Selection out of range.")
            return
        aid, pa = votable_items[choice_idx - 1]
        decision = input("Vote (Y=approve / N=reject): ").strip().upper()
        if decision == "Y":
            pa.approvals.add(voter_org_id)
            print(f"{voter_org_id} approved.")
        elif decision == "N":
            pa.rejections.add(voter_org_id)
            pa.status = PendingStatus.REJECTED
            print(f"{voter_org_id} rejected. Action will not be applied.")
            return
        else:
            print("Invalid input.")
            return
        if all(org in pa.approvals for org in ADMIN_VOTE_MEMBER_ORGS):
            if self._apply_admin_action(pa):
                pa.status = PendingStatus.COMMITTED
                print("All members approved. Action applied and recorded on chain.")
            else:
                print("Apply failed.")
        else:
            print(f"Approvals: {pa.approvals}. Need all of {ADMIN_VOTE_MEMBER_ORGS}.")

    def _menu_transporter(self, user: UserAccount) -> None:
        while True:
            print(
                "\n=== Transporter Menu ===\n"
                "1. Submit new IoT telemetry (to pending queue)\n"
                "2. View pending transactions\n"
                "3. View blockchain\n"
                "4. Vote on admin action\n"
                "0. Logout\n"
            )
            choice = input("Select an option: ").strip()
            if choice == "1":
                shipment_id = input("Enter shipment ID (default SHIP-001): ").strip() or "SHIP-001"
                container_id = input("Enter container ID (default CTR-0001): ").strip() or "CTR-0001"
                location = input("Location (optional): ").strip()
                base_lat, base_lng = 39.9042, 116.4074
                step = self.pending_counter
                radiation = simulate_iot_value()
                lat, lng = simulate_gps_route(base_lat, base_lng, step)
                temperature = round(random.gauss(20.0, 2.0), 2)

                tx = self.network.create_transaction_from_iot_data(
                    shipment_id=shipment_id,
                    container_id=container_id,
                    radiation_level=radiation,
                    gps_lat=lat,
                    gps_lng=lng,
                    submitted_by_org_id=user.org_id or "TransporterOrg",
                    location=location,
                    temperature=temperature,
                )
                pid = self._next_pending_id()
                self.pending_txs[pid] = PendingTransaction(
                    pending_id=pid,
                    tx=tx,
                    status=PendingStatus.PENDING,
                )
                print(
                    f"Created pending transaction ID={pid}, radiation={radiation:.3f} μSv/h, location=({lat:.6f}, {lng:.6f})"
                )
                print("Note: ask RegulatorA / RegulatorB to login and endorse this transaction.")
            elif choice == "2":
                self._print_pending_list(only_pending=False)
            elif choice == "3":
                self._print_chain_summary()
            elif choice == "4":
                self._do_vote_admin_action(user.org_id)
            elif choice == "0":
                break
            else:
                print("Invalid option. Please try again.")

    def _menu_regulator(self, user: UserAccount) -> None:
        assert user.org_id is not None
        org_id = user.org_id
        while True:
            print(
                f"\n=== Regulator ({org_id}) Menu ===\n"
                "1. View transactions pending my decision\n"
                "2. Approve / Reject a transaction\n"
                "3. View blockchain\n"
                "4. Vote on admin action\n"
                "0. Logout\n"
            )
            choice = input("Select an option: ").strip()
            if choice == "1":
                self._print_pending_list(only_pending=True)
            elif choice == "2":
                try:
                    pid_str = input("Enter pending transaction ID: ").strip()
                    pid = int(pid_str)
                    ptx = self.pending_txs.get(pid)
                    if not ptx:
                        print("Transaction not found.")
                        continue
                    if ptx.status != PendingStatus.PENDING:
                        print(f"Current status is {ptx.status.value}; cannot decide again.")
                        continue
                    if org_id in ptx.approvals or org_id in ptx.rejections:
                        print("You already made a decision for this transaction.")
                        continue

                    decision = input("Decision (Y=approve / N=reject): ").strip().upper()
                    if decision == "Y":
                        # Endorse + record approval
                        self.network.endorse_transaction(ptx.tx, org_id)
                        ptx.approvals.add(org_id)
                        print(f"{org_id} approved and endorsed the transaction.")
                        # Commit: write Excel locally and append hash to chain
                        if self.network.policy.is_satisfied(ptx.tx.endorsements):
                            self.ledger.add_data_record(ptx.tx.record)
                            ptx.status = PendingStatus.COMMITTED
                            print("All required regulators endorsed. Data written to local Excel and hash committed on chain.")
                    elif decision == "N":
                        ptx.rejections.add(org_id)
                        ptx.status = PendingStatus.REJECTED
                        print(f"{org_id} rejected the transaction. Marked REJECTED and will not be committed.")
                    else:
                        print("Invalid input. Use Y or N.")
                except Exception as exc:  # noqa: BLE001
                    print(f"Operation failed: {exc}")
            elif choice == "3":
                self._print_chain_summary()
            elif choice == "4":
                self._do_vote_admin_action(org_id)
            elif choice == "0":
                break
            else:
                print("Invalid option. Please try again.")

    # ---------- Main loop ----------

    def run(self) -> None:
        print("=== Radioactive Waste Transport Consortium Blockchain (CLI Demo) ===")
        print("Identity by certificate only (no passwords in code).")
        print("Usernames with certs: admin, transporter, regulatorA, regulatorB")

        while True:
            print("\n=== Login ===")
            username = input("Username (q to quit): ").strip()
            if username.lower() == "q":
                print("Exited.")
                break

            user = self.auth.authenticate(username)
            if not user:
                print("Login failed: no valid certificate for that username.")
                continue

            print(f"Login successful. Role: {user.role.value}")
            if user.role == UserRole.ADMIN:
                self._menu_admin(user)
            elif user.role == UserRole.TRANSPORTER:
                self._menu_transporter(user)
            elif user.role == UserRole.REGULATOR:
                self._menu_regulator(user)
            else:
                print("Unknown role. No menu available.")


if __name__ == "__main__":
    app = BlockchainCLIApp()
    app.run()

