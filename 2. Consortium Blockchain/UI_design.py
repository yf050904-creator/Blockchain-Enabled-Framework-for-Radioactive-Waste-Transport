from __future__ import annotations

import base64
import json
import os
import secrets
import sys
import time
from hashlib import sha256
from typing import Dict, List, Optional

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor, QFont
from PySide6.QtWidgets import (
    QAbstractItemView,
    QApplication,
    QComboBox,
    QFormLayout,
    QFrame,
    QGraphicsDropShadowEffect,
    QGroupBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QSizePolicy,
    QStackedWidget,
    QTabWidget,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from cert_store import CertStore, load_pem_file, sign_message
from radiation_chain import (
    ADMIN_VOTE_MEMBER_ORGS,
    AdminActionType,
    AuthSystem,
    ConsortiumNetwork,
    EndorsementPolicy,
    Ledger,
    OrgRole,
    Organization,
    PendingAdminAction,
    PendingStatus,
    PendingTransaction,
    UserAccount,
    UserRole,
    _ensure_data_dir,
    simulate_gps_route,
    simulate_iot_value,
)

# VS Code–inspired light theme (QSS)
VS_CODE_LIGHT_QSS = """
QMainWindow, QWidget {
    background-color: #f3f3f3;
    color: #242424;
    font-family: "Segoe UI", "Microsoft YaHei UI", sans-serif;
    font-size: 13px;
}
QLabel {
    background-color: transparent;
}
QTabWidget::pane {
    border: 1px solid #e5e5e5;
    border-radius: 2px;
    background: #ffffff;
    top: -1px;
}
QTabBar::tab {
    background: #ececec;
    color: #242424;
    padding: 8px 16px;
    margin-right: 2px;
    border: 1px solid #e5e5e5;
    border-bottom: none;
    border-top-left-radius: 3px;
    border-top-right-radius: 3px;
    min-width: 72px;
}
QTabBar::tab:selected {
    background: #ffffff;
    color: #0078d4;
    font-weight: 600;
}
QTabBar::tab:!selected:hover {
    background: #e8e8e8;
}
QTabBar::tab:disabled {
    color: #a0a0a0;
    background: #f0f0f0;
}
QLineEdit, QComboBox {
    background: #ffffff;
    border: 1px solid #e5e5e5;
    border-radius: 2px;
    padding: 6px 8px;
    min-height: 22px;
}
QLineEdit:focus, QComboBox:focus {
    border: 1px solid #0078d4;
}
QTextEdit {
    background: #ffffff;
    border: 1px solid #e5e5e5;
    border-radius: 2px;
    padding: 8px;
    selection-background-color: #cce4f7;
}
QPushButton {
    background: #0078d4;
    color: #ffffff;
    border: none;
    border-radius: 2px;
    padding: 8px 16px;
    font-weight: 600;
    min-height: 28px;
}
QPushButton:hover {
    background: #106ebe;
}
QPushButton:pressed {
    background: #005a9e;
}
QPushButton:disabled {
    background: #c8c8c8;
    color: #f5f5f5;
}
QPushButton#secondaryBtn {
    background: #ffffff;
    color: #242424;
    border: 1px solid #e5e5e5;
    font-weight: 500;
}
QPushButton#secondaryBtn:hover {
    background: #f0f0f0;
    border-color: #d0d0d0;
}
QGroupBox {
    font-weight: 600;
    border: 1px solid #e5e5e5;
    border-radius: 3px;
    margin-top: 14px;
    padding-top: 10px;
    background: #fafafa;
}
QGroupBox::title {
    subcontrol-origin: margin;
    left: 10px;
    padding: 0 6px;
    color: #242424;
}
QTableWidget {
    background: #ffffff;
    gridline-color: #e5e5e5;
    border: 1px solid #e5e5e5;
    border-radius: 2px;
    selection-background-color: #e4e6f1;
    selection-color: #242424;
}
QTableWidget::item:selected {
    background: #e4e6f1;
    color: #242424;
}
QHeaderView::section {
    background: #f3f3f3;
    color: #242424;
    padding: 8px 6px;
    border: 1px solid #e5e5e5;
    font-weight: 600;
}
QLabel#headerTitle {
    font-size: 15px;
    font-weight: 600;
    color: #242424;
}
QLabel#hintLabel {
    color: #616161;
    font-size: 12px;
}
/* Full-window login */
QWidget#loginPage {
    background-color: #eceef1;
}
QFrame#loginCard {
    background-color: #ffffff;
    border: 1px solid #d8dbdf;
    border-radius: 10px;
}
/* Global QWidget background must not paint gray on labels inside the card */
QFrame#loginCard QLabel {
    background-color: transparent;
}
QLabel#loginTitle {
    font-size: 24px;
    font-weight: 600;
    color: #1f2328;
    letter-spacing: -0.3px;
    background-color: transparent;
}
QLabel#loginUserLabel {
    font-size: 16px;
    font-weight: 600;
    color: #1f2328;
    background-color: transparent;
}
QPushButton#loginPrimaryBtn {
    min-height: 44px;
    font-size: 17px;
    padding: 12px 20px;
    border-radius: 6px;
}
QLineEdit#loginUsername {
    min-height: 40px;
    font-size: 15px;
    padding: 8px 12px;
    border-radius: 4px;
}
"""


def _now_ts() -> float:
    return time.time()


class ConsortiumEngine:
    """
    In-memory demo engine backing the UI.
    Chain hashes are stored in-memory; IoT full data is written to local Excel by Ledger.
    """

    def __init__(self) -> None:
        self.orgs = [
            Organization("ProducerOrg", "Producer", OrgRole.PRODUCER),
            Organization("TransporterOrg", "Transporter", OrgRole.TRANSPORTER),
            Organization("RegulatorA", "Regulator A", OrgRole.REGULATOR),
            Organization("RegulatorB", "Regulator B", OrgRole.REGULATOR),
            Organization("DisposalOrg", "Disposal", OrgRole.DISPOSAL),
        ]
        self.policy = EndorsementPolicy(required_regulator_ids=["RegulatorA", "RegulatorB"])
        self.ledger = Ledger()
        _ensure_data_dir(self.ledger.data_dir)
        self.network = ConsortiumNetwork(self.orgs, self.policy, self.ledger)
        self.auth = AuthSystem(CertStore())

        self.pending_counter = 0
        self.pending_txs: Dict[int, PendingTransaction] = {}

        self.admin_action_counter = 0
        self.pending_admin_actions: Dict[int, PendingAdminAction] = {}

    def _next_pending_id(self) -> int:
        self.pending_counter += 1
        return self.pending_counter

    def _next_admin_action_id(self) -> int:
        self.admin_action_counter += 1
        return self.admin_action_counter

    def submit_iot_pending(
        self,
        user: UserAccount,
        shipment_id: str,
        container_id: str,
        location: str,
        temperature: float,
    ) -> int:
        if user.role != UserRole.TRANSPORTER:
            raise PermissionError("Only Transporter can submit IoT data.")
        base_lat, base_lng = 39.9042, 116.4074
        radiation = simulate_iot_value()
        step = self.pending_counter + 1
        lat, lng = simulate_gps_route(base_lat, base_lng, step)

        tx = self.network.create_transaction_from_iot_data(
            shipment_id=shipment_id,
            container_id=container_id,
            radiation_level=radiation,
            gps_lat=lat,
            gps_lng=lng,
            submitted_by_org_id=user.org_id or "TransporterOrg",
            location=location,
            temperature=temperature,
            event_time=_now_ts(),
        )
        pid = self._next_pending_id()
        self.pending_txs[pid] = PendingTransaction(
            pending_id=pid,
            tx=tx,
            status=PendingStatus.PENDING,
        )
        return pid

    def list_pending_transactions(self, only_pending: bool = True) -> List[PendingTransaction]:
        items: List[PendingTransaction] = []
        for ptx in self.pending_txs.values():
            if only_pending and ptx.status != PendingStatus.PENDING:
                continue
            items.append(ptx)
        items.sort(key=lambda x: x.pending_id)
        return items

    def approve_transaction(self, user: UserAccount, pending_id: int) -> bool:
        if user.role != UserRole.REGULATOR:
            raise PermissionError("Only Regulators can approve IoT transactions.")
        ptx = self.pending_txs.get(pending_id)
        if not ptx:
            raise KeyError("Pending transaction not found.")
        if ptx.status != PendingStatus.PENDING:
            raise ValueError("Transaction is not pending.")
        if not user.org_id:
            raise ValueError("Regulator org_id is missing.")

        org_id = user.org_id
        self.network.endorse_transaction(ptx.tx, org_id)
        ptx.approvals.add(org_id)

        if self.policy.is_satisfied(ptx.tx.endorsements):
            self.ledger.add_data_record(ptx.tx.record)
            ptx.status = PendingStatus.COMMITTED
            return True
        return False

    def reject_transaction(self, user: UserAccount, pending_id: int) -> None:
        if user.role != UserRole.REGULATOR:
            raise PermissionError("Only Regulators can reject IoT transactions.")
        ptx = self.pending_txs.get(pending_id)
        if not ptx:
            raise KeyError("Pending transaction not found.")
        if ptx.status != PendingStatus.PENDING:
            raise ValueError("Transaction is not pending.")
        if not user.org_id:
            raise ValueError("Regulator org_id is missing.")
        org_id = user.org_id
        ptx.rejections.add(org_id)
        ptx.status = PendingStatus.REJECTED

    def create_admin_action(
        self,
        user: UserAccount,
        action_type: AdminActionType,
        payload: Dict,
    ) -> int:
        if user.role != UserRole.ADMIN:
            raise PermissionError("Only admin can create admin actions.")
        aid = self._next_admin_action_id()
        self.pending_admin_actions[aid] = PendingAdminAction(
            action_id=aid,
            action_type=action_type,
            payload=payload,
            status=PendingStatus.PENDING,
        )
        return aid

    def list_pending_admin_actions(self, only_pending: bool = True) -> List[PendingAdminAction]:
        items: List[PendingAdminAction] = []
        for pa in self.pending_admin_actions.values():
            if only_pending and pa.status != PendingStatus.PENDING:
                continue
            items.append(pa)
        items.sort(key=lambda x: x.action_id)
        return items

    def _apply_admin_action(self, pa: PendingAdminAction) -> bool:
        payload_str = json.dumps(pa.payload, sort_keys=True)
        payload_hash = sha256(payload_str.encode("utf-8")).hexdigest()

        if pa.action_type == AdminActionType.REGISTER:
            ok = self.auth.cert_store.issue_certificate(
                pa.payload["username"],
                pa.payload["role"],
                pa.payload.get("org_id"),
            )
            if not ok:
                return False
            self.ledger.add_admin_record(pa.action_type.value, payload_hash)
            return True
        if pa.action_type == AdminActionType.ASSIGN:
            ok = self.auth.update_user_role(
                pa.payload["username"],
                UserRole(pa.payload["role"]),
                pa.payload.get("org_id"),
            )
            if not ok:
                return False
            self.ledger.add_admin_record(pa.action_type.value, payload_hash)
            return True
        if pa.action_type == AdminActionType.DEREGISTER:
            ok = self.auth.remove_user(pa.payload["username"])
            if not ok:
                return False
            self.ledger.add_admin_record(pa.action_type.value, payload_hash)
            return True
        return False

    def vote_admin_action(
        self,
        user: UserAccount,
        action_id: int,
        decision: str,
    ) -> None:
        if user.role not in (UserRole.TRANSPORTER, UserRole.REGULATOR):
            raise PermissionError("Only members can vote admin actions.")
        if not user.org_id:
            raise ValueError("Voter org_id missing.")
        voter_org_id = user.org_id

        if voter_org_id not in ADMIN_VOTE_MEMBER_ORGS:
            raise PermissionError("Your org is not allowed to vote.")

        pa = self.pending_admin_actions.get(action_id)
        if not pa:
            raise KeyError("Admin action not found.")
        if pa.status != PendingStatus.PENDING:
            raise ValueError("Admin action is not pending.")
        if voter_org_id in pa.approvals or voter_org_id in pa.rejections:
            raise ValueError("You already voted.")

        decision = decision.strip().upper()
        if decision == "Y":
            pa.approvals.add(voter_org_id)
        elif decision == "N":
            pa.rejections.add(voter_org_id)
            pa.status = PendingStatus.REJECTED
            return
        else:
            raise ValueError("Decision must be Y or N.")

        if all(org in pa.approvals for org in ADMIN_VOTE_MEMBER_ORGS):
            ok = self._apply_admin_action(pa)
            if ok:
                pa.status = PendingStatus.COMMITTED

    def chain_as_text(self) -> str:
        lines: List[str] = []
        if not self.ledger.blocks:
            return "Chain is empty."
        for block in self.ledger.blocks:
            lines.append(
                f"Block {block.index} | time={time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(block.timestamp))}"
            )
            lines.append(f"  previous_hash={block.previous_hash}")
            lines.append(f"  hash={block.hash}")
            for rec in block.records:
                if rec.record_type == "DATA":
                    lines.append(
                        f"  DATA index={rec.index} data_hash={rec.data_hash} file={rec.file_name}"
                    )
                else:
                    lines.append(
                        f"  ADMIN index={rec.index} action_type={rec.action_type} payload_hash={rec.data_hash}"
                    )
        return "\n".join(lines)

    def login_with_cert(self, username: str) -> UserAccount:
        nonce = secrets.token_hex(16)
        ts = int(time.time())
        message = f"login|{username}|{ts}|{nonce}".encode("utf-8")
        priv_pem = load_pem_file(os.path.join(self.auth.cert_store.certs_dir, f"{username}_private.pem"))
        if not priv_pem:
            raise PermissionError(f"Private key not found for '{username}' (certs/{username}_private.pem).")
        signature = sign_message(priv_pem, message)
        signature_b64 = base64.b64encode(signature).decode("ascii")
        user = self.auth.authenticate_with_signature(username, message, signature_b64)
        if not user:
            raise PermissionError("Certificate verification failed.")
        return user


class MainWindow(QMainWindow):
    TAB_SUBMIT = 0
    TAB_APPROVE = 1
    TAB_ADMIN = 2
    TAB_VOTE = 3
    TAB_CHAIN = 4

    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("Consortium Blockchain — Desktop")
        self.resize(1100, 720)
        self.engine = ConsortiumEngine()
        self.current_user: Optional[UserAccount] = None

        self._stack = QStackedWidget()
        self.setCentralWidget(self._stack)

        self._build_login_page()
        self._build_main_page()
        self._stack.addWidget(self._page_login)
        self._stack.addWidget(self._page_main)
        self._stack.setCurrentIndex(0)

    def _build_login_page(self) -> None:
        outer = QWidget()
        outer.setObjectName("loginPage")
        root = QVBoxLayout(outer)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)
        root.addStretch(1)

        row = QHBoxLayout()
        row.addStretch(1)

        card = QFrame()
        card.setObjectName("loginCard")
        card.setMinimumWidth(440)
        card.setMaximumWidth(520)
        card.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Minimum)
        card_l = QVBoxLayout(card)
        card_l.setContentsMargins(44, 40, 44, 36)
        card_l.setSpacing(0)

        title = QLabel("Consortium Blockchain")
        title.setObjectName("loginTitle")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)
        card_l.addWidget(title)
        card_l.addSpacing(28)

        user_row = QHBoxLayout()
        user_row.setSpacing(14)
        user_lbl = QLabel("Username")
        user_lbl.setObjectName("loginUserLabel")
        self.username_entry = QLineEdit()
        self.username_entry.setObjectName("loginUsername")
        user_row.addWidget(user_lbl, 0, Qt.AlignmentFlag.AlignVCenter)
        user_row.addWidget(self.username_entry, 1, Qt.AlignmentFlag.AlignVCenter)
        card_l.addLayout(user_row)
        card_l.addSpacing(24)

        self.login_btn = QPushButton("Login")
        self.login_btn.setObjectName("loginPrimaryBtn")
        self.login_btn.setDefault(True)
        self.login_btn.setAutoDefault(True)
        self.login_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.login_btn.clicked.connect(self._on_login)
        self.login_btn.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        card_l.addWidget(self.login_btn)

        shadow = QGraphicsDropShadowEffect(card)
        shadow.setBlurRadius(36)
        shadow.setOffset(0, 8)
        shadow.setColor(QColor(15, 23, 42, 42))
        card.setGraphicsEffect(shadow)

        row.addWidget(card, alignment=Qt.AlignmentFlag.AlignCenter)
        row.addStretch(1)
        root.addLayout(row)
        root.addStretch(1)

        self._page_login = outer

    def _build_main_page(self) -> None:
        self._page_main = QWidget()
        root = QVBoxLayout(self._page_main)

        header = QHBoxLayout()
        self.user_label = QLabel("Not logged in")
        self.user_label.setObjectName("headerTitle")
        header.addWidget(self.user_label)
        header.addStretch()
        self.logout_btn = QPushButton("Logout")
        self.logout_btn.setObjectName("secondaryBtn")
        self.logout_btn.clicked.connect(self._on_logout)
        header.addWidget(self.logout_btn)
        root.addLayout(header)

        self.tabs = QTabWidget()
        root.addWidget(self.tabs)

        self._tab_submit = QWidget()
        self._tab_approve = QWidget()
        self._tab_admin = QWidget()
        self._tab_vote = QWidget()
        self._tab_chain = QWidget()

        self.tabs.addTab(self._tab_submit, "IoT Submit")
        self.tabs.addTab(self._tab_approve, "IoT Approvals")
        self.tabs.addTab(self._tab_admin, "Admin Member Mgmt")
        self.tabs.addTab(self._tab_vote, "Vote Admin Actions")
        self.tabs.addTab(self._tab_chain, "Blockchain Ledger")

        self._build_tab_submit()
        self._build_tab_approve()
        self._build_tab_admin()
        self._build_tab_vote()
        self._build_tab_chain()

    def _build_tab_submit(self) -> None:
        lay = QVBoxLayout(self._tab_submit)
        grp = QGroupBox("Submit IoT telemetry")
        gl = QFormLayout(grp)
        self.sub_shipment = QLineEdit("SHIP-001")
        self.sub_container = QLineEdit("CTR-0001")
        self.sub_location = QLineEdit("Route-1")
        self.sub_temp = QLineEdit("20.0")
        gl.addRow("Shipment ID", self.sub_shipment)
        gl.addRow("Container ID", self.sub_container)
        gl.addRow("Location", self.sub_location)
        gl.addRow("Temperature", self.sub_temp)
        self.submit_btn = QPushButton("Create pending transaction")
        self.submit_btn.clicked.connect(self._on_submit_iot)
        gl.addRow(self.submit_btn)
        lay.addWidget(grp)
        hint = QLabel("After submission, regulators approve; on commit, Excel is written under blockchain_data/ and hash goes on-chain.")
        hint.setObjectName("hintLabel")
        hint.setWordWrap(True)
        lay.addWidget(hint)
        lay.addStretch()

    def _build_tab_approve(self) -> None:
        lay = QHBoxLayout(self._tab_approve)
        left = QVBoxLayout()
        left.addWidget(QLabel("Pending transactions"))
        self.pending_table = QTableWidget(0, 6)
        self.pending_table.setHorizontalHeaderLabels(
            ["ID", "Shipment", "Container", "Radiation", "Temp", "Status"]
        )
        self.pending_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.pending_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.pending_table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.pending_table.itemSelectionChanged.connect(self._on_pending_select)
        left.addWidget(self.pending_table)
        self.pending_details = QTextEdit()
        self.pending_details.setReadOnly(True)
        self.pending_details.setMinimumHeight(180)
        left.addWidget(self.pending_details)
        lay.addLayout(left, stretch=3)

        right = QVBoxLayout()
        right.addStretch()
        self.approve_btn = QPushButton("Approve")
        self.approve_btn.clicked.connect(self._on_approve)
        self.reject_btn = QPushButton("Reject")
        self.reject_btn.setObjectName("secondaryBtn")
        self.reject_btn.clicked.connect(self._on_reject)
        self.refresh_pending_btn = QPushButton("Refresh")
        self.refresh_pending_btn.setObjectName("secondaryBtn")
        self.refresh_pending_btn.clicked.connect(self._refresh_pending_transactions)
        right.addWidget(self.approve_btn)
        right.addWidget(self.reject_btn)
        right.addWidget(self.refresh_pending_btn)
        lay.addLayout(right, stretch=0)

    def _build_tab_admin(self) -> None:
        lay = QVBoxLayout(self._tab_admin)
        grp = QGroupBox("Create admin action (requires member votes)")
        gl = QFormLayout(grp)
        gl.setHorizontalSpacing(12)
        self.admin_action_type = QComboBox()
        self.admin_action_type.addItems(["REGISTER", "ASSIGN", "DEREGISTER"])
        self.admin_username = QLineEdit()
        self.admin_role = QComboBox()
        self.admin_role.addItems(["ADMIN", "TRANSPORTER", "REGULATOR"])
        self.admin_role.setCurrentText("TRANSPORTER")
        self.admin_org = QLineEdit("RegulatorA")
        label_width = 150
        action_label = QLabel("Action type")
        action_label.setFixedWidth(label_width)
        username_label = QLabel("Username")
        username_label.setFixedWidth(label_width)
        role_label = QLabel("Role")
        role_label.setFixedWidth(label_width)
        self.admin_org_label = QLabel("Regulator org")
        self.admin_org_label.setFixedWidth(label_width)
        gl.addRow(action_label, self.admin_action_type)
        gl.addRow(username_label, self.admin_username)
        gl.addRow(role_label, self.admin_role)
        gl.addRow(self.admin_org_label, self.admin_org)
        self.create_admin_btn = QPushButton("Create pending admin action")
        self.create_admin_btn.clicked.connect(self._on_create_admin_action)
        gl.addRow(self.create_admin_btn)
        self.admin_role.currentTextChanged.connect(self._update_admin_org_visibility)
        self.admin_action_type.currentTextChanged.connect(self._update_admin_org_visibility)
        self._update_admin_org_visibility()
        lay.addWidget(grp)

        lay.addWidget(QLabel("Pending admin actions"))
        self.admin_table = QTableWidget(0, 6)
        self.admin_table.setHorizontalHeaderLabels(
            ["ID", "Type", "Payload", "Approvals", "Rejections", "Status"]
        )
        ah = self.admin_table.horizontalHeader()
        for col in range(6):
            ah.setSectionResizeMode(
                col,
                QHeaderView.ResizeMode.Stretch if col == 2 else QHeaderView.ResizeMode.ResizeToContents,
            )
        lay.addWidget(self.admin_table)
        self.admin_refresh_btn = QPushButton("Refresh")
        self.admin_refresh_btn.setObjectName("secondaryBtn")
        self.admin_refresh_btn.clicked.connect(self._refresh_admin_actions)
        lay.addWidget(self.admin_refresh_btn, alignment=Qt.AlignmentFlag.AlignRight)

    def _build_tab_vote(self) -> None:
        lay = QVBoxLayout(self._tab_vote)
        lay.addWidget(QLabel("Pending admin actions (vote from list selection)"))
        self.vote_table = QTableWidget(0, 6)
        self.vote_table.setHorizontalHeaderLabels(
            ["ID", "Type", "Payload", "Approvals", "Rejections", "Status"]
        )
        self.vote_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.vote_table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        vh = self.vote_table.horizontalHeader()
        for col in range(6):
            vh.setSectionResizeMode(
                col,
                QHeaderView.ResizeMode.Stretch if col == 2 else QHeaderView.ResizeMode.ResizeToContents,
            )
        lay.addWidget(self.vote_table)

        grp = QGroupBox("Your vote")
        gl = QFormLayout(grp)
        self.vote_decision = QComboBox()
        self.vote_decision.addItems(["Y", "N"])
        gl.addRow("Decision", self.vote_decision)
        self.vote_btn = QPushButton("Submit vote")
        self.vote_btn.clicked.connect(self._on_vote_admin_action)
        gl.addRow(self.vote_btn)
        lay.addWidget(grp)
        self.vote_refresh_btn = QPushButton("Refresh")
        self.vote_refresh_btn.setObjectName("secondaryBtn")
        self.vote_refresh_btn.clicked.connect(self._refresh_vote_admin_actions)
        lay.addWidget(self.vote_refresh_btn, alignment=Qt.AlignmentFlag.AlignRight)

    def _build_tab_chain(self) -> None:
        lay = QVBoxLayout(self._tab_chain)
        self.chain_text = QTextEdit()
        self.chain_text.setReadOnly(True)
        self.chain_text.setFont(QFont("Consolas", 10))
        self.chain_text.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        lay.addWidget(self.chain_text)
        self.chain_refresh_btn = QPushButton("Refresh ledger")
        self.chain_refresh_btn.setObjectName("secondaryBtn")
        self.chain_refresh_btn.clicked.connect(self._refresh_chain)
        lay.addWidget(self.chain_refresh_btn, alignment=Qt.AlignmentFlag.AlignRight)

    def _set_tabs_by_role(self, role: UserRole) -> None:
        self.tabs.setTabEnabled(self.TAB_SUBMIT, role == UserRole.TRANSPORTER)
        self.tabs.setTabEnabled(self.TAB_APPROVE, role == UserRole.REGULATOR)
        self.tabs.setTabEnabled(self.TAB_ADMIN, role == UserRole.ADMIN)
        self.tabs.setTabEnabled(self.TAB_VOTE, role in (UserRole.TRANSPORTER, UserRole.REGULATOR))
        self.tabs.setTabEnabled(self.TAB_CHAIN, role != UserRole.ADMIN)

    def _update_admin_org_visibility(self) -> None:
        action = self.admin_action_type.currentText().strip().upper()
        role = self.admin_role.currentText().strip().upper()
        show_org = action in {"REGISTER", "ASSIGN"} and role == "REGULATOR"
        self.admin_org.setVisible(show_org)
        self.admin_org.setEnabled(show_org)
        if self.admin_org_label is not None:
            self.admin_org_label.setVisible(show_org)

    def _on_logout(self) -> None:
        self.current_user = None
        self.user_label.setText("Not logged in")
        self._stack.setCurrentIndex(0)

    def _on_login(self) -> None:
        username = self.username_entry.text().strip()
        if not username:
            QMessageBox.warning(self, "Login", "Please enter a username.")
            return
        try:
            user = self.engine.login_with_cert(username)
        except Exception as exc:  # noqa: BLE001
            QMessageBox.critical(self, "Login failed", str(exc))
            return

        self.current_user = user
        org = user.org_id or "—"
        self.user_label.setText(f"{user.username}  ·  {user.role.value}  ·  {org}")
        self._set_tabs_by_role(user.role)
        if user.role == UserRole.TRANSPORTER:
            self.tabs.setCurrentIndex(self.TAB_SUBMIT)
        elif user.role == UserRole.REGULATOR:
            self.tabs.setCurrentIndex(self.TAB_APPROVE)
        elif user.role == UserRole.ADMIN:
            self.tabs.setCurrentIndex(self.TAB_ADMIN)
        self._refresh_pending_transactions()
        self._refresh_admin_actions()
        self._refresh_vote_admin_actions()
        self._refresh_chain()
        self._stack.setCurrentIndex(1)

    def _fill_table(self, table: QTableWidget, rows: List[List[str]]) -> None:
        table.setRowCount(0)
        for r in rows:
            row = table.rowCount()
            table.insertRow(row)
            for c, val in enumerate(r):
                item = QTableWidgetItem(str(val))
                item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEditable)
                table.setItem(row, c, item)

    def _refresh_pending_transactions(self) -> None:
        self.pending_table.setRowCount(0)
        self.pending_details.clear()
        if not self.current_user or self.current_user.role != UserRole.REGULATOR:
            return
        rows: List[List[str]] = []
        for ptx in self.engine.list_pending_transactions(only_pending=True):
            r = ptx.tx.record
            rows.append(
                [
                    str(ptx.pending_id),
                    r.shipment_id,
                    r.container_id,
                    f"{r.radiation_level:.3f}",
                    f"{r.temperature:.2f}",
                    ptx.status.value,
                ]
            )
        self._fill_table(self.pending_table, rows)

    def _selected_pending_id(self) -> Optional[int]:
        r = self.pending_table.currentRow()
        if r < 0:
            return None
        item = self.pending_table.item(r, 0)
        if not item:
            return None
        return int(item.text())

    def _on_pending_select(self) -> None:
        if not self.current_user or self.current_user.role != UserRole.REGULATOR:
            return
        pid = self._selected_pending_id()
        if pid is None:
            return
        ptx = self.engine.pending_txs.get(pid)
        if not ptx:
            return
        r = ptx.tx.record
        lines = [
            f"Pending ID: {ptx.pending_id}",
            f"Status: {ptx.status.value}",
            f"Shipment: {r.shipment_id}",
            f"Container: {r.container_id}",
            f"Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(r.timestamp))}",
            f"Event-time: {r.event_time}",
            f"Location: {r.location}",
            f"Latitude: {r.gps_lat:.6f}",
            f"Longitude: {r.gps_lng:.6f}",
            f"Radiation-level: {r.radiation_level:.3f}",
            f"Temperature: {r.temperature:.2f}",
            f"data_hash: {ptx.tx.data_hash}",
            f"Endorsements: {[e.org_id for e in ptx.tx.endorsements]}",
            f"Approvals: {sorted(list(ptx.approvals))}",
            f"Rejections: {sorted(list(ptx.rejections))}",
        ]
        self.pending_details.setPlainText("\n".join(lines))

    def _on_approve(self) -> None:
        if not self.current_user or self.current_user.role != UserRole.REGULATOR:
            QMessageBox.warning(self, "Approve", "Only regulators can approve.")
            return
        pending_id = self._selected_pending_id()
        if pending_id is None:
            QMessageBox.warning(self, "Approve", "Select a pending transaction first.")
            return
        try:
            committed = self.engine.approve_transaction(self.current_user, pending_id)
        except Exception as exc:  # noqa: BLE001
            QMessageBox.critical(self, "Approve failed", str(exc))
            return
        if committed:
            QMessageBox.information(
                self,
                "Approve",
                "Policy satisfied. Data written to Excel and hash committed on chain.",
            )
        else:
            QMessageBox.information(
                self,
                "Approve",
                "Endorsed. Waiting for the other regulator.",
            )
        self._refresh_pending_transactions()
        self._refresh_chain()

    def _on_reject(self) -> None:
        if not self.current_user or self.current_user.role != UserRole.REGULATOR:
            QMessageBox.warning(self, "Reject", "Only regulators can reject.")
            return
        pending_id = self._selected_pending_id()
        if pending_id is None:
            QMessageBox.warning(self, "Reject", "Select a pending transaction first.")
            return
        try:
            self.engine.reject_transaction(self.current_user, pending_id)
        except Exception as exc:  # noqa: BLE001
            QMessageBox.critical(self, "Reject failed", str(exc))
            return
        QMessageBox.information(self, "Reject", "Transaction marked REJECTED.")
        self._refresh_pending_transactions()
        self._refresh_chain()

    def _on_submit_iot(self) -> None:
        if not self.current_user or self.current_user.role != UserRole.TRANSPORTER:
            QMessageBox.warning(self, "Submit", "Only transporter can submit.")
            return
        shipment_id = self.sub_shipment.text().strip() or "SHIP-001"
        container_id = self.sub_container.text().strip() or "CTR-0001"
        location = self.sub_location.text().strip()
        try:
            temperature = float(self.sub_temp.text().strip() or "20.0")
        except ValueError:
            QMessageBox.warning(self, "Submit", "Temperature must be a number.")
            return
        try:
            pid = self.engine.submit_iot_pending(
                self.current_user,
                shipment_id=shipment_id,
                container_id=container_id,
                location=location,
                temperature=temperature,
            )
        except Exception as exc:  # noqa: BLE001
            QMessageBox.critical(self, "Submit failed", str(exc))
            return
        QMessageBox.information(self, "Submitted", f"Pending transaction ID={pid}")
        self._refresh_chain()
        self._refresh_pending_transactions()
        self._refresh_vote_admin_actions()

    def _refresh_admin_actions(self) -> None:
        if not self.current_user or self.current_user.role != UserRole.ADMIN:
            self.admin_table.setRowCount(0)
            return
        rows: List[List[str]] = []
        for pa in self.engine.list_pending_admin_actions(only_pending=True):
            payload_str = json.dumps(pa.payload, separators=(",", ":"))
            rows.append(
                [
                    str(pa.action_id),
                    pa.action_type.value,
                    payload_str,
                    ",".join(sorted(pa.approvals)),
                    ",".join(sorted(pa.rejections)),
                    pa.status.value,
                ]
            )
        self._fill_table(self.admin_table, rows)

    def _refresh_vote_admin_actions(self) -> None:
        if not self.current_user or self.current_user.role not in (UserRole.TRANSPORTER, UserRole.REGULATOR):
            self.vote_table.setRowCount(0)
            return
        voter_org = self.current_user.org_id
        if not voter_org:
            self.vote_table.setRowCount(0)
            return
        rows: List[List[str]] = []
        for pa in self.engine.list_pending_admin_actions(only_pending=True):
            if voter_org in pa.approvals or voter_org in pa.rejections:
                continue
            payload_str = json.dumps(pa.payload, separators=(",", ":"))
            rows.append(
                [
                    str(pa.action_id),
                    pa.action_type.value,
                    payload_str,
                    ",".join(sorted(pa.approvals)),
                    ",".join(sorted(pa.rejections)),
                    pa.status.value,
                ]
            )
        self._fill_table(self.vote_table, rows)

    def _on_create_admin_action(self) -> None:
        if not self.current_user or self.current_user.role != UserRole.ADMIN:
            QMessageBox.warning(self, "Admin", "Only admin can create admin actions.")
            return
        action_type_str = self.admin_action_type.currentText().strip().upper()
        try:
            action_type = AdminActionType(action_type_str)
        except ValueError:
            QMessageBox.warning(self, "Admin", "Invalid action type.")
            return
        username = self.admin_username.text().strip()
        if not username:
            QMessageBox.warning(self, "Admin", "Username is required.")
            return

        payload: Dict = {"username": username}
        role_str = self.admin_role.currentText().strip().upper()

        if action_type == AdminActionType.REGISTER:
            payload["role"] = role_str
            if role_str == "ADMIN":
                payload["org_id"] = None
            elif role_str == "TRANSPORTER":
                payload["org_id"] = "TransporterOrg"
            elif role_str == "REGULATOR":
                org_id = self.admin_org.text().strip()
                if not org_id:
                    QMessageBox.warning(self, "Admin", "Regulator org_id is required for REGULATOR role.")
                    return
                payload["org_id"] = org_id
            else:
                QMessageBox.warning(self, "Admin", "Invalid role.")
                return
        elif action_type == AdminActionType.ASSIGN:
            payload["role"] = role_str
            if role_str == "ADMIN":
                payload["org_id"] = None
            elif role_str == "TRANSPORTER":
                payload["org_id"] = "TransporterOrg"
            elif role_str == "REGULATOR":
                payload["org_id"] = self.admin_org.text().strip() or None
            else:
                QMessageBox.warning(self, "Admin", "Invalid role.")
                return

        try:
            aid = self.engine.create_admin_action(self.current_user, action_type, payload)
        except Exception as exc:  # noqa: BLE001
            QMessageBox.critical(self, "Admin", str(exc))
            return
        QMessageBox.information(self, "Admin", f"Pending admin action created: ID={aid}")
        self._refresh_admin_actions()
        self._refresh_vote_admin_actions()
        self._refresh_chain()

    def _on_vote_admin_action(self) -> None:
        if not self.current_user or self.current_user.role not in (UserRole.TRANSPORTER, UserRole.REGULATOR):
            QMessageBox.warning(self, "Vote", "Only members can vote.")
            return
        row = self.vote_table.currentRow()
        if row < 0:
            QMessageBox.warning(self, "Vote", "Select an action from the table first.")
            return
        try:
            aid_item = self.vote_table.item(row, 0)
            aid = int(aid_item.text()) if aid_item else 0
        except ValueError:
            QMessageBox.warning(self, "Vote", "Invalid selected action ID.")
            return
        decision = self.vote_decision.currentText().strip().upper()
        try:
            self.engine.vote_admin_action(self.current_user, aid, decision)
        except Exception as exc:  # noqa: BLE001
            QMessageBox.critical(self, "Vote failed", str(exc))
            return
        QMessageBox.information(self, "Vote", "Vote recorded.")
        self._refresh_admin_actions()
        self._refresh_vote_admin_actions()
        self._refresh_chain()

    def _refresh_chain(self) -> None:
        self.chain_text.setPlainText(self.engine.chain_as_text())


def main() -> None:
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    app.setStyleSheet(VS_CODE_LIGHT_QSS)
    win = MainWindow()
    win.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
