import time
import json
import hashlib
import random
from typing import Dict, Any, List, Optional

# ================== 1. Blockchain Initialization ==================
blockchain: List[Dict[str, Any]] = []


# ================== 2. Genesis Block & Hash & Block Functions ==================
def calculate_hash(index: int,
                   timestamp: float,
                   data: Dict[str, Any],
                   previous_hash: str) -> str:
    """
    Calculate the block hash using SHA-256.
    """
    block_string = f"{index}{timestamp}{json.dumps(data, sort_keys=True)}{previous_hash}"
    return hashlib.sha256(block_string.encode("utf-8")).hexdigest()


def create_genesis_block() -> Dict[str, Any]:
    """
    Genesis block: the first block of the blockchain
    """
    index = 0
    timestamp = time.time()
    data = {"msg": "Genesis Block"}
    previous_hash = "0" * 64
    hash_value = calculate_hash(index, timestamp, data, previous_hash)
    return {
        "index": index,
        "timestamp": timestamp,
        "data": data,
        "previous_hash": previous_hash,
        "hash": hash_value
    }


def get_last_blockchain_value() -> Optional[Dict[str, Any]]:
    """
    Get the last block in the blockchain
    """
    if not blockchain:
        return None
    return blockchain[-1]


def add_block(data: Dict[str, Any]) -> None:
    """
    Add a new block to the blockchain
    """
    last_block = get_last_blockchain_value()
    if last_block is None:
        genesis = create_genesis_block()
        blockchain.append(genesis)
        last_block = genesis

    index = last_block["index"] + 1
    timestamp = time.time()
    previous_hash = last_block["hash"]
    hash_value = calculate_hash(index, timestamp, data, previous_hash)

    block = {
        "index": index,
        "timestamp": timestamp,
        "data": data,
        "previous_hash": previous_hash,
        "hash": hash_value
    }
    blockchain.append(block)


def verify_chain() -> bool:
    """
    Verify whether the blockchain has been tampered with
    """
    if len(blockchain) <= 1:
        return True

    for i in range(1, len(blockchain)):
        current = blockchain[i]
        previous = blockchain[i - 1]

        # 1) Recalculate the hash of the current block
        recalculated_hash = calculate_hash(
            current["index"],
            current["timestamp"],
            current["data"],
            current["previous_hash"]
        )
        if current["hash"] != recalculated_hash:
            print(f"[!] Block {current['index']} hash mismatch!")
            print(f"    stored hash      : {current['hash']}")
            print(f"    recalculated hash: {recalculated_hash}")
            return False

        # 2) Check whether the chain linkage is valid
        if current["previous_hash"] != previous["hash"]:
            print(f"[!] Block {current['index']} previous_hash mismatch!")
            return False

    return True


def tamper_chain() -> None:
    """
    Simulate blockchain tampering
    """
    if len(blockchain) < 2:
        print("Chain length is insufficient for tampering demonstration.")
        return

    block = blockchain[1]

    print("=== Tamper Demonstration ===")
    print("Original data:", block["data"])

    original_recalc = calculate_hash(
        block["index"],
        block["timestamp"],
        block["data"],
        block["previous_hash"]
    )
    print("Hash before tampering:", original_recalc)

    block["data"]["radiation_level"] = 999.999
    block["data"]["status"] = "LOST"
    print("[Tamper] Modified data:", block["data"])

    tampered_recalc = calculate_hash(
        block["index"],
        block["timestamp"],
        block["data"],
        block["previous_hash"]
    )
    print("Hash after tampering:", tampered_recalc)

    print("Stored hash in block:", block["hash"])
    print("=============================")


# ================== 3. IoT Data Simulation ==================
def generate_iot_data() -> Dict[str, Any]:
    """
    Generate simulated IoT data for nuclear waste transportation
    """
    radiation_level = round(random.uniform(0.3, 1.5), 3)
    status = random.choice(["Transiting", "Arrived", "Delayed"])
    location = random.choice(["Station_A", "Station_B", "Station_C", "On_Road"])
    latitude = round(random.uniform(30.0, 42.0), 6)
    longitude = round(random.uniform(110.0, 125.0), 6)
    temperature = round(random.uniform(5, 28), 2)

    return {
        "location": location,
        "latitude": latitude,
        "longitude": longitude,
        "radiation_level": radiation_level,
        "temperature": temperature,
        "status": status,
        "event_time": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    }


# ================== 4. User Input ==================
def get_user_choice() -> str:
    user_input = input("Your choice: ")
    return user_input


def print_blockchain_elements() -> None:
    print("\n=== Outputting Blocks ===")
    for block in blockchain:
        print(json.dumps(block, indent=2))


# ================== 5. Main Loop ==================
while True:
    print("\nPlease choose:")
    print("1: Add a new IoT record to blockchain.")
    print("2: Output the blockchain blocks.")
    print("3: Verify the blockchain.")
    print("h: Tamper with the chain.")
    print("q: Quit.")

    user_choice = get_user_choice()

    if user_choice == '1':
        data = generate_iot_data()
        add_block(data)
        print("[OK] New block added.")
    elif user_choice == '2':
        print_blockchain_elements()
    elif user_choice == '3':
        if verify_chain():
            print("Blockchain is valid.")
        else:
            print("Invalid blockchain! Program will stop.")
            print_blockchain_elements()
            break
    elif user_choice == 'h':
        tamper_chain()
    elif user_choice == 'q':
        break
    else:
        print("Invalid input, please choose a valid option!")