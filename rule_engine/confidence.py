import json
import os
from collections import deque

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STATE_FILE = os.path.join(BASE_DIR, "logs", "confidence_state.json")

WINDOW = 5
BLOCK_THRESHOLD = 3


def load_state():
    if not os.path.exists(STATE_FILE):
        return {}

    with open(STATE_FILE, "r") as f:
        return json.load(f)


def save_state(state):
    with open(STATE_FILE, "w") as f:
        json.dump(state, f, indent=2)


def update_confidence(ip, is_high):
    state = load_state()

    history = deque(state.get(ip, []), maxlen=WINDOW)
    history.append(1 if is_high else 0)

    state[ip] = list(history)
    save_state(state)

    return sum(history)
