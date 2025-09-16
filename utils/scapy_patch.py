import sys, types, six

# Create fake scapy.modules.six.moves
six_moves = types.ModuleType("scapy.modules.six.moves")
six_moves.range = six.moves.range
sys.modules["scapy.modules.six.moves"] = six_moves
