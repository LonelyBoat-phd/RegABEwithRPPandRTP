"""Public synthetic schedules. Never seeds cryptographic randomness."""
import random


def legal_schedule(profiles, events, seed, observer=0):
    if type(events) is not int or events < 0 or not 0 <= observer < len(profiles):
        raise ValueError('invalid schedule dimensions')
    legal = [(i, w) for i, row in enumerate(profiles) if i != observer
             for w, bit in enumerate(row) if bit == 0]
    if events > len(legal):
        raise ValueError(f'requested {events} distinct committed revocations, only {len(legal)} legal pairs')
    random.Random(seed).shuffle(legal)
    return legal[:events]
