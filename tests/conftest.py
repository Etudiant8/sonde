from __future__ import annotations

from pathlib import Path

import pytest

ECHANTILLONS = Path(__file__).parent / "echantillons"

# Horodatage de départ du scénario synthétique (voir tests/outils/fabrique_pcap.py)
T0 = 1_780_000_000.0


@pytest.fixture
def echantillons() -> Path:
    return ECHANTILLONS


@pytest.fixture
def config():
    from shadowreef.config import Config

    return Config()


@pytest.fixture
def base(tmp_path):
    from shadowreef.stockage import Base

    b = Base(tmp_path / "shadowreef.db")
    b.initialiser()
    yield b
    b.fermer()
