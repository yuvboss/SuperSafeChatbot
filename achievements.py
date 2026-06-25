from dataclasses import dataclass


@dataclass
class Achievement:
    id: str
    emoji: str
    name: str
    description: str


ALL_ACHIEVEMENTS = [
    Achievement("first_scan", "🔍", "First Scan", "Submitted your first code for scanning"),
    Achievement("clean_sheet", "✅", "Clean Sheet", "Got a scan with zero findings"),
    Achievement("fixer", "🔧", "Fixer", "Fixed at least one hardcoded credential"),
    Achievement("hat_trick", "🎩", "Hat Trick", "Fixed 3 or more credentials in one session"),
    Achievement("security_pro", "🏆", "Security Pro", "5 consecutive clean scans"),
]

_MAP = {a.id: a for a in ALL_ACHIEVEMENTS}


def check_new_achievements(state) -> list:
    """Return newly unlocked Achievement objects and mutate state.unlocked_achievements."""
    if "unlocked_achievements" not in state:
        state.unlocked_achievements = set()

    newly = []

    def _try(aid: str):
        if aid not in state.unlocked_achievements:
            state.unlocked_achievements.add(aid)
            newly.append(_MAP[aid])

    if state.get("scans_total", 0) >= 1:
        _try("first_scan")
    if state.get("clean_scans_streak", 0) >= 1:
        _try("clean_sheet")
    if state.get("findings_fixed", 0) >= 1:
        _try("fixer")
    if state.get("findings_fixed", 0) >= 3:
        _try("hat_trick")
    if state.get("clean_scans_streak", 0) >= 5:
        _try("security_pro")

    return newly
