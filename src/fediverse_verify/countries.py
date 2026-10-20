"""Display names for PID issuing countries (EU/EEA plus Switzerland). Unknown codes show as-is."""

NAMES = {
    "AT": "Austria", "BE": "Belgium", "BG": "Bulgaria", "HR": "Croatia", "CY": "Cyprus",
    "CZ": "Czechia", "DK": "Denmark", "EE": "Estonia", "FI": "Finland", "FR": "France",
    "DE": "Germany", "GR": "Greece", "HU": "Hungary", "IE": "Ireland", "IT": "Italy",
    "LV": "Latvia", "LT": "Lithuania", "LU": "Luxembourg", "MT": "Malta", "NL": "Netherlands",
    "PL": "Poland", "PT": "Portugal", "RO": "Romania", "SK": "Slovakia", "SI": "Slovenia",
    "ES": "Spain", "SE": "Sweden", "IS": "Iceland", "LI": "Liechtenstein", "NO": "Norway",
    "CH": "Switzerland",
}


def country_name(code: str | None) -> str:
    if not code:
        return "an unknown country"
    return NAMES.get(code.upper(), code.upper())


def issuer_label(country: str | None, authority: str | None) -> str:
    """'Italy', or 'Italy (Ministero dell'Interno)' when the authority adds information."""
    name = country_name(country)
    if authority and authority.strip().upper() not in {(country or "").upper(), name.upper()}:
        return f"{name} ({authority.strip()})"
    return name
