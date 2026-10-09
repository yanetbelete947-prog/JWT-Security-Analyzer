#!/usr/bin/env python3

import argparse
import base64
import json
import re
import sys
from datetime import datetime, timezone

import jwt
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console()


SUPPORTED_ALGORITHMS = {
    "HS256", "HS384", "HS512",
    "RS256", "RS384", "RS512",
    "ES256", "ES384", "ES512",
    "PS256", "PS384", "PS512",
}


UNSAFE_ALGORITHMS = {
    "none"
}


STANDARD_CLAIMS = {
    "iss",
    "sub",
    "aud",
    "exp",
    "nbf",
    "iat",
    "jti",
}


SENSITIVE_NAMES = {
    "password",
    "passwd",
    "secret",
    "api_key",
    "apikey",
    "access_token",
    "refresh_token",
    "private_key",
    "credit_card",
}


def decode_base64url(value):
    """Decode a Base64URL encoded JWT component."""
    padding = "=" * (-len(value) % 4)

    try:
        decoded = base64.urlsafe_b64decode(
            value + padding
        )
        return decoded.decode("utf-8")
    except Exception as exc:
        raise ValueError(f"Invalid Base64URL data: {exc}")


def parse_jwt(token):
    """Parse the three JWT sections."""
    parts = token.strip().split(".")

    if len(parts) != 3:
        raise ValueError(
            "JWT must contain exactly three sections: "
            "header.payload.signature"
        )

    header_raw = decode_base64url(parts[0])
    payload_raw = decode_base64url(parts[1])

    try:
        header = json.loads(header_raw)
    except json.JSONDecodeError:
        raise ValueError("JWT header is not valid JSON.")

    try:
        payload = json.loads(payload_raw)
    except json.JSONDecodeError:
        raise ValueError("JWT payload is not valid JSON.")

    if not isinstance(header, dict):
        raise ValueError("JWT header must be a JSON object.")

    if not isinstance(payload, dict):
        raise ValueError("JWT payload must be a JSON object.")

    return {
        "header": header,
        "payload": payload,
        "signature": parts[2],
        "raw_parts": parts,
    }


def timestamp_to_datetime(timestamp):
    """Convert a Unix timestamp to UTC datetime."""
    try:
        return datetime.fromtimestamp(
            float(timestamp),
            tz=timezone.utc
        )
    except (ValueError, TypeError, OverflowError):
        return None


def format_timestamp(timestamp):
    dt = timestamp_to_datetime(timestamp)

    if not dt:
        return "Invalid timestamp"

    return dt.strftime("%Y-%m-%d %H:%M:%S UTC")


def add_finding(findings, severity, title, description):
    findings.append({
        "severity": severity,
        "title": title,
        "description": description,
    })


def analyze_algorithm(header, findings):
    algorithm = header.get("alg")

    if not algorithm:
        add_finding(
            findings,
            "CRITICAL",
            "Missing algorithm",
            "The JWT header does not contain an alg field."
        )
        return

    if algorithm == "none":
        add_finding(
            findings,
            "CRITICAL",
            "Unsigned algorithm",
            "The token specifies the 'none' algorithm. "
            "Applications should not accept unsigned authentication tokens."
        )
        return

    if algorithm not in SUPPORTED_ALGORITHMS:
        add_finding(
            findings,
            "MEDIUM",
            "Unrecognized algorithm",
            f"The analyzer does not recognize algorithm '{algorithm}'."
        )


def analyze_claims(payload, findings):
    # Expiration
    if "exp" not in payload:
        add_finding(
            findings,
            "MEDIUM",
            "Missing expiration",
            "The token does not contain an exp claim."
        )
    else:
        exp = timestamp_to_datetime(payload["exp"])

        if exp is None:
            add_finding(
                findings,
                "HIGH",
                "Invalid expiration",
                "The exp claim is not a valid Unix timestamp."
            )
        else:
            now = datetime.now(timezone.utc)

            if exp <= now:
                add_finding(
                    findings,
                    "HIGH",
                    "Expired token",
                    f"The token expired at {format_timestamp(payload['exp'])}."
                )
            else:
                lifetime = exp - now

                if lifetime.total_seconds() > 86400 * 30:
                    add_finding(
                        findings,
                        "MEDIUM",
                        "Very long token lifetime",
                        "The token remains valid for more than 30 days."
                    )

    # Issued-at
    if "iat" in payload:
        iat = timestamp_to_datetime(payload["iat"])

        if iat is None:
            add_finding(
                findings,
                "MEDIUM",
                "Invalid issued-at timestamp",
                "The iat claim is not a valid timestamp."
            )
        else:
            now = datetime.now(timezone.utc)

            if iat > now:
                add_finding(
                    findings,
                    "MEDIUM",
                    "Future issued-at timestamp",
                    "The iat claim is in the future."
                )

    # Not-before
    if "nbf" in payload:
        nbf = timestamp_to_datetime(payload["nbf"])

        if nbf is None:
            add_finding(
                findings,
                "MEDIUM",
                "Invalid not-before timestamp",
                "The nbf claim is not a valid timestamp."
            )

    # Audience
    if "aud" not in payload:
        add_finding(
            findings,
            "LOW",
            "Missing audience",
            "The token does not contain an aud claim."
        )

    # Issuer
    if "iss" not in payload:
        add_finding(
            findings,
            "LOW",
            "Missing issuer",
            "The token does not contain an iss claim."
        )


def analyze_sensitive_claims(payload, findings):
    for key, value in payload.items():
        key_lower = str(key).lower()

        if key_lower in SENSITIVE_NAMES:
            add_finding(
                findings,
                "HIGH",
                "Potential sensitive information",
                f"The claim '{key}' may contain sensitive information."
            )

        
        if any(
            word in key_lower
            for word in ["password", "secret", "private_key"]
        ):
            add_finding(
                findings,
                "HIGH",
                "Sensitive claim name",
                f"The claim '{key}' appears to contain secret material."
            )


def calculate_score(findings):
    """
    Start at 100 and subtract according to severity.
    """
    deductions = {
        "CRITICAL": 40,
        "HIGH": 20,
        "MEDIUM": 10,
        "LOW": 3,
    }

    score = 100

    for finding in findings:
        score -= deductions.get(
            finding["severity"],
            0
        )

    return max(0, score)


def risk_level(score):
    if score >= 90:
        return "LOW"

    if score >= 70:
        return "MEDIUM"

    if score >= 40:
        return "HIGH"

    return "CRITICAL"


def verify_signature(token, algorithm, key):
    """
    Verify a JWT signature using a user-supplied key.

    The key can be:
    - an HMAC secret
    - an RSA public key
    - an EC public key
    """
    try:
        jwt.decode(
            token,
            key,
            algorithms=[algorithm],
            options={
                "verify_exp": False,
                "verify_nbf": False,
            },
        )

        return True, "Signature is valid."

    except jwt.InvalidSignatureError:
        return False, "Signature verification failed."

    except jwt.InvalidTokenError as exc:
        return False, f"Token verification failed: {exc}"

    except Exception as exc:
        return False, f"Verification error: {exc}"


def display_analysis(result):
    header = result["header"]
    payload = result["payload"]
    findings = result["findings"]

    console.print()
    console.print(
        Panel.fit(
            "[bold]JWT SECURITY ANALYZER[/bold]",
            border_style="cyan"
        )
    )

    # Token information
    table = Table(title="Token Information")

    table.add_column("Property")
    table.add_column("Value")

    table.add_row(
        "Algorithm",
        str(header.get("alg", "MISSING"))
    )

    table.add_row(
        "Type",
        str(header.get("typ", "Not specified"))
    )

    table.add_row(
        "Score",
        f"{result['score']}/100"
    )

    table.add_row(
        "Risk",
        result["risk"]
    )

    console.print(table)

    # Claims
    claims_table = Table(title="Claims")

    claims_table.add_column("Claim")
    claims_table.add_column("Value")

    for key, value in payload.items():
        value_string = str(value)

        if key in {"exp", "iat", "nbf"}:
            value_string += (
                f" ({format_timestamp(value)})"
            )

        claims_table.add_row(
            str(key),
            value_string
        )

    console.print(claims_table)

    # Findings
    findings_table = Table(title="Security Findings")

    findings_table.add_column("Severity")
    findings_table.add_column("Finding")
    findings_table.add_column("Description")

    if not findings:
        findings_table.add_row(
            "PASS",
            "No findings",
            "No issues were detected by the configured checks."
        )
    else:
        for finding in findings:
            findings_table.add_row(
                finding["severity"],
                finding["title"],
                finding["description"]
            )

    console.print(findings_table)

    # Signature
    if result.get("signature_verification"):
        verification = result["signature_verification"]

        console.print(
            Panel(
                verification["message"],
                title="Signature Verification"
            )
        )


def generate_html(result, output_file):
    findings_html = ""

    for finding in result["findings"]:
        findings_html += f"""
        <tr>
            <td>{finding['severity']}</td>
            <td>{finding['title']}</td>
            <td>{finding['description']}</td>
        </tr>
        """

    claims_html = ""

    for key, value in result["payload"].items():
        claims_html += f"""
        <tr>
            <td>{key}</td>
            <td>{value}</td>
        </tr>
        """

    html = f"""
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">

<title>JWT Security Report</title>

<style>

body {{
    font-family: Arial, sans-serif;
    background: #111;
    color: #eee;
    margin: 40px;
}}

h1 {{
    color: #4dd0e1;
}}

.card {{
    background: #1b1b1b;
    padding: 20px;
    margin-bottom: 20px;
    border-radius: 8px;
}}

table {{
    width: 100%;
    border-collapse: collapse;
}}

th, td {{
    padding: 10px;
    border-bottom: 1px solid #333;
    text-align: left;
}}

th {{
    background: #222;
}}

</style>

</head>

<body>

<h1>JWT Security Report</h1>

<div class="card">

<h2>Token Information</h2>

<p>
<b>Algorithm:</b>
{result['header'].get('alg', 'MISSING')}
</p>

<p>
<b>Type:</b>
{result['header'].get('typ', 'Not specified')}
</p>

<p>
<b>Score:</b>
{result['score']}/100
</p>

<p>
<b>Risk:</b>
{result['risk']}
</p>

</div>

<div class="card">

<h2>Claims</h2>

<table>

<tr>
<th>Claim</th>
<th>Value</th>
</tr>

{claims_html}

</table>

</div>

<div class="card">

<h2>Security Findings</h2>

<table>

<tr>
<th>Severity</th>
<th>Finding</th>
<th>Description</th>
</tr>

{findings_html}

</table>

</div>

</body>
</html>
"""

    with open(
        output_file,
        "w",
        encoding="utf-8"
    ) as file:
        file.write(html)


def main():
    parser = argparse.ArgumentParser(
        description=(
            "JWT Security Analyzer - "
            "Analyze JWT structure, claims and security properties."
        )
    )

    parser.add_argument(
        "token",
        help="JWT token or file containing a JWT"
    )

    parser.add_argument(
        "--key",
        help="Secret/public key used for signature verification"
    )

    parser.add_argument(
        "--json",
        dest="json_file",
        help="Write analysis to JSON file"
    )

    parser.add_argument(
        "--html",
        dest="html_file",
        help="Write analysis to HTML file"
    )

    args = parser.parse_args()

    # Read token directly or from file.
    try:
        if args.token.startswith("eyJ"):
            token = args.token.strip()
        else:
            with open(
                args.token,
                "r",
                encoding="utf-8"
            ) as file:
                token = file.read().strip()

    except FileNotFoundError:
        console.print(
            "[red]Error:[/red] Token file not found."
        )
        sys.exit(1)

    # Parse JWT.
    try:
        parsed = parse_jwt(token)

    except ValueError as exc:
        console.print(
            f"[red]Invalid JWT:[/red] {exc}"
        )
        sys.exit(1)

    header = parsed["header"]
    payload = parsed["payload"]

    findings = []

    analyze_algorithm(
        header,
        findings
    )

    analyze_claims(
        payload,
        findings
    )

    analyze_sensitive_claims(
        payload,
        findings
    )

    score = calculate_score(
        findings
    )

    result = {
        "algorithm": header.get("alg"),
        "header": header,
        "payload": payload,
        "signature_present": bool(
            parsed["signature"]
        ),
        "findings": findings,
        "score": score,
        "risk": risk_level(score),
    }

    # Optional signature verification.
    if args.key:
        algorithm = header.get("alg")

        if algorithm in UNSAFE_ALGORITHMS:
            result["signature_verification"] = {
                "valid": False,
                "message": (
                    "Unsigned algorithm cannot be "
                    "cryptographically verified."
                ),
            }

        elif algorithm not in SUPPORTED_ALGORITHMS:
            result["signature_verification"] = {
                "valid": False,
                "message": "Unsupported algorithm.",
            }

        else:
            try:
                with open(
                    args.key,
                    "rb"
                ) as file:
                    key = file.read()

            except FileNotFoundError:
                console.print(
                    "[red]Key file not found.[/red]"
                )
                sys.exit(1)

            valid, message = verify_signature(
                token,
                algorithm,
                key
            )

            result["signature_verification"] = {
                "valid": valid,
                "message": message,
            }

    display_analysis(result)

    # JSON output
    if args.json_file:
        with open(
            args.json_file,
            "w",
            encoding="utf-8"
        ) as file:
            json.dump(
                result,
                file,
                indent=4,
                default=str
            )

        console.print(
            f"[green]JSON report written to "
            f"{args.json_file}[/green]"
        )

    # HTML output
    if args.html_file:
        generate_html(
            result,
            args.html_file
        )

        console.print(
            f"[green]HTML report written to "
            f"{args.html_file}[/green]"
        )


if __name__ == "__main__":
    main()
