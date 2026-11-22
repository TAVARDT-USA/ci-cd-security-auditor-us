"""
TAVARDT CI/CD Security Auditor
Static analyzer and security linter for GitHub Actions workflows.
Audits permissions, pull_request_target triggers, action SHA pinning, and secret leakage.
"""

import os
import sys
import re
import json
import argparse

BANNER = """
===================================================================
     TAVARDT CI/CD Security Auditor - Pipeline Hardener CLI       
  Defensive Supply Chain & Secret Exposure Audit for GitHub Actions
               https://ag.tavardt.com/br/ciberseguranca/           
===================================================================
"""

SEVERITY_WEIGHTS = {
    "CRITICAL": 45,
    "HIGH": 30,
    "MEDIUM": 15,
    "LOW": 5
}

def analyze_workflow_content(content, filename="workflow.yml"):
    findings = []
    score = 0

    # 1. Check for pull_request_target with unsafe ref checkout
    if "pull_request_target" in content:
        if "github.event.pull_request.head.sha" in content or "head.ref" in content:
            findings.append({
                "severity": "CRITICAL",
                "title": "Gatilho pull_request_target com Checkout Inseguro de Fork",
                "description": "O workflow roda no contexto do repositório base com acesso total a secrets enquanto faz checkout de código não confiável enviado no PR.",
                "evidence": "Gatilho pull_request_target associado a ref de PR externo.",
                "remediation": "Utilize o evento pull_request padrão com permissões somente leitura ou isole a execução de código não confiável em jobs secundários."
            })
            score += SEVERITY_WEIGHTS["CRITICAL"]
        else:
            findings.append({
                "severity": "HIGH",
                "title": "Gatilho pull_request_target em Uso sem Isolamento Estrito",
                "description": "O evento pull_request_target herda privilégios elevados e acesso a variáveis protegidas. Requer validação rigorosa.",
                "evidence": "on: pull_request_target declarado no manifesto.",
                "remediation": "Avalie se o evento pull_request convencional é suficiente para a rotina de integração."
            })
            score += SEVERITY_WEIGHTS["HIGH"]

    # 2. Check for permissions: write-all or lack of explicit permissions
    if "write-all" in content:
        findings.append({
            "severity": "HIGH",
            "title": "Permissoes Globais Excessivas GITHUB_TOKEN (write-all)",
            "description": "O token padrão herdou permissões amplas de escrita em todas as entidades do repositório.",
            "evidence": "permissions: write-all identificado no cabeçalho ou job.",
            "remediation": "Restrinja o escopo utilizando 'permissions: contents: read' no topo do arquivo."
        })
        score += SEVERITY_WEIGHTS["HIGH"]
    elif "permissions:" not in content:
        findings.append({
            "severity": "MEDIUM",
            "title": "Bloco de Permissoes Explicito Ausente",
            "description": "O workflow não declara restrições explícitas de permissão, herdando configurações padrão da organização.",
            "evidence": "Bloco permissions: não localizado no arquivo.",
            "remediation": "Defina permissões mínimas explícitas no nível raiz do manifesto."
        })
        score += SEVERITY_WEIGHTS["MEDIUM"]

    # 3. Command Injection via context expressions strictly inside run: blocks
    lines = content.splitlines()
    in_run = False
    run_indent = 0
    injection_pattern = re.compile(r"\$\{\{\s*github\.(event\.(pull_request|issue|comment)\.(title|body)|head_ref)", re.IGNORECASE)
    detected_injections = []

    for line in lines:
        stripped = line.strip()
        indent = len(line) - len(line.lstrip())

        if stripped.startswith("run:"):
            in_run = True
            run_indent = indent
            if injection_pattern.search(line):
                detected_injections.append(stripped)
            continue

        if in_run:
            if stripped and indent <= run_indent and re.match(r"^[a-zA-Z0-9_-]+:", stripped):
                in_run = False
            elif in_run and injection_pattern.search(line):
                detected_injections.append(stripped)

    if detected_injections:
        findings.append({
            "severity": "CRITICAL",
            "title": "Injecao de Comandos Shell por Expressoes de Contexto em run:",
            "description": "Expressões de entrada não sanitizadas interpoladas diretamente em blocos run: permitem quebra de comandos shell e RCE.",
            "evidence": "Instruções detectadas: " + "; ".join(detected_injections[:2]),
            "remediation": "Passe variáveis de contexto através de variáveis de ambiente no bloco env: em vez de interpolação direta."
        })
        score += SEVERITY_WEIGHTS["CRITICAL"]

    # 4. Unpinned Actions (Tag vs SHA)
    tag_action_pattern = r"uses:\s*([a-zA-Z0-9_.-]+/[a-zA-Z0-9_.-]+)@(v[0-9]+|main|master)"
    unpinned = re.findall(tag_action_pattern, content)
    if unpinned:
        sample_unpinned = [f"{u[0]}@{u[1]}" for u in unpinned[:3]]
        findings.append({
            "severity": "MEDIUM",
            "title": "Acoes Externas Fixadas por Tag Mutavel",
            "description": "Ações de terceiros estão vinculadas a tags mutáveis em vez de commit SHA imutável de 40 caracteres.",
            "evidence": "Ações identificadas: " + ", ".join(sample_unpinned) + ("..." if len(unpinned) > 3 else ""),
            "remediation": "Substitua tags como @v3 pelo commit SHA imutável correspondente (ex: @8e5e7e5...)."
        })
        score += SEVERITY_WEIGHTS["MEDIUM"]

    # 5. Direct secret exfiltration / hardcoded credentials
    secret_leaks = [
        (r"AKIA[0-9A-Z]{16}", "AWS Access Key ID"),
        (r"ghp_[0-9a-zA-Z]{36}", "GitHub Personal Access Token"),
        (r"-----BEGIN (RSA |OPENSSH |EC )?PRIVATE KEY-----", "Chave Privada SSH/RSA"),
        (r"curl.*-d.*secrets\.", "Exfiltração de Secret via Curl")
    ]
    for pattern, name in secret_leaks:
        if re.search(pattern, content, re.IGNORECASE):
            findings.append({
                "severity": "CRITICAL",
                "title": f"Credencial Exposta ou Exfiltracao Detectada: {name}",
                "description": "Identificada chave privada ou instrução de transmissão de secrets para endpoint externo.",
                "evidence": f"Padrão de credencial sensível correspondente a {name}.",
                "remediation": "Revogue a credencial imediatamente e utilize mecanismos de OIDC federado."
            })
            score += SEVERITY_WEIGHTS["CRITICAL"]

    normalized_score = min(100, score)
    return {
        "file": filename,
        "score": normalized_score,
        "risk_level": "CRITICAL" if normalized_score >= 60 else ("HIGH" if normalized_score >= 35 else ("MEDIUM" if normalized_score > 0 else "SECURE")),
        "findings": findings
    }

def main():
    parser = argparse.ArgumentParser(description="TAVARDT CI/CD Security Auditor CLI")
    parser.add_argument("path", help="Caminho do arquivo YAML ou diretório de workflows (.github/workflows)")
    parser.add_argument("--json", action="store_true", help="Emitir relatório estruturado em formato JSON")
    args = parser.parse_args()

    target_path = args.path
    if not os.path.exists(target_path):
        print(f"Erro: Caminho '{target_path}' não encontrado.", file=sys.stderr)
        sys.exit(1)

    files_to_scan = []
    if os.path.isfile(target_path):
        files_to_scan.append(target_path)
    elif os.path.isdir(target_path):
        for root, _, files in os.walk(target_path):
            for file in files:
                if file.endswith((".yml", ".yaml")):
                    files_to_scan.append(os.path.join(root, file))

    if not files_to_scan:
        print(f"Nenhum manifesto YAML (.yml / .yaml) encontrado em '{target_path}'.", file=sys.stderr)
        sys.exit(0)

    results = []
    for file_path in files_to_scan:
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
            results.append(analyze_workflow_content(content, filename=file_path))
        except Exception as e:
            print(f"Erro ao ler '{file_path}': {e}", file=sys.stderr)

    if args.json:
        print(json.dumps(results, indent=2, ensure_ascii=False))
        return

    print(BANNER)
    for res in results:
        print(f"\n[+] Arquivo: {res['file']}")
        print(f"    Pontuação de Risco: {res['score']}/100 [{res['risk_level']}]")
        print(f"    Total de Vulnerabilidades: {len(res['findings'])}")
        print("-" * 65)
        if not res["findings"]:
            print("    [OK] Nenhuma vulnerabilidade crítica ou má prática de supply chain identificada.")
        else:
            for f in res["findings"]:
                print(f"    [{f['severity']}] {f['title']}")
                print(f"      Evidência: {f['evidence']}")
                print(f"      Mitigação: {f['remediation']}\n")

    print("=" * 65)
    print("Para consultoria de blindagem perimetral e arquitetura Zero Trust em CI/CD:")
    print("https://ag.tavardt.com/br/ciberseguranca/")
    print("=" * 65)

if __name__ == "__main__":
    main()
