#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
TAVARDT CI/CD Security Auditor & Supply Chain Integrity Inspector (CLI)
Inspeção determinística de workflows, permissões e segredos.
Regra Estrita: ZERO TRAVESSÕES EM-DASH
Regra Estrita: ZERO DUPLO HÍFEN (chr(45) + chr(45))
"""

import sys
import os
import re

SEVERITY_CRITICAL = "CRÍTICO"
SEVERITY_HIGH = "ALTO"
SEVERITY_MEDIUM = "MÉDIO"
SEVERITY_INFO = "INFORMATIVO"

def audit_workflow_content(file_path, content):
    findings = []
    lines = content.splitlines()

    # 1. Verificação de pull_request_target com checkout inseguro de head ref
    has_pr_target = False
    for i, line in enumerate(lines):
        if "pull_request_target" in line and not line.strip().startswith("#"):
            has_pr_target = True
            break
            
    if has_pr_target:
        unsafe_checkout = False
        unsafe_line = 0
        for i, line in enumerate(lines):
            if any(k in line for k in ["github.event.pull_request.head.sha", "head.ref"]) and not line.strip().startswith("#"):
                unsafe_checkout = True
                unsafe_line = i + 1
                break
        if unsafe_checkout:
            findings.append({
                "severity": SEVERITY_CRITICAL,
                "rule": "CICD-001-PR-TARGET-UNTRUSTED-CHECKOUT",
                "line": unsafe_line,
                "title": "Gatilho pull_request_target com checkout de código não confiável",
                "desc": "Executa workflow privilegiado com acesso a secrets enquanto faz checkout do commit de fork externo. Permite execução remota de código e exfiltração de segredos."
            })
        else:
            findings.append({
                "severity": SEVERITY_HIGH,
                "rule": "CICD-002-PR-TARGET-PRIVILEGED-TRIGGER",
                "line": 1,
                "title": "Uso do gatilho pull_request_target sem isolamento estrito",
                "desc": "O gatilho pull_request_target concede permissões elevadas e acesso a secrets. Recomendado utilizar pull_request tradicional com permissão restrita."
            })

    # 2. Verificação de permissions: write-all ou ausência de permissões restritivas
    has_write_all = False
    has_permissions_block = False
    for i, line in enumerate(lines):
        if "permissions:" in line and not line.strip().startswith("#"):
            has_permissions_block = True
            if "write-all" in line:
                has_write_all = True
                findings.append({
                    "severity": SEVERITY_HIGH,
                    "rule": "CICD-003-PERMISSIONS-WRITE-ALL",
                    "line": i + 1,
                    "title": "Permissões globais excessivas no token (write-all)",
                    "desc": "GITHUB_TOKEN com permissões irrestritas de escrita. Configure permissions: read-all ou especifique escopos mínimos necessários."
                })
                break
                
    if not has_permissions_block and ("jobs:" in content or "job:" in content):
        findings.append({
            "severity": SEVERITY_MEDIUM,
            "rule": "CICD-004-MISSING-TOP-LEVEL-PERMISSIONS",
            "line": 1,
            "title": "Ausência de bloco de permissões restritivas de nível superior",
            "desc": "O workflow herda as permissões padrão da organização. Defina explicitamente permissions: read-all no topo do arquivo."
        })

    # 3. Verificação de actions de terceiros sem fixação por commit SHA imutável
    uses_regex = re.compile(r'^\s*[\*\-]\s*uses:\s*([a-zA-Z0-9_\-\.\/]+)@([^\s]+)', re.MULTILINE)
    for match in uses_regex.finditer(content):
        action_name = match.group(1)
        action_ref = match.group(2)
        line_num = content[:match.start()].count("\n") + 1
        
        # Actions locais iniciam com ./
        if action_name.startswith("./"):
            continue
            
        # Commit SHA válido possui exatamente 40 caracteres hexadecimais
        if not re.fullmatch(r'[a-f0-9]{40}', action_ref.strip()):
            findings.append({
                "severity": SEVERITY_HIGH,
                "rule": "CICD-005-UNPINNED-THIRD-PARTY-ACTION",
                "line": line_num,
                "title": f"Action externa não fixada por commit SHA imutável: {action_name}@{action_ref}",
                "desc": "Tags mutáveis (ex: @v3, @main) podem ser sequestradas caso a conta do mantenedor seja comprometida. Fixe pelo SHA de 40 caracteres."
            })

    # 4. Verificação de injeção direta de expressões de contexto em scripts de shell (run:)
    in_run_block = False
    run_indent = 0
    injection_patterns = [
        r'\$\{\{\s*github\.event\.pull_request\.title\s*\}\}',
        r'\$\{\{\s*github\.event\.pull_request\.body\s*\}\}',
        r'\$\{\{\s*github\.event\.issue\.title\s*\}\}',
        r'\$\{\{\s*github\.event\.issue\.body\s*\}\}',
        r'\$\{\{\s*github\.event\.comment\.body\s*\}\}',
        r'\$\{\{\s*github\.head_ref\s*\}\}',
        r'\$\{\{\s*inputs\.[a-zA-Z0-9_]+\s*\}\}'
    ]
    
    for i, line in enumerate(lines):
        clean_line = line.strip()
        if clean_line.startswith("#"):
            continue
            
        for pat in injection_patterns:
            if re.search(pat, line):
                # Verificar se está dentro ou próximo de um bloco de execução
                findings.append({
                    "severity": SEVERITY_CRITICAL,
                    "rule": "CICD-006-DIRECT-CONTEXT-INJECTION",
                    "line": i + 1,
                    "title": "Injeção de expressão de contexto não sanitizada em script bash",
                    "desc": "Injeção direta de contexto controlado pelo usuário em comandos shell. O invasor pode injetar comandos adicionais (ex: '; curl exfil...'). Transfira o valor para variáveis de ambiente (env:)."
                })
                break

    # 5. Verificação de impressão ou eco explícito de secrets
    for i, line in enumerate(lines):
        clean_line = line.strip()
        if re.search(r'echo\s+["\']?\$\{\{\s*secrets\.', clean_line, re.IGNORECASE):
            findings.append({
                "severity": SEVERITY_HIGH,
                "rule": "CICD-007-SECRET-PRINTED-IN-LOGS",
                "line": i + 1,
                "title": "Tentativa de impressão ou eco de segredo em log de execução",
                "desc": "Instrução echo com referência direta a secrets. Mesmo com mascaramento nativo, caracteres truncados ou codificados em base64 podem vazar segredos."
            })

    # 6. Verificação de risco em self-hosted runners persistentes
    for i, line in enumerate(lines):
        if "runs-on:" in line and "self-hosted" in line and not line.strip().startswith("#"):
            findings.append({
                "severity": SEVERITY_MEDIUM,
                "rule": "CICD-008-SELF-HOSTED-RUNNER-PERSISTENCE",
                "line": i + 1,
                "title": "Utilização de self-hosted runner sem garantia de efemeridade",
                "desc": "Runners persistentes podem reter artefatos maliciosos entre execuções de pipelines. Garanta a utilização de runners descartáveis baseados em contêineres isolados."
            })

    return findings

def audit_path(target_path):
    print("=" * 65)
    print("TAVARDT CI/CD Security Auditor & Supply Chain Integrity Inspector")
    print("Inspeção determinística de workflows, permissões e segredos.")
    print("=" * 65)
    print(f"[*] Alvo da auditoria: {target_path}\n")

    files_to_check = []
    if os.path.isfile(target_path):
        files_to_check.append(target_path)
    elif os.path.isdir(target_path):
        for root, _, files in os.walk(target_path):
            for f in files:
                if f.endswith(".yml") or f.endswith(".yaml"):
                    files_to_check.append(os.path.join(root, f))
    else:
        print(f"[ERRO] Caminho inexistente ou inacessível: {target_path}")
        sys.exit(1)

    if not files_to_check:
        print("[!] Nenhum arquivo de workflow YAML identificado no diretório indicado.")
        sys.exit(0)

    total_findings = 0
    critical_count = 0
    high_count = 0
    medium_count = 0

    for fpath in files_to_check:
        print(f"[*] Analisando: {fpath}")
        try:
            with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
        except Exception as e:
            print(f"    [ERRO] Impossível ler arquivo: {e}")
            continue

        findings = audit_workflow_content(fpath, content)
        if not findings:
            print("    [CONFORME] Nenhuma vulnerabilidade ou desvio detectado.")
        else:
            for fd in findings:
                total_findings += 1
                sev = fd["severity"]
                if sev == SEVERITY_CRITICAL:
                    critical_count += 1
                    tag = "[CRÍTICO]"
                elif sev == SEVERITY_HIGH:
                    high_count += 1
                    tag = "[ALTO]"
                else:
                    medium_count += 1
                    tag = "[MÉDIO]"
                    
                print(f"    {tag} Linha {fd['line']}: {fd['title']}")
                print(f"           Regra: {fd['rule']}")
                print(f"           Detalhe: {fd['desc']}")
        print()

    print("=" * 65)
    print("RESUMO DA AUDITORIA DETERMINÍSTICA DE CI/CD")
    print("=" * 65)
    print(f"Total de arquivos inspecionados: {len(files_to_check)}")
    print(f"Total de vulnerabilidades identificadas: {total_findings}")
    print(f"  * Críticas: {critical_count}")
    print(f"  * Altas:    {high_count}")
    print(f"  * Médias:   {medium_count}")
    print("=" * 65)

    if critical_count > 0 or high_count > 0:
        print("[STATUS] REPROVADO: O pipeline contém vulnerabilidades severas de Supply Chain.")
        sys.exit(1)
    else:
        print("[STATUS] APROVADO: Workflows em conformidade com as diretrizes TAVARDT Zero Trust.")
        sys.exit(0)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Uso: python audit_ci_cd_security.py <caminho_arquivo_ou_diretório>")
        print("Exemplo 1: python audit_ci_cd_security.py .github/workflows/")
        print("Exemplo 2: python audit_ci_cd_security.py .github/workflows/deploy.yml")
        sys.exit(1)

    target = sys.argv[1]
    audit_path(target)
