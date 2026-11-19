#!/usr/bin/env python3
"""Cyber Hunt Lab: bounded, non-invasive HTTP configuration audit."""
import argparse
import datetime as dt
import html
import ipaddress
import json
import os
import socket
import ssl
import sys
import time
from pathlib import Path
from urllib.parse import urlsplit, urljoin
import requests

UA = 'CyberHuntLab-AuthorizedAudit/2026 (+non-invasive; contact operator)'
SEC_HEADERS = {'strict-transport-security':'HSTS', 'content-security-policy':'CSP', 'x-content-type-options':'X-Content-Type-Options', 'referrer-policy':'Referrer-Policy', 'permissions-policy':'Permissions-Policy'}

def public_addresses(host):
    try:
        answers = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except socket.gaierror as e:
        raise ValueError(f'DNS indisponível: {e}') from e
    ips = {a[4][0] for a in answers}
    if not ips or any(not ipaddress.ip_address(x).is_global for x in ips):
        raise ValueError('Destino DNS não público ou potencialmente interno bloqueado')
    return sorted(ips)

def validate_url(url, allowed_host):
    p = urlsplit(url)
    if p.scheme not in ('http','https') or not p.hostname or p.username or p.password:
        raise ValueError('URL inválida: somente HTTP(S) sem credenciais')
    if p.hostname.lower().rstrip('.') != allowed_host.lower().rstrip('.'):
        raise ValueError('Host fora do escopo declarado')
    if p.port not in (None,80,443):
        raise ValueError('Porta não autorizada (somente 80/443)')
    public_addresses(p.hostname)
    return p

def finding(code, title, severity, evidence, recommendation, status='OBSERVATION'):
    return dict(id=code, title=title, severity=severity, status=status, evidence=evidence, recommendation=recommendation)

def tls_info(host):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((host,443), timeout=6) as sock:
            with context.wrap_socket(sock, server_hostname=host) as tls:
                cert = tls.getpeercert()
                return {'protocol':tls.version(), 'cipher':tls.cipher()[0], 'certificate_expires':cert.get('notAfter'), 'verified':True}
    except Exception as e:
        return {'verified':False,'error':str(e)[:250]}

def audit(url, host, max_requests, delay):
    validate_url(url,host)
    report={'project':'Cyber Hunt Lab Termux','target':url,'scope_host':host,'started_at':dt.datetime.now(dt.timezone.utc).isoformat(),'authorization':'Operator attested explicit permission; scope restricted to exact host','method':'GET only; no crawling, fuzzing, or authentication','findings':[],'observations':{},'requests_made':0,'limitations':[]}
    session=requests.Session(); session.trust_env=False
    session.headers.update({'User-Agent':UA,'Accept':'text/html,application/json;q=0.8,*/*;q=0.5'})
    current=url
    for i in range(min(max_requests,3)):
        validate_url(current,host)
        # Recheck immediately before every request. DNS rebinding remains a limitation of requests' separate resolution.
        try:
            response=session.get(current,timeout=(5,8),allow_redirects=False,stream=True)
        except requests.RequestException as e:
            report['limitations'].append('Falha HTTP: '+str(e)[:240]); break
        report['requests_made']+=1
        headers={k.lower():v for k,v in response.headers.items()}
        report['observations'].setdefault('http',[]).append({'url':current,'status':response.status_code,'headers':{k:v[:350] for k,v in headers.items() if k in SEC_HEADERS or k in ('server','content-type','cache-control','access-control-allow-origin','retry-after','location','x-ratelimit-limit','ratelimit-limit')}})
        if response.status_code == 429:
            report['limitations'].append('HTTP 429 recebido; auditoria interrompida. Retry-After: '+headers.get('retry-after','não informado')); response.close(); break
        if response.status_code in (301,302,303,307,308) and 'location' in headers:
            nxt=urljoin(current,headers['location']); response.close()
            try: validate_url(nxt,host)
            except ValueError: report['limitations'].append('Redirecionamento fora do escopo bloqueado: '+nxt[:200]); break
            if i == min(max_requests,3)-1: report['limitations'].append('Limite de redirecionamentos atingido'); break
            current=nxt; time.sleep(delay); continue
        if urlsplit(current).scheme=='https':
            for key,label in SEC_HEADERS.items():
                if key not in headers:
                    report['findings'].append(finding('HEADER_'+key.upper().replace('-','_'),label+' ausente','LOW','Cabeçalho não observado na resposta HTTP','Avaliar política apropriada e impacto na aplicação'))
        if headers.get('access-control-allow-origin')=='*':
            report['findings'].append(finding('CORS_WILDCARD','CORS com origem curinga','INFO','Access-Control-Allow-Origin: *','Confirmar se a API publica dados intencionalmente; curinga não implica vulnerabilidade'))
        if 'set-cookie' in headers:
            cookie=headers['set-cookie'].lower()
            for attr in ('secure','httponly','samesite'):
                if attr not in cookie:
                    report['findings'].append(finding('COOKIE_'+attr.upper(),'Atributo de cookie não observado: '+attr,'LOW','Um cabeçalho Set-Cookie não contém '+attr,'Revisar cookies de sessão; inspeção agregada pode não cobrir todos os cookies'))
        response.close()
        break
    if urlsplit(url).scheme=='https': report['observations']['tls']=tls_info(host)
    else: report['findings'].append(finding('HTTP_SCHEME','URL inicial sem HTTPS','MEDIUM','Esquema HTTP informado','Usar HTTPS e avaliar redirecionamento seguro'))
    report['limitations'].append('Auditoria superficial de configuração; não comprova XSS, SQLi, IDOR, CSRF ou outras falhas exploráveis')
    report['limitations'].append('Verificação DNS pré-requisição não fixa o IP da conexão; não usar contra destinos que possam sofrer DNS rebinding')
    report['finished_at']=dt.datetime.now(dt.timezone.utc).isoformat()
    return report

def ai_summary(report, api_key, model):
    # No secret headers, response bodies or cookies are sent to the model.
    sanitized={k:report[k] for k in ('target','findings','limitations')}
    payload={'model':model,'messages':[{'role':'system','content':'Analise somente as evidências fornecidas de uma auditoria autorizada. Não invente vulnerabilidades nem provas de exploração. Responda em português, diferenciando observações de falhas confirmadas.'},{'role':'user','content':json.dumps(sanitized,ensure_ascii=False)}], 'temperature':0.1}
    try:
        r=requests.post('https://api.openai.com/v1/chat/completions',headers={'Authorization':'Bearer '+api_key},json=payload,timeout=35)
        r.raise_for_status(); return r.json()['choices'][0]['message']['content']
    except Exception as e: return 'Análise IA não executada: '+str(e)[:240]

def main():
    parser=argparse.ArgumentParser(description='Cyber Hunt Lab - Termux')
    parser.add_argument('--url'); parser.add_argument('--scope-host'); parser.add_argument('--yes-authorized',action='store_true'); parser.add_argument('--max-requests',type=int,default=2); parser.add_argument('--delay',type=float,default=2); parser.add_argument('--ai',action='store_true'); parser.add_argument('--model',default=os.getenv('OPENAI_MODEL','gpt-4.1-mini'))
    a=parser.parse_args()
    url=a.url or input('URL HTTPS do alvo: ').strip()
    host=a.scope_host or input('Host exato autorizado (ex: exemplo.com): ').strip()
    if not a.yes_authorized:
        confirmation=input('Confirma autorização explícita e escopo para esta URL? Digite AUTORIZADO: ').strip()
        if confirmation!='AUTORIZADO': sys.exit('Auditoria cancelada: autorização não confirmada')
    if not 1<=a.max_requests<=3 or a.delay<1: sys.exit('Limites: 1-3 requisições, atraso mínimo 1 segundo')
    try: report=audit(url,host,a.max_requests,a.delay)
    except (ValueError,KeyboardInterrupt) as e: sys.exit('Auditoria interrompida: '+str(e))
    if a.ai:
        key=os.getenv('OPENAI_API_KEY','')
        report['ai_analysis']=ai_summary(report,key,a.model) if key else 'NOT_EXECUTED: OPENAI_API_KEY ausente'
    out=Path('reports'); out.mkdir(exist_ok=True)
    stamp=dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    base=out/('audit-'+stamp)
    (base.with_suffix('.json')).write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding='utf-8')
    lines=['# Cyber Hunt Lab — Relatório','',f"Alvo: `{report['target']}`",f"Escopo: `{host}`",f"Requisições: {report['requests_made']}",'','## Achados']
    for f in report['findings']: lines.extend(['',f"### {f['title']} [{f['severity']}]",f"Status: {f['status']}",f"Evidência: {f['evidence']}",f"Recomendação: {f['recommendation']}"])
    if not report['findings']: lines.append('Nenhum achado identificado nesta verificação limitada.')
    lines+=['','## Limitações']+['- '+s for s in report['limitations']]
    if 'ai_analysis' in report: lines+=['','## Análise opcional de IA',report['ai_analysis']]
    md='\n'.join(lines)+'\n'
    (base.with_suffix('.md')).write_text(md,encoding='utf-8')
    (base.with_suffix('.html')).write_text('<!doctype html><html lang="pt-BR"><meta charset="utf-8"><title>Cyber Hunt Lab Audit</title><style>body{max-width:850px;margin:3rem auto;font:16px/1.6 system-ui;padding:1rem;background:#0c1220;color:#e8eef8}pre{white-space:pre-wrap}</style><h1>Cyber Hunt Lab</h1><pre>'+html.escape(md)+'</pre></html>',encoding='utf-8')
    print(f"\nConcluído: {report['requests_made']} requisição(ões), {len(report['findings'])} observações. Arquivos: {base}.json/.md/.html")

if __name__=='__main__': main()
