"""Eventos de assinatura eletrônica: validação de origem e máquina de estados.

Webhook de assinatura é um endpoint público que move negócio no CRM. Duas
coisas precisam ser verdade antes de ele mexer em qualquer coisa:

**A origem é autêntica.** Sem verificação de assinatura HMAC, qualquer um que
descubra a URL fecha contratos no seu CRM. A comparação usa
``hmac.compare_digest`` — comparar com ``==`` vaza informação pelo tempo de
resposta e permite descobrir o segredo byte a byte.

**A transição é válida.** Provedores reenviam eventos e a ordem de chegada
não é garantida: um `assinado` pode chegar depois de um `recusado` por causa
de uma retentativa. Sem máquina de estados, o último a chegar ganha — e um
contrato recusado aparece como fechado.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Any


class Estado(str, Enum):
    """Situação do documento, na ordem natural do fluxo."""

    CRIADO = "criado"
    ENVIADO = "enviado"
    VISUALIZADO = "visualizado"
    ASSINADO = "assinado"
    RECUSADO = "recusado"
    EXPIRADO = "expirado"
    CANCELADO = "cancelado"


#: Estados terminais: uma vez neles, nenhum evento posterior muda nada.
TERMINAIS = frozenset({Estado.ASSINADO, Estado.RECUSADO, Estado.EXPIRADO, Estado.CANCELADO})

#: Transições permitidas. O que não está aqui é reordenação ou reenvio.
TRANSICOES: dict[Estado, frozenset[Estado]] = {
    Estado.CRIADO: frozenset({Estado.ENVIADO, Estado.CANCELADO}),
    Estado.ENVIADO: frozenset(
        {Estado.VISUALIZADO, Estado.ASSINADO, Estado.RECUSADO,
         Estado.EXPIRADO, Estado.CANCELADO}
    ),
    Estado.VISUALIZADO: frozenset(
        {Estado.ASSINADO, Estado.RECUSADO, Estado.EXPIRADO, Estado.CANCELADO}
    ),
    Estado.ASSINADO: frozenset(),
    Estado.RECUSADO: frozenset(),
    Estado.EXPIRADO: frozenset(),
    Estado.CANCELADO: frozenset(),
}

#: Nomes que os provedores usam. Cada um inventa o seu.
APELIDOS = {
    # Clicksign
    "document.created": Estado.CRIADO,
    "document.sent": Estado.ENVIADO,
    "document.viewed": Estado.VISUALIZADO,
    "document.signed": Estado.ASSINADO,
    "document.refused": Estado.RECUSADO,
    "auto_close": Estado.ASSINADO,
    # D4Sign
    "1": Estado.CRIADO,
    "2": Estado.ENVIADO,
    "4": Estado.ASSINADO,
    "5": Estado.RECUSADO,
    # Genéricos
    "created": Estado.CRIADO,
    "sent": Estado.ENVIADO,
    "viewed": Estado.VISUALIZADO,
    "opened": Estado.VISUALIZADO,
    "signed": Estado.ASSINADO,
    "completed": Estado.ASSINADO,
    "declined": Estado.RECUSADO,
    "refused": Estado.RECUSADO,
    "expired": Estado.EXPIRADO,
    "cancelled": Estado.CANCELADO,
    "canceled": Estado.CANCELADO,
}


class AssinaturaInvalida(ValueError):
    """HMAC não confere — a requisição não veio do provedor."""


class TransicaoInvalida(ValueError):
    """Evento que não faz sentido a partir do estado atual."""


class CorpoInvalido(ValueError):
    """Corpo do webhook fora do contrato: JSON quebrado ou que não é objeto.

    Herda de `ValueError` de propósito. Para o endpoint, um corpo malformado é
    uma só categoria — entrada ruim, resposta 4xx — e o handler a trata num
    único `except ValueError`. Um `TypeError` aqui escaparia desse `except` e
    viraria 500, transformando cliente mal-educado em erro nosso.
    """


@dataclass(frozen=True)
class Evento:
    """Um evento já normalizado, independente do provedor."""

    documento_id: str
    estado: Estado
    quando: datetime | None
    signatario: str = ""
    bruto: dict[str, Any] | None = None


def validar_assinatura(corpo: bytes, cabecalho: str, segredo: str) -> None:
    """Confere o HMAC-SHA256 do corpo.

    Args:
        corpo: bytes exatos recebidos — **não** o JSON reserializado. Qualquer
            diferença de espaço ou ordem de chave muda o hash, e reserializar
            é o erro que faz a validação falhar em produção e "funcionar" nos
            testes.
        cabecalho: valor recebido, com ou sem prefixo ``sha256=``.
        segredo: chave compartilhada com o provedor.

    Raises:
        AssinaturaInvalida: quando não confere ou o cabeçalho está ausente.
    """
    if not cabecalho:
        raise AssinaturaInvalida("requisicao sem cabecalho de assinatura")
    if not segredo:
        raise AssinaturaInvalida("segredo do webhook nao configurado")

    recebida = cabecalho.split("=", 1)[-1].strip()
    esperada = hmac.new(segredo.encode(), corpo, hashlib.sha256).hexdigest()

    # compare_digest, nunca `==`: a comparacao curto-circuitada vaza o
    # segredo pelo tempo de resposta, byte a byte.
    if not hmac.compare_digest(recebida, esperada):
        raise AssinaturaInvalida("assinatura nao confere")


def normalizar(payload: dict[str, Any]) -> Evento:
    """Converte o payload do provedor no formato interno.

    Cada provedor nomeia os campos do seu jeito. Concentrar a tradução aqui
    deixa o resto do robô ignorante sobre qual serviço está em uso — trocar
    de fornecedor mexe só neste arquivo.

    Raises:
        ValueError: evento sem tipo reconhecível ou sem identificador.
    """
    tipo = str(
        payload.get("event")
        or payload.get("type")
        or payload.get("tipo_post")
        or ""
    ).lower()
    estado = APELIDOS.get(tipo)
    if estado is None:
        raise ValueError(f"tipo de evento desconhecido: {tipo!r}")

    documento = str(
        payload.get("document_key")
        or payload.get("uuid")
        or (payload.get("document") or {}).get("key")
        or payload.get("id")
        or ""
    )
    if not documento:
        raise ValueError("evento sem identificador de documento")

    return Evento(
        documento_id=documento,
        estado=estado,
        quando=_para_datetime(payload.get("occurred_at") or payload.get("data")),
        signatario=str(
            payload.get("signer_email")
            or (payload.get("signer") or {}).get("email")
            or ""
        ),
        bruto=payload,
    )


def pode_transitar(atual: Estado | None, novo: Estado) -> bool:
    """``True`` se a transição é válida.

    Documento desconhecido (``atual is None``) aceita qualquer estado: o robô
    pode ter sido ligado no meio de um fluxo já em andamento.
    """
    if atual is None:
        return True
    return novo in TRANSICOES[atual]


def aplicar(atual: Estado | None, evento: Evento) -> Estado:
    """Devolve o novo estado, recusando reordenação e reenvio.

    Raises:
        TransicaoInvalida: o evento chegou fora de ordem ou é repetido. Quem
            chama decide se ignora (o caso comum, porque provedor reenvia) ou
            se alerta.
    """
    if atual == evento.estado:
        raise TransicaoInvalida(f"evento repetido: ja estava em {atual.value}")
    if atual in TERMINAIS:
        raise TransicaoInvalida(
            f"documento ja estava em {atual.value}, que e terminal; "
            f"ignorando {evento.estado.value}"
        )
    if not pode_transitar(atual, evento.estado):
        raise TransicaoInvalida(
            f"transicao invalida: {atual.value if atual else 'novo'} -> {evento.estado.value}"
        )
    return evento.estado


def ler_corpo(corpo: bytes) -> dict[str, Any]:
    """Decodifica o JSON do webhook com mensagem útil quando falha."""
    try:
        dados = json.loads(corpo)
    except json.JSONDecodeError as exc:
        raise CorpoInvalido(f"corpo nao e JSON valido: {exc}") from exc
    if not isinstance(dados, dict):
        raise CorpoInvalido("corpo do webhook precisa ser um objeto JSON")
    return dados


def _para_datetime(bruto: Any) -> datetime | None:
    if not bruto:
        return None
    try:
        return datetime.fromisoformat(str(bruto).replace("Z", "+00:00"))
    except ValueError:
        return None
