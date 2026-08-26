"""Endpoint FastAPI que recebe os eventos e move o negócio no Bitrix24.

O handler responde **202 rápido e sempre**, exceto quando a assinatura HMAC
falha. Provedor de assinatura trata resposta lenta ou 5xx como falha e
reenvia — às vezes em escalada. Um erro no CRM não pode virar uma tempestade
de retentativas.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from bitrix24_client import Bitrix24
from bitrix24_client.errors import BitrixError

# Importado no topo, e não dentro de `criar_app`, de propósito. Com
# `from __future__ import annotations` as anotações viram strings, e o FastAPI
# as resolve contra os **globais do módulo**. Com o import dentro da função,
# `Request` e `Response` não existem ali — e o FastAPI, sem conseguir
# resolvê-los, os trata como parâmetros de query. O resultado é todo POST
# devolvendo 422 "field required: request", sem nenhuma pista da causa.
from fastapi import FastAPI, Header, Request, Response

from .eventos import (
    AssinaturaInvalida,
    Estado,
    Evento,
    TransicaoInvalida,
    aplicar,
    ler_corpo,
    normalizar,
    validar_assinatura,
)

log = logging.getLogger("esign")

#: Para qual estágio mover o negócio em cada desfecho.
ESTAGIO_POR_ESTADO = {
    Estado.ENVIADO: "C1:UC_ASSINATURA",
    Estado.ASSINADO: "C1:WON",
    Estado.RECUSADO: "C1:LOSE",
    Estado.EXPIRADO: "C1:LOSE",
    Estado.CANCELADO: "C1:LOSE",
}

#: Texto que vai para a timeline em cada estado.
TEXTO_POR_ESTADO = {
    Estado.ENVIADO: "Contrato enviado para assinatura.",
    Estado.VISUALIZADO: "O cliente abriu o contrato.",
    Estado.ASSINADO: "Contrato ASSINADO.",
    Estado.RECUSADO: "O cliente RECUSOU a assinatura.",
    Estado.EXPIRADO: "O prazo de assinatura expirou.",
    Estado.CANCELADO: "A solicitacao de assinatura foi cancelada.",
}


@dataclass
class Rastreador:
    """Aplica um evento ao negócio correspondente."""

    bx: Bitrix24
    campo_documento: str = "UF_CRM_DOC_ASSINATURA"
    campo_estado: str = "UF_CRM_STATUS_ASSINATURA"
    dry_run: bool = True
    estagios: dict[Estado, str] = field(default_factory=lambda: dict(ESTAGIO_POR_ESTADO))

    def processar(self, evento: Evento) -> str:
        """Aplica o evento e devolve uma descrição do que aconteceu."""
        negocio = self._negocio_do_documento(evento.documento_id)
        if not negocio:
            return f"documento {evento.documento_id} sem negocio vinculado"

        deal_id = int(negocio["ID"])
        atual = _estado_atual(negocio.get(self.campo_estado))

        try:
            novo = aplicar(atual, evento)
        except TransicaoInvalida as exc:
            # Reenvio e reordenacao sao rotina, nao incidente: registra e sai.
            log.info("negocio %d: %s", deal_id, exc)
            return str(exc)

        campos: dict[str, Any] = {self.campo_estado: novo.value}
        estagio = self.estagios.get(novo)
        if estagio:
            campos["STAGE_ID"] = estagio

        if self.dry_run:
            log.info("[simulacao] negocio %d -> %s", deal_id, campos)
            return f"simulado: {atual.value if atual else 'novo'} -> {novo.value}"

        self.bx.call("crm.deal.update", {"id": deal_id, "fields": campos})
        self._anotar(deal_id, novo, evento)
        return f"negocio {deal_id}: {atual.value if atual else 'novo'} -> {novo.value}"

    def _negocio_do_documento(self, documento_id: str) -> dict[str, Any] | None:
        achados = list(
            self.bx.fetch_all(
                "crm.deal.list",
                {
                    "filter": {self.campo_documento: documento_id},
                    "select": ["ID", "TITLE", "STAGE_ID", self.campo_estado],
                },
            )
        )
        return achados[0] if achados else None

    def _anotar(self, deal_id: int, estado: Estado, evento: Evento) -> None:
        texto = TEXTO_POR_ESTADO.get(estado, f"Assinatura: {estado.value}")
        if evento.signatario:
            texto += f" Signatario: {evento.signatario}."
        if evento.quando:
            texto += f" Em {evento.quando.strftime('%d/%m/%Y %H:%M')}."
        self.bx.call(
            "crm.timeline.comment.add",
            {"fields": {"ENTITY_ID": deal_id, "ENTITY_TYPE": "deal", "COMMENT": texto}},
        )


def criar_app(rastreador: Rastreador, segredo: str):
    """Monta o app FastAPI com o endpoint de webhook.

    A função existe para o app receber suas dependências por parâmetro em vez
    de importá-las do módulo — assim o teste monta um app com um rastreador
    de mentira sem tocar em variável global.
    """
    app = FastAPI(title="Rastreador de assinatura", version="1.0.0")

    @app.get("/saude")
    def saude() -> dict[str, str]:
        return {"status": "ok"}

    @app.post("/webhook/assinatura", status_code=202)
    async def webhook(
        request: Request,
        response: Response,
        x_signature: str = Header(default="", alias="X-Signature"),
    ) -> dict[str, str]:
        corpo = await request.body()

        try:
            validar_assinatura(corpo, x_signature, segredo)
        except AssinaturaInvalida as exc:
            # Unico caso de erro para o provedor: requisicao nao autentica
            # nao deve ser reenviada, deve ser investigada.
            log.warning("webhook recusado: %s", exc)
            response.status_code = 401
            return {"erro": str(exc)}

        try:
            evento = normalizar(ler_corpo(corpo))
        except ValueError as exc:
            log.warning("payload ignorado: %s", exc)
            return {"resultado": f"ignorado: {exc}"}

        try:
            resultado = rastreador.processar(evento)
        except BitrixError as exc:
            # 202 mesmo assim: reenvio em escalada por causa de um erro no
            # CRM piora o problema em vez de resolver.
            log.exception("falha ao processar %s", evento.documento_id)
            return {"resultado": f"erro registrado: {exc}"}

        return {"resultado": resultado}

    return app


def _estado_atual(bruto: Any) -> Estado | None:
    if not bruto:
        return None
    try:
        return Estado(str(bruto))
    except ValueError:
        return None


def segredo_do_ambiente() -> str:
    """Lê o segredo do webhook, exigindo que ele exista.

    Falhar na subida é melhor que subir um endpoint que aceita qualquer
    requisição — um endpoint público que move negócio no CRM sem verificação
    é convite aberto.
    """
    segredo = os.environ.get("ESIGN_WEBHOOK_SECRET", "")
    if not segredo:
        raise RuntimeError(
            "ESIGN_WEBHOOK_SECRET nao definido. Sem ele o endpoint aceitaria "
            "qualquer requisicao."
        )
    return segredo


def agora() -> datetime:
    return datetime.now()
