"""Testes do endpoint, com um rastreador de mentira no lugar do CRM."""

from __future__ import annotations

import hashlib
import hmac
import json

import pytest
from fastapi.testclient import TestClient

from esign.eventos import Evento
from esign.servidor import criar_app

SEGREDO = "segredo-de-teste"


class RastreadorFalso:
    """Registra o que recebeu, sem tocar em portal nenhum."""

    def __init__(self, erro: Exception | None = None) -> None:
        self.recebidos: list[Evento] = []
        self.erro = erro

    def processar(self, evento: Evento) -> str:
        self.recebidos.append(evento)
        if self.erro:
            raise self.erro
        return f"ok: {evento.estado.value}"


@pytest.fixture
def rastreador():
    return RastreadorFalso()


@pytest.fixture
def cliente(rastreador):
    return TestClient(criar_app(rastreador, SEGREDO))


def enviar(cliente, payload: dict, segredo: str = SEGREDO, assinar: bool = True):
    corpo = json.dumps(payload).encode()
    cabecalhos = {}
    if assinar:
        assinatura = hmac.new(segredo.encode(), corpo, hashlib.sha256).hexdigest()
        cabecalhos["X-Signature"] = f"sha256={assinatura}"
    return cliente.post("/webhook/assinatura", content=corpo, headers=cabecalhos)


class TestSaude:
    def test_endpoint_de_saude(self, cliente):
        assert cliente.get("/saude").json() == {"status": "ok"}


class TestSeguranca:
    def test_assinatura_valida_e_aceita(self, cliente, rastreador):
        resposta = enviar(cliente, {"event": "document.signed", "document_key": "k1"})
        assert resposta.status_code == 202
        assert len(rastreador.recebidos) == 1

    def test_sem_assinatura_e_401(self, cliente, rastreador):
        resposta = enviar(cliente, {"event": "signed", "id": "k1"}, assinar=False)
        assert resposta.status_code == 401
        assert rastreador.recebidos == [], "nao pode chegar ao CRM"

    def test_assinatura_de_outro_segredo_e_401(self, cliente, rastreador):
        resposta = enviar(cliente, {"event": "signed", "id": "k1"}, segredo="errado")
        assert resposta.status_code == 401
        assert rastreador.recebidos == []


class TestResiliencia:
    def test_payload_desconhecido_responde_202_e_nao_processa(self, cliente, rastreador):
        """Provedor trata 4xx/5xx como falha e reenvia; 202 encerra a fila."""
        resposta = enviar(cliente, {"event": "evento_novo_do_provedor", "id": "k1"})
        assert resposta.status_code == 202
        assert "ignorado" in resposta.json()["resultado"]
        assert rastreador.recebidos == []

    def test_erro_no_crm_ainda_responde_202(self):
        """Reenvio em escalada por erro no CRM piora o problema."""
        from bitrix24_client.errors import BitrixAPIError

        falho = RastreadorFalso(erro=BitrixAPIError("ERRO", "portal fora", "crm.deal.update"))
        cliente = TestClient(criar_app(falho, SEGREDO))
        resposta = enviar(cliente, {"event": "signed", "id": "k1"})
        assert resposta.status_code == 202
        assert "erro registrado" in resposta.json()["resultado"]

    def test_corpo_nao_json_responde_202(self, cliente):
        corpo = b"isso nao e json"
        assinatura = hmac.new(SEGREDO.encode(), corpo, hashlib.sha256).hexdigest()
        resposta = cliente.post(
            "/webhook/assinatura", content=corpo, headers={"X-Signature": assinatura}
        )
        assert resposta.status_code == 202
        assert "ignorado" in resposta.json()["resultado"]


class TestNormalizacaoNoEndpoint:
    def test_evento_chega_normalizado_ao_rastreador(self, cliente, rastreador):
        enviar(
            cliente,
            {
                "event": "document.signed",
                "document_key": "abc123",
                "signer_email": "joao@x.com.br",
            },
        )
        evento = rastreador.recebidos[0]
        assert evento.documento_id == "abc123"
        assert evento.signatario == "joao@x.com.br"
