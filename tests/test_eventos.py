"""Testes de segurança do webhook e da máquina de estados."""

from __future__ import annotations

import hashlib
import hmac
import json
from datetime import datetime

import pytest

from esign.eventos import (
    AssinaturaInvalida,
    Estado,
    Evento,
    TransicaoInvalida,
    aplicar,
    ler_corpo,
    normalizar,
    pode_transitar,
    validar_assinatura,
)

SEGREDO = "segredo-do-webhook"


def assinar(corpo: bytes, segredo: str = SEGREDO) -> str:
    return "sha256=" + hmac.new(segredo.encode(), corpo, hashlib.sha256).hexdigest()


class TestAssinatura:
    def test_assinatura_correta_passa(self):
        corpo = b'{"event":"document.signed","document_key":"abc"}'
        validar_assinatura(corpo, assinar(corpo), SEGREDO)  # nao levanta

    def test_aceita_com_e_sem_prefixo(self):
        corpo = b'{"a":1}'
        assinatura = assinar(corpo)
        validar_assinatura(corpo, assinatura, SEGREDO)
        validar_assinatura(corpo, assinatura.split("=", 1)[1], SEGREDO)

    def test_segredo_errado_e_recusado(self):
        corpo = b'{"a":1}'
        with pytest.raises(AssinaturaInvalida, match="nao confere"):
            validar_assinatura(corpo, assinar(corpo, "outro"), SEGREDO)

    def test_corpo_alterado_e_recusado(self):
        """O ataque obvio: assinatura valida de outro payload."""
        original = b'{"valor":100}'
        adulterado = b'{"valor":999999}'
        with pytest.raises(AssinaturaInvalida):
            validar_assinatura(adulterado, assinar(original), SEGREDO)

    def test_sem_cabecalho_e_recusado(self):
        with pytest.raises(AssinaturaInvalida, match="sem cabecalho"):
            validar_assinatura(b"{}", "", SEGREDO)

    def test_sem_segredo_configurado_e_recusado(self):
        """Nao configurar o segredo nao pode virar 'aceita tudo'."""
        with pytest.raises(AssinaturaInvalida, match="nao configurado"):
            validar_assinatura(b"{}", assinar(b"{}"), "")

    def test_reserializar_o_json_quebra_a_assinatura(self):
        """Documenta por que o handler usa os bytes crus da requisicao.

        Basta o provedor enviar sem espaco depois dos dois-pontos — como a
        maioria envia — para o `json.dumps` do Python produzir bytes
        diferentes e a validacao falhar so em producao.
        """
        corpo = b'{"event":"signed","id":"k1"}'
        reserializado = json.dumps(json.loads(corpo)).encode()
        assert corpo != reserializado, "o dumps do Python insere espacos"
        with pytest.raises(AssinaturaInvalida):
            validar_assinatura(reserializado, assinar(corpo), SEGREDO)


class TestNormalizar:
    @pytest.mark.parametrize(
        "payload,esperado",
        [
            ({"event": "document.signed", "document_key": "k1"}, Estado.ASSINADO),
            ({"event": "document.refused", "document_key": "k1"}, Estado.RECUSADO),
            ({"tipo_post": "4", "uuid": "k1"}, Estado.ASSINADO),
            ({"type": "completed", "id": "k1"}, Estado.ASSINADO),
            ({"event": "opened", "id": "k1"}, Estado.VISUALIZADO),
        ],
    )
    def test_traduz_o_dialeto_de_cada_provedor(self, payload, esperado):
        assert normalizar(payload).estado is esperado

    def test_extrai_documento_aninhado(self):
        payload = {"event": "signed", "document": {"key": "abc123"}}
        assert normalizar(payload).documento_id == "abc123"

    def test_extrai_signatario_e_data(self):
        payload = {
            "event": "signed",
            "document_key": "k1",
            "signer_email": "joao@x.com.br",
            "occurred_at": "2026-09-15T14:03:00Z",
        }
        evento = normalizar(payload)
        assert evento.signatario == "joao@x.com.br"
        assert evento.quando == datetime.fromisoformat("2026-09-15T14:03:00+00:00")

    def test_tipo_desconhecido_levanta(self):
        with pytest.raises(ValueError, match="desconhecido"):
            normalizar({"event": "algo_novo", "id": "k1"})

    def test_sem_identificador_levanta(self):
        with pytest.raises(ValueError, match="sem identificador"):
            normalizar({"event": "signed"})


class TestMaquinaDeEstados:
    def test_fluxo_feliz(self):
        estado = None
        for esperado in (Estado.CRIADO, Estado.ENVIADO, Estado.VISUALIZADO, Estado.ASSINADO):
            estado = aplicar(estado, Evento("k1", esperado, None))
        assert estado is Estado.ASSINADO

    def test_documento_novo_aceita_qualquer_estado(self):
        """O robo pode ter sido ligado no meio de um fluxo em andamento."""
        assert aplicar(None, Evento("k1", Estado.ASSINADO, None)) is Estado.ASSINADO

    def test_evento_repetido_e_recusado(self):
        with pytest.raises(TransicaoInvalida, match="repetido"):
            aplicar(Estado.ASSINADO, Evento("k1", Estado.ASSINADO, None))

    def test_assinado_depois_de_recusado_nao_passa(self):
        """O caso caro: retentativa fora de ordem fecharia um contrato recusado."""
        with pytest.raises(TransicaoInvalida, match="terminal"):
            aplicar(Estado.RECUSADO, Evento("k1", Estado.ASSINADO, None))

    def test_voltar_para_enviado_depois_de_assinado_nao_passa(self):
        with pytest.raises(TransicaoInvalida):
            aplicar(Estado.ASSINADO, Evento("k1", Estado.ENVIADO, None))

    def test_pular_visualizado_e_permitido(self):
        """Cliente pode assinar sem que o 'viewed' chegue antes."""
        assert pode_transitar(Estado.ENVIADO, Estado.ASSINADO)

    def test_cancelar_um_enviado_e_permitido(self):
        assert pode_transitar(Estado.ENVIADO, Estado.CANCELADO)

    def test_todos_os_estados_tem_transicao_declarada(self):
        """Guarda contra alguem adicionar um estado e esquecer a tabela."""
        from esign.eventos import TRANSICOES

        assert set(TRANSICOES) == set(Estado)


class TestLerCorpo:
    def test_json_valido(self):
        assert ler_corpo(b'{"a":1}') == {"a": 1}

    def test_json_invalido_levanta_com_motivo(self):
        with pytest.raises(ValueError, match="nao e JSON"):
            ler_corpo(b"{isso nao e json")

    def test_lista_no_topo_e_recusada(self):
        with pytest.raises(ValueError, match="objeto JSON"):
            ler_corpo(b"[1,2,3]")
