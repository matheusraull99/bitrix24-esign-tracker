"""Rastreador de assinatura eletronica integrado ao Bitrix24."""

from .eventos import (
    APELIDOS,
    TERMINAIS,
    TRANSICOES,
    AssinaturaInvalida,
    CorpoInvalido,
    Estado,
    Evento,
    TransicaoInvalida,
    aplicar,
    ler_corpo,
    normalizar,
    pode_transitar,
    validar_assinatura,
)
from .servidor import ESTAGIO_POR_ESTADO, Rastreador, criar_app, segredo_do_ambiente

__version__ = "1.0.0"

__all__ = [
    "APELIDOS",
    "ESTAGIO_POR_ESTADO",
    "TERMINAIS",
    "TRANSICOES",
    "AssinaturaInvalida",
    "CorpoInvalido",
    "Estado",
    "Evento",
    "Rastreador",
    "TransicaoInvalida",
    "aplicar",
    "criar_app",
    "ler_corpo",
    "normalizar",
    "pode_transitar",
    "segredo_do_ambiente",
    "validar_assinatura",
]
