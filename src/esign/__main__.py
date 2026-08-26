"""Sobe o servidor de webhooks.

    python -m esign            # desenvolvimento
    uvicorn esign.__main__:app # produção, atrás de um proxy com TLS
"""

from __future__ import annotations

import logging
import os

from bitrix24_client import from_env

from .servidor import Rastreador, criar_app, segredo_do_ambiente

logging.basicConfig(
    level=os.environ.get("LOG_LEVEL", "INFO"),
    format="%(asctime)s %(levelname)-7s %(name)s %(message)s",
)

# `segredo_do_ambiente` levanta se a variável não existir: melhor falhar na
# subida do que expor um endpoint que aceita qualquer requisição.
app = criar_app(
    Rastreador(from_env(), dry_run=os.environ.get("ESIGN_DRY_RUN", "1") == "1"),
    segredo_do_ambiente(),
)


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=int(os.environ.get("PORT", "8000")))
