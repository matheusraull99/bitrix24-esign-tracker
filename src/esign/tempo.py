"""Hora no fuso de quem acompanha a assinatura — nunca no fuso do servidor.

`datetime.now()` sem fuso devolve a hora do relógio da máquina, *e sem dizer
qual fuso é*. Num servidor de nuvem (e no `ubuntu-latest` do CI) isso é UTC:
das 21h à meia-noite de Brasília o dia já virou lá, e o carimbo sai três horas
adiantado sem nenhum sinal de que está errado.

Aqui isso apareceria no lugar mais visível do robô: o comentário que ele grava
na timeline do negócio ("Em 15/09/2026 14:03"). O provedor de assinatura manda
o instante em UTC (`...Z`), e imprimir esse valor cru mostra ao vendedor uma
hora que não é a que o cliente assinou. Pior, é uma hora plausível — ninguém
desconfia de três horas de diferença, só acha que o cliente assinou de manhã.

Por isso todo instante passa por `no_fuso()` antes de virar texto: o que chega
ciente do fuso é *convertido* para São Paulo, e o que chega ingênuo é assumido
como já sendo hora de São Paulo. Depois disso nada é ingênuo, então comparar ou
subtrair dois instantes nunca estoura `TypeError`.

Usar UTC "porque é neutro" calaria o lint, mas mudaria a regra de negócio: o
calendário e o expediente aqui são brasileiros.
"""

from __future__ import annotations

from datetime import date, datetime
from zoneinfo import ZoneInfo

#: Fuso de referência da operação. Em Windows depende do pacote `tzdata`.
FUSO = ZoneInfo("America/Sao_Paulo")


def agora() -> datetime:
    """Instante atual, ciente do fuso (nunca ingênuo)."""
    return datetime.now(FUSO)


def hoje() -> date:
    """Dia civil corrente no Brasil, independente do fuso da máquina."""
    return agora().date()


def no_fuso(quando: datetime) -> datetime:
    """Traz um instante para São Paulo, venha ele ciente do fuso ou ingênuo.

    Ingênuo é tratado como já sendo hora local — é o que o Bitrix24 devolve
    em vários campos, e o portal é brasileiro. O retorno é sempre ciente, o
    que torna seguro comparar ou subtrair dois resultados desta função.
    """
    if quando.tzinfo is None:
        return quando.replace(tzinfo=FUSO)
    return quando.astimezone(FUSO)
