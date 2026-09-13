"""
OpenBastion 主程式啟動入口 (Application Entrypoint)
=================================================
啟動 OpenBastion 核心跳板機通訊服務。
Main entrypoint to boot up OpenBastion gateway services.
"""

import asyncio
import logging
import sys

from core.gateway import GatewayListener
from core.i18n import t

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] (%(name)s) %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("openbastion.main")


async def main() -> None:
    """
    主非同步執行回環。
    Main asynchronous application loop.
    """
    gateway = GatewayListener(host="0.0.0.0", port=2222)
    await gateway.start()

    logger.info(t("log.channel_waiting_db", port=2222))
    logger.info(t("log.connect_hint"))
    logger.info(t("log.shutdown_hint"))

    try:
        # 維持服務運作
        while True:
            await asyncio.sleep(3600)
    except (asyncio.CancelledError, KeyboardInterrupt):
        logger.info(t("log.shutting_down"))
    finally:
        await gateway.stop()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
