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

    logger.info("OpenBastion 核心通訊通道已就緒 (Port 2222)")
    logger.info("可於本機執行連線驗證: ssh -p 2222 admin@127.0.0.1 (預設密碼: openbastion123)")
    logger.info("按下 Ctrl+C 可停止服務")

    try:
        # 維持服務運作
        while True:
            await asyncio.sleep(3600)
    except (asyncio.CancelledError, KeyboardInterrupt):
        logger.info("接收到終止信號，正在關閉服務...")
    finally:
        await gateway.stop()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
