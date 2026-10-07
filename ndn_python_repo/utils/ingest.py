# -----------------------------------------------------------------------------
# Direct ingest protocol.
#
# One Interest, one Data: the producer sends a single ingest Interest naming
# the Data to be stored; the repo fetches and stores that Data, then replies
# to the same Interest with an empty Data packet as acknowledgement, or with
# an application-level NACK if the command failed.
#
# The ingest Interest is a signed Interest carrying SignatureTime and
# SignatureNonce. Its params-sha256 name component covers the parameters and
# the signature, so every command (including a resend) has a distinct name
# and each reply answers exactly one Interest name.
#
# @Author regmisuravi@gmail.com
# @Date   2026-06-30
# -----------------------------------------------------------------------------

import asyncio as aio
import logging

from ndn.app import NDNApp
from ndn.encoding import Name, NonStrictName, ContentType
from ..handle.read_handle import ReadHandle
from ndn.types import InterestNack, InterestTimeout
from ..command import ObjParam
from ..storage import Storage
from .concurrent_fetcher import concurrent_fetcher
from typing import Optional


class DirectIngestHandle:
    """
    Repo-side handler for the direct ingest protocol.
    Listens on <repo_name>/ingest, and processes each command as a single Interest/Data

    1. Producer sends a signed Interest to <repo_name>/ingest/params-sha256=<digest>,
       with AppParam = ObjParam { name, forwarding_hint, ... }.
    2. Repo fetches data_name from the producer, using forwarding_hint if given.
    3. Repo stores the fetched Data.
    4. Repo replies to the original ingest Interest with an empty Data packet,
       or with an application-level NACK (ContentType=NACK) if the command failed.
    """

    FETCH_RETRIES   = 3
    RETRY_BACKOFF_S = 0.5  # multiplied by attempt number
    DEFAULT_INTEREST_LIFETIME_MS = 4000  # NDN default when InterestLifetime is absent
    REPLY_MARGIN_MS = 500  # reply this long before the ingest Interest expires

    def __init__(self, app: NDNApp, storage: Storage, config: dict, read_handle: ReadHandle):
        self.app     = app
        self.storage = storage
        self.config  = config
        self.prefix  = None
        self._registered_prefixes = set()
        self.m_read_handle = read_handle

    async def listen(self, prefix: NonStrictName):
        """
        Register Interest filter on <prefix>/ingest.
        Called by WriteCommandHandle.listen().

        :param prefix: NonStrictName. The repo's name prefix.
        """
        self.prefix   = Name.normalize(prefix)
        ingest_prefix = self.prefix + Name.from_str('ingest')
        await self.app.register(ingest_prefix, self._on_insert_interest)
        logging.info(f'DirectIngestHandle listening on {Name.to_str(ingest_prefix)}')

    # Ingest Interest entry point.

    def _on_insert_interest(self, int_name, int_param, app_param):
        aio.create_task(self._process_insert(int_name, int_param, app_param))

    async def _process_insert(self, int_name, int_param, app_param):
        """
        Parse the command, fetch and store the requested Data, then reply to
        int_name with an empty Data packet as acknowledgement, or with an
        application-level NACK (ContentType=NACK) on failure.
        """
        logging.info(f'ingest.received {Name.to_str(int_name)}')

        # Parse
        try:
            param = ObjParam.parse(app_param)
        except Exception as e:
            logging.warning(f'ingest.parse.fail: {e}')
            self._reply_nack(int_name)
            return

        data_name = param.name
        fwd_hint  = (param.forwarding_hint.names[0]
                     if param.forwarding_hint and param.forwarding_hint.names
                     else None)

        if not data_name:
            logging.warning(f'ingest.no.data_name {Name.to_str(int_name)}')
            self._reply_nack(int_name)
            return

        # Normalize block ids (mirrors write_command_handle logic)
        start_block_id = param.start_block_id
        end_block_id   = param.end_block_id
        if start_block_id is None and end_block_id is not None:
            start_block_id = 0
        if end_block_id is not None and end_block_id < (start_block_id or 0):
            logging.warning(f'ingest.malformed end_block_id < start_block_id {Name.to_str(int_name)}')
            self._reply_nack(int_name)
            return

        logging.info(f'ingest.data.requested {Name.to_str(data_name)} '
                     f'start={start_block_id} end={end_block_id}')

        # Fetch, bounded by the ingest Interest's lifetime so that the reply
        # (ack or NACK) still reaches the producer before its PIT entry expires.
        lifetime = (int_param.lifetime if int_param and int_param.lifetime is not None
                    else self.DEFAULT_INTEREST_LIFETIME_MS)
        deadline_s = max(lifetime - self.REPLY_MARGIN_MS, 0) / 1000.0
        try:
            insert_num, is_success = await aio.wait_for(
                self._fetch_and_store(data_name, start_block_id, end_block_id, fwd_hint),
                timeout=deadline_s)
        except aio.TimeoutError:
            logging.error(f'ingest.fetch.deadline {Name.to_str(data_name)} deadline={deadline_s}s')
            self._reply_nack(int_name)
            return

        if not is_success:
            logging.error(f'ingest.fetch.fail {Name.to_str(data_name)} inserted={insert_num}')
            self._reply_nack(int_name)
            return

        logging.info(f'ingest.data.saved {Name.to_str(data_name)} count={insert_num}')

        register_prefix = param.register_prefix.name if param.register_prefix else None
        if register_prefix:
            prefix_str = Name.to_str(register_prefix)
            if prefix_str not in self._registered_prefixes:
                self._registered_prefixes.add(prefix_str)
                self.m_read_handle.listen(register_prefix)
                logging.info(f'ingest.prefix.registered {prefix_str}')

        # Ack
        self.app.put_data(int_name, None)
        logging.info(f'ingest.ack.sent data={Name.to_str(data_name)}')

    def _reply_nack(self, int_name):
        """
        Reply to the ingest Interest with an application-level NACK, so the
        producer learns about the failure without waiting for its Interest to time out.
        """
        self.app.put_data(int_name, None, content_type=ContentType.NACK)
        logging.info(f'ingest.nack.sent {Name.to_str(int_name)}')

    async def _fetch_and_store(self, data_name: NonStrictName, start_block_id: Optional[int],
                               end_block_id: Optional[int], fwd_hint: NonStrictName):
        """
        Fetch and store the requested Data.

        :return: (insert_num, is_success).
        """
        if start_block_id is not None:
            insert_num = await self._fetch_segmented_data(data_name, start_block_id, end_block_id, fwd_hint)
            if end_block_id is None:
                # end auto-detected: success only if at least one segment was stored
                return insert_num, insert_num > 0
            return insert_num, start_block_id + insert_num - 1 == end_block_id

        fetched_name, data_bytes = await self._fetch_data(data_name, fwd_hint)
        if fetched_name is None:
            return 0, False
        self.storage.put_data_packet(fetched_name, data_bytes)
        logging.info(f'ingest.data.saved {Name.to_str(fetched_name)}')
        return 1, True

    # Fetch helpers.

    async def _fetch_segmented_data(self, data_name: NonStrictName, start_block_id: int,
                                    end_block_id: Optional[int], fwd_hint: NonStrictName) -> int:
        """
        Fetch segmented Data packets and store each one.

        :param data_name: NonStrictName. Name prefix of segmented Data.
        :param start_block_id: int. Inclusive start segment number.
        :param end_block_id: Optional[int]. Inclusive end segment number.
        :param fwd_hint: NonStrictName. Forwarding hint used to fetch the Data.
        :return: Number of Data packets fetched.
        """
        forwarding_hint = [fwd_hint] if fwd_hint else None
        semaphore = aio.Semaphore(10)
        block_id = start_block_id
        async for (fetched_name, _, _, data_bytes) in (
                concurrent_fetcher(self.app, data_name, start_block_id, end_block_id,
                                   semaphore, forwarding_hint=forwarding_hint)):
            logging.info(f'concurrent fetching {Name.to_str(fetched_name)}')
            self.storage.put_data_packet(fetched_name, data_bytes)
            block_id += 1
        return block_id - start_block_id

    async def _fetch_data(self, data_name: NonStrictName, fwd_hint: NonStrictName):
        """
        Fetch a single Data packet, retrying on Nack or timeout.

        :param data_name: NonStrictName. Name of the Data packet.
        :param fwd_hint: NonStrictName. Forwarding hint used to fetch the Data.
        :return: (FormalName, bytes) of the fetched Data, or (None, None) on failure.
        """
        forwarding_hint = [fwd_hint] if fwd_hint else None

        for attempt in range(1, self.FETCH_RETRIES + 1):
            try:
                fetched_name, _, _, data_bytes = await self.app.express_interest(
                    data_name,
                    need_raw_packet=True,
                    can_be_prefix=False,
                    lifetime=4000,
                    forwarding_hint=forwarding_hint
                )

                logging.info(f'ingest.data.received {Name.to_str(fetched_name)}')
                return fetched_name, data_bytes

            except InterestNack as e:
                logging.warning(
                    f'ingest.fetch.nack attempt={attempt} '
                    f'reason={e.reason} data={Name.to_str(data_name)}'
                )
                await aio.sleep(self.RETRY_BACKOFF_S * attempt)

            except InterestTimeout:
                logging.warning(
                    f'ingest.fetch.timeout attempt={attempt} '
                    f'data={Name.to_str(data_name)}'
                )
                await aio.sleep(self.RETRY_BACKOFF_S * attempt)

        logging.error(f'ingest.fetch.exhausted data={Name.to_str(data_name)}')
        return None, None
